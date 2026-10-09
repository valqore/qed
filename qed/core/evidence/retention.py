"""Retention: which payloads may be dropped, and which never may (SPEC §10.6).

Purging is the only destructive thing `qed` does to its own chain, so the whole
module is about being precise about what it will not touch.

The chain survives it by construction. `payload_hash`, `hash`, `sig` and
`prev_hash` are never cleared, and `hash` recomputes from `payload_hash` rather
than from the payload — so a record whose payload is gone still verifies its
linkage and its signature, and `qed-verify` reports it as purged rather than
broken. What is lost is the ability to read *what* the action was, which is
exactly the point of a retention policy.

**Some payloads are structural and may never be purged.** This is a
correctness constraint, not a policy preference, and it is the thing most
likely to be got wrong by a config that means well:

* a `checkpoint`'s payload holds its `merkle_root`. Purge it and that
  checkpoint can never be checked again — the roots are not recoverable from
  anywhere else, and a checkpoint that cannot be verified is worse than no
  checkpoint, because it looks like one.
* a `key_rotated`'s payload holds `new_public_pem`. Purge it and an auditor
  given only the first public key loses the thread at the rotation.
* `genesis` and `policy_loaded` carry the chain's identity and the rules that
  were in force. Without them an export is a list of signed hashes with no
  stated meaning.
* `admin_action` records the purges themselves. Purging those would erase the
  record of what was erased, which is the one thing a retention policy must
  never do.

Nothing here reads a clock or a database. `plan_purge` takes the records and a
`now`, and returns what to do.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Final

from qed.core.schemas import STRUCTURAL_TYPES, EvidenceRecord, EvidenceType

__all__ = [
    "NEVER_PURGE",
    "PurgePlan",
    "RetentionPolicy",
    "parse_retention",
    "plan_purge",
    "purgeable_types",
]

#: The structural record types, under the name retention cares about. One set,
#: defined in :data:`qed.core.schemas.STRUCTURAL_TYPES`, because the reason
#: these payloads may not be purged is the same reason they are not masked:
#: they are how the chain is read, not data it happens to carry. Two lists
#: would be two lists to keep in step.
NEVER_PURGE: Final[frozenset[EvidenceType]] = STRUCTURAL_TYPES


@dataclass(frozen=True)
class RetentionPolicy:
    """How long payloads are kept, per type (SPEC §10.6).

    `payload` is the default age; `by_type` overrides it. ``None`` anywhere
    means forever, which is also what an absent configuration means — a
    kernel that started deleting evidence because nobody had configured
    retention would be the wrong default by a long way.
    """

    payload: timedelta | None = None
    by_type: dict[EvidenceType, timedelta | None] = field(default_factory=dict)
    #: The ages exactly as the config wrote them, keyed by `"payload"` and by
    #: type name. `describe()` prefers these, because a retention age reported
    #: back as `1d` when the operator wrote `24h` is a small lie in a document
    #: an auditor reads -- and the `admin_action` record quotes it verbatim.
    declared: dict[str, str | None] = field(default_factory=dict)

    @property
    def active(self) -> bool:
        """Whether this policy would ever purge anything."""
        return self.payload is not None or any(age is not None for age in self.by_type.values())

    def age_for(self, type_: EvidenceType) -> timedelta | None:
        """The retention age for one record type, or None for forever."""
        if type_ in NEVER_PURGE:
            return None
        if type_ in self.by_type:
            return self.by_type[type_]
        return self.payload

    def describe(self) -> dict[str, object]:
        """What `qed status` and the `admin_action` record report."""
        return {
            "payload": self._text("payload", self.payload),
            "by_type": {
                type_.value: self._text(type_.value, age)
                for type_, age in sorted(self.by_type.items(), key=lambda item: item[0].value)
            },
            "never_purged": sorted(type_.value for type_ in NEVER_PURGE),
        }

    def _text(self, key: str, age: timedelta | None) -> str | None:
        """The configured spelling, or a derived one for a policy built in code."""
        if key in self.declared:
            return self.declared[key]
        return None if age is None else _duration_text(age)


@dataclass(frozen=True)
class PurgePlan:
    """Which records a purge would clear, and why it is safe.

    `seqs` is explicit rather than a `seq <= N` range. A range would be simpler
    and wrong: retention is per type, so the set is not contiguous, and an
    exempt `checkpoint` sitting in the middle of an otherwise expired stretch
    must survive it.
    """

    seqs: tuple[int, ...] = ()
    #: How many records of each type, for the `admin_action` payload. An
    #: operator reading "4,112 payloads purged" wants to know of what.
    by_type: dict[str, int] = field(default_factory=dict)
    #: The oldest and newest timestamps involved, so the record says which
    #: period stopped being readable.
    oldest: datetime | None = None
    newest: datetime | None = None
    #: Records that were old enough but exempt. Counted, not purged.
    exempt: int = 0

    @property
    def empty(self) -> bool:
        return not self.seqs

    def summary(self) -> dict[str, object]:
        return {
            "records": len(self.seqs),
            "by_type": dict(sorted(self.by_type.items())),
            "from_seq": self.seqs[0] if self.seqs else None,
            "to_seq": self.seqs[-1] if self.seqs else None,
            "oldest_ts": None if self.oldest is None else self.oldest.isoformat(),
            "newest_ts": None if self.newest is None else self.newest.isoformat(),
            "exempt_structural_records": self.exempt,
        }


def plan_purge(
    records: Iterable[EvidenceRecord],
    *,
    policy: RetentionPolicy,
    now: datetime,
) -> PurgePlan:
    """Decide which payloads have outlived the policy.

    Pure, and takes `now` rather than reading a clock, so the same chain and
    the same instant always produce the same plan — which is what makes a
    purge reviewable before it happens.
    """
    if not policy.active:
        return PurgePlan()

    seqs: list[int] = []
    counts: dict[str, int] = {}
    stamps: list[datetime] = []
    exempt = 0

    for record in records:
        if record.payload is None:
            continue  # already purged; nothing to do and nothing to report
        age = policy.age_for(record.type)
        expired = age is not None and (now - record.ts) >= age
        if record.type in NEVER_PURGE:
            # Counted only when it *would* have gone, so the number means
            # "this policy was overruled here" rather than "this chain has
            # checkpoints in it".
            if policy.payload is not None and (now - record.ts) >= policy.payload:
                exempt += 1
            continue
        if not expired:
            continue
        seqs.append(record.seq)
        counts[record.type.value] = counts.get(record.type.value, 0) + 1
        stamps.append(record.ts)

    return PurgePlan(
        seqs=tuple(seqs),
        by_type=counts,
        oldest=min(stamps) if stamps else None,
        newest=max(stamps) if stamps else None,
        exempt=exempt,
    )


def _duration_text(value: timedelta) -> str:
    """A duration as the config would have written it.

    Round numbers only, because that is what a retention policy is: `7y`,
    `90d`, `24h`. Anything that does not divide evenly falls back to seconds
    rather than rounding, since a reported retention age that is not the
    configured one is a small lie in an audit document.
    """
    seconds = value.total_seconds()
    for suffix, size in (("d", 86400.0), ("h", 3600.0), ("m", 60.0)):
        if seconds >= size and seconds % size == 0:
            return f"{int(seconds // size)}{suffix}"
    return f"{seconds:g}s"


def parse_retention(text: str | None) -> timedelta | None:
    """``"7y"``, ``"90d"``, ``"forever"`` or ``None``.

    Years are accepted here and nowhere else in the product: a retention
    policy is written in the language of the obligation it comes from, and
    those are expressed in years. 365 days, stated rather than implied --
    nothing in a retention window turns on leap days, and a calendar-aware
    year would make the purge boundary depend on which year it is run in.
    """
    if text is None:
        return None
    value = text.strip().lower()
    if value in {"", "forever", "never", "none"}:
        return None
    units = {"s": 1.0, "m": 60.0, "h": 3600.0, "d": 86400.0, "w": 604800.0, "y": 365 * 86400.0}
    suffix = value[-1]
    if suffix not in units:
        raise ValueError(
            f"{text!r} is not a retention age. Use a number and one of s/m/h/d/w/y, or `forever`."
        )
    try:
        amount = float(value[:-1])
    except ValueError:
        raise ValueError(
            f"{text!r} is not a retention age. Use a number and one of s/m/h/d/w/y, or `forever`."
        ) from None
    if amount <= 0:
        raise ValueError(
            f"{text!r} would purge every payload immediately. Use `forever` to keep them, "
            "or a positive age."
        )
    return timedelta(seconds=amount * units[suffix])


def purgeable_types() -> Sequence[str]:
    """Every type a retention policy may name. Used by the config's linter."""
    return sorted(type_.value for type_ in EvidenceType if type_ not in NEVER_PURGE)
