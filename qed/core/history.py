"""The 24-hour counters two shipped rules read (SPEC §5).

`AG-BUD-007` fires on `derived.history.calls_24h >= 500` and `AG-IDN-010` on
`derived.history.blocks_24h >= 5`. Both shipped in week 1 and **neither could
ever fire**: `HistoryDerived` was threaded through `check_proposal` into
`EvalContext` and nothing ever passed it, so every decision saw zeros. The
spec said the API layer collected it. Nothing did.

This module is the collection, and its whole design is one problem: a count
over "the last 24 hours" is a different number every millisecond, which makes
it both expensive to compute and impossible to reproduce.

**So the window is aligned, not rolling.** The counters cover
``[end - 24h, end)`` where ``end`` is ``now`` floored to
``policies.history_refresh_seconds``. Two consequences, and both are the point:

* every decision inside one bucket sees the same counters, so the query runs
  once per bucket per principal instead of once per decision -- which is what
  keeps a store round-trip off the decision path (SPEC §21's latency budget);
* the window is a pure function of the decision's own timestamp, so
  ``qed replay`` recomputes the identical numbers from the chain. A cadence
  implemented as "a cache with a TTL" would have been cheaper to write and
  would have made every replay of a history-dependent rule inconclusive
  forever, because nothing would record which stale value was used.

``history_refresh_seconds: 0`` turns alignment off: ``end`` is the decision's
own timestamp, the counters are exact to the millisecond, and every decision
pays for a query. Still replayable, because the timestamp is recorded.

**What is counted, and from where.** Both numbers come from the evidence chain
and nothing else, because that is the only source an auditor also has:

* ``calls_24h`` -- ``proposal`` records for this principal in the window;
* ``blocks_24h`` -- ``verdict`` records for this principal in the window whose
  decision was BLOCK.

The store answers both from indexed columns, which is why `decision` is
denormalised onto `evidence` in migration 0006: reading it out of the payload
JSON would need a different expression per backend, and would stop working
when retention strips the payload.

**Counted by `principal_hash`, which is NULL for an unattended agent.** An
action with no human principal therefore contributes to no counter and sees
zeros, so neither rule fires for one. That is a real gap and it is left open
deliberately: the alternative is grouping every unattended agent in the
instance under one NULL identity, and "this principal has been blocked
repeatedly" would then mean "some agent somewhere has been".

**The two sides read the principal from different places, because they have
to.** `principal_hash` is a denormalised *storage* column; it is not a field
of `EvidenceRecord` and so it is not in an export. The store can therefore
filter on it directly, while :func:`counts_from_records` -- which works from
what an auditor actually holds -- takes the principal out of each `proposal`
payload and reaches a verdict through its `proposal_id`. The column is written
from the same value the payload carries, so the two agree; that they agree is
asserted in `tests/core/test_history.py` rather than assumed, because this is
exactly the shape of thing that drifts.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import UTC, datetime, timedelta
from typing import Final

from qed.core.schemas import HistoryDerived

__all__ = [
    "DEFAULT_REFRESH_SECONDS",
    "WINDOW",
    "counts_from_records",
    "window_for",
]

#: The window both rules speak about. Not configurable: `calls_24h` is the
#: field name in a shipped rule's predicate, and a 24-hour field covering
#: twelve hours would be a lie with a test behind it.
WINDOW: Final = timedelta(hours=24)

#: One minute. Both thresholds in the shipped pack are daily volumes -- 500
#: calls, 5 blocks -- so a minute of staleness cannot change an answer that
#: a human would consider correct, and it reduces the query to at most one per
#: principal per minute.
DEFAULT_REFRESH_SECONDS: Final = 60


def window_for(now: datetime, refresh_seconds: int) -> tuple[datetime, datetime]:
    """The ``[start, end)`` the counters cover for a decision made at `now`.

    Pure, and a pure function of the decision's timestamp alone -- which is
    what makes the counters replayable. `refresh_seconds` of 0 or less means
    no alignment: the window ends at `now`.

    **Half-open, and that is load-bearing rather than tidy.** `check_proposal`
    collects the counters before it appends the proposal record, so a decision
    never counts itself. `end` is always at or before the decision's own
    timestamp, so excluding `end` reproduces that exactly when `qed replay`
    counts over a chain where the record *is* present. An inclusive bound
    would make every replayed `calls_24h` one too high -- a difference that
    would show up only on a rule near its threshold, which is the hardest kind
    to go looking for.
    """
    if refresh_seconds <= 0:
        end = now
    else:
        # Floored against the Unix epoch rather than against anything in this
        # process, so two replicas deciding in the same second agree, and a
        # replay months later lands on the same boundary.
        seconds = int(now.timestamp())
        end = datetime.fromtimestamp(seconds - (seconds % refresh_seconds), tz=UTC)
    return end - WINDOW, end


def counts_from_records(
    records: Iterable[Mapping[str, object]],
    *,
    principal_hash: str | None,
    start: datetime,
    end: datetime,
) -> tuple[HistoryDerived, bool]:
    """Recompute the counters from chain records, and whether that was possible.

    This is the replay side of the same definition the store query implements
    in SQL. Two implementations of one rule is a place for them to drift, so
    `tests/core/test_history.py` runs both over the same chain and asserts
    they agree -- without that test this function is a second opinion rather
    than a check.

    The flag is False when a `verdict` record inside the window has had its
    payload stripped by retention: the decision is then unknowable, so
    `blocks_24h` cannot be asserted and the caller must say so rather than
    report a number that is merely a lower bound.
    """
    if principal_hash is None:
        # Nothing is counted against an absent principal. See the module
        # docstring: the alternative groups every unattended agent together.
        return HistoryDerived(), True

    in_window = [
        record
        for record in records
        if (stamp := _stamp(record.get("ts"))) is not None and start <= stamp < end
    ]

    complete = True
    mine: set[str] = set()
    calls = 0
    for record in in_window:
        if record.get("type") != "proposal":
            continue
        proposal = _inner(record, "proposal")
        if proposal is None:
            # Purged. Whose proposal this was is no longer knowable, so both
            # counters become lower bounds rather than numbers.
            complete = False
            continue
        principal = proposal.get("principal")
        if not isinstance(principal, Mapping):
            complete = False
            continue
        if principal.get("human_hash") != principal_hash:
            continue
        calls += 1
        identifier = proposal.get("id")
        if isinstance(identifier, str):
            mine.add(identifier)

    blocks = 0
    for record in in_window:
        if record.get("type") != "verdict":
            continue
        verdict = _inner(record, "verdict")
        if verdict is None:
            complete = False
            continue
        # A verdict carries no principal of its own: it is reached through the
        # proposal it decided, which is why the proposal ids are collected
        # above before anything is counted here.
        if verdict.get("proposal_id") not in mine:
            continue
        if verdict.get("decision") == "BLOCK":
            blocks += 1

    return HistoryDerived(calls_24h=calls, blocks_24h=blocks), complete


def _inner(record: Mapping[str, object], key: str) -> Mapping[str, object] | None:
    """A record's payload sub-object, or None once retention has stripped it."""
    payload = record.get("payload")
    if not isinstance(payload, Mapping):
        return None
    inner = payload.get(key)
    return inner if isinstance(inner, Mapping) else None


def _stamp(value: object) -> datetime | None:
    if isinstance(value, datetime):
        return value
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:  # pragma: no cover - a record that would not verify
        return None
