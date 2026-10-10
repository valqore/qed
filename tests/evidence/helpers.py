"""Record builders for tests that are about a *policy* over records.

The retention planner takes records and a clock and returns a plan. It never
hashes or signs anything, so building a real chain to test it would mean a
signing key, a store and a writer per case, to exercise a pure function.

These are well-formed `EvidenceRecord`s with plausible but meaningless hashes.
Anything that asserts a hash, a signature or linkage must use a real chain --
`tests/evidence/test_chain.py` does, and so do the applying tests in
`test_retention.py`.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any, Final

from qed.core.schemas import Assurance, EvidenceRecord, EvidenceType, utcnow


class _Default:
    """Distinguishes "no payload given" from `payload=None`, which means purged."""


DEFAULT: Final = _Default()


def fake_record(
    seq: int,
    type_: EvidenceType,
    *,
    age: timedelta = timedelta(0),
    payload: dict[str, Any] | _Default | None = DEFAULT,
) -> EvidenceRecord:
    """One record at `seq`, backdated by `age`.

    `payload=None` means the payload has already been purged, which is a state
    the planner has to recognise and skip.
    """
    digest = f"{seq:064x}"
    body = {"note": type_.value} if isinstance(payload, _Default) else payload
    return EvidenceRecord(
        seq=seq,
        ts=utcnow() - age,
        type=type_,
        assurance=Assurance.kernel,
        payload=body,
        payload_hash=digest,
        prev_hash=f"{max(seq - 1, 0):064x}",
        hash=digest,
        key_id="ed25519:0000000000000000",
        sig="x" * 86,
    )


def fake_records(
    spec: list[tuple[int, EvidenceType]],
    *,
    age: timedelta = timedelta(0),
    payload: dict[str, Any] | _Default | None = DEFAULT,
) -> list[EvidenceRecord]:
    return [fake_record(seq, type_, age=age, payload=payload) for seq, type_ in spec]


#: How long a survivor may wait for a dead leader's advisory lock.
#:
#: PostgreSQL releases a session's advisory locks when it **reaps the backend**,
#: not when `close()` returns -- `close()` sends a terminate and comes back. So
#: the next `pg_try_advisory_lock` can arrive first, and three tests across two
#: files asserted the *immediate* retry. They passed locally for weeks and
#: failed on CI, once each, in different runs.
#:
#: The bound is the real claim, and it is a claim about the product: a crashed
#: leader's lock frees up *shortly* after the crash, which is why
#: `qed/api/leader.py` asks every tick rather than once. Asserting zero was
#: asserting something PostgreSQL never promised.
TAKEOVER_TIMEOUT_S = 10.0


def take_over(store: object, *, timeout: float = TAKEOVER_TIMEOUT_S) -> None:
    """Become the chain leader, waiting for a dead leader's lock to be reaped."""
    import time

    deadline = time.monotonic() + timeout
    while not store.try_become_leader():  # type: ignore[attr-defined]
        assert time.monotonic() < deadline, (
            f"the chain lock was still held {timeout}s after the leader's connection "
            "closed; a crashed replica would have stalled the chain for at least that "
            "long"
        )
        time.sleep(0.05)
