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
