"""Domain model guarantees (SPEC §3)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from qed.core.schemas import (
    ActionProposal,
    Budget,
    BudgetState,
    EvidenceRecord,
    rfc3339_ms,
)
from tests.conftest import BASE_PROPOSAL, make_proposal


def test_proposals_are_frozen(proposal: ActionProposal) -> None:
    with pytest.raises(ValidationError):
        proposal.action = proposal.action  # type: ignore[misc]


def test_unknown_fields_are_refused() -> None:
    with pytest.raises(ValidationError):
        make_proposal({"surprise": True})


def test_unknown_nested_fields_are_refused() -> None:
    with pytest.raises(ValidationError):
        make_proposal({"context": {"blast_radius_hints": {"radius": 9000}}})


def test_naive_timestamps_are_refused() -> None:
    with pytest.raises(ValidationError, match="timezone-aware"):
        make_proposal({"ts": datetime(2026, 10, 7, 12, 0, 0)})


def test_timestamps_are_truncated_to_milliseconds() -> None:
    p = make_proposal({"ts": datetime(2026, 10, 7, 12, 0, 0, 123_999, tzinfo=UTC)})
    assert p.ts.microsecond == 123_000
    assert rfc3339_ms(p.ts) == "2026-10-07T12:00:00.123Z"


def test_timestamps_normalise_to_utc() -> None:
    offset = timezone(timedelta(hours=3))
    p = make_proposal({"ts": datetime(2026, 10, 7, 15, 0, 0, tzinfo=offset)})
    assert rfc3339_ms(p.ts) == "2026-10-07T12:00:00.000Z"


def test_timestamp_serialises_the_same_way_in_both_dump_modes() -> None:
    """Record bytes must not depend on which dump mode the caller chose."""
    p = make_proposal()
    assert p.model_dump()["ts"] == p.model_dump(mode="json")["ts"]


def test_round_trip_through_json_is_stable() -> None:
    p = make_proposal()
    again = ActionProposal.model_validate_json(p.model_dump_json())
    assert again == p


def test_base_fixture_matches_the_declared_schema_version() -> None:
    assert BASE_PROPOSAL["schema_version"] == make_proposal().schema_version


def test_blast_radius_is_bounded() -> None:
    from qed.core.schemas import Derived

    with pytest.raises(ValidationError):
        Derived(blast_radius=101)


class TestBudgetExhaustion:
    def test_zero_cap_means_uncapped(self) -> None:
        state = BudgetState(token_jti="j", steps_used=10**6)
        assert not state.exhausted()

    def test_steps_cap(self) -> None:
        state = BudgetState(token_jti="j", budget=Budget(steps=3), steps_used=3)
        assert state.exhausted()

    def test_one_step_left_is_not_exhausted(self) -> None:
        state = BudgetState(token_jti="j", budget=Budget(steps=3), steps_used=2)
        assert not state.exhausted()

    def test_seconds_cap_needs_a_clock_and_a_start(self) -> None:
        start = datetime(2026, 10, 7, 12, 0, 0, tzinfo=UTC)
        state = BudgetState(token_jti="j", budget=Budget(seconds=60), first_seen=start)
        assert not state.exhausted(start + timedelta(seconds=30))
        assert state.exhausted(start + timedelta(seconds=61))

    def test_seconds_cap_without_a_clock_cannot_expire(self) -> None:
        state = BudgetState(token_jti="j", budget=Budget(seconds=1))
        assert not state.exhausted()


def test_evidence_records_reject_a_negative_sequence_number() -> None:
    with pytest.raises(ValidationError):
        EvidenceRecord(
            seq=-1,
            ts="2026-10-07T12:00:00.000Z",
            type="proposal",
            assurance="kernel",
            payload_hash="0" * 64,
            payload={},
            prev_hash="0" * 64,
            hash="0" * 64,
            key_id="ed25519:0",
            sig="x",
        )
