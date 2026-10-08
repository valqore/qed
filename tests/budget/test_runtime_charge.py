"""When a decision charges the ledger, and when it must not (SPEC §8).

The rule under test is one sentence: the budget follows what *happened*, not
what was decided. In enforce mode a BLOCK stops the action, so nothing is
spent. In shadow mode the adapter proceeds whatever the verdict says, so the
tokens and the money are spent for real and the ledger has to say so.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from gate.core.schemas import Budget, BudgetState, Decision, EvidenceType, Mode
from gate.runtime import Session, check_proposal, open_session
from tests.conftest import make_proposal

NOW = datetime.fromisoformat("2026-10-07T12:00:00+00:00")
JTI = "01JB000000000000000000JTI0"

#: Account-wide scope trips AG-BLR-001, whose verdict is a hard BLOCK rather
#: than an approval request — so "did not run" is unambiguous.
DESTRUCTIVE: dict[str, object] = {
    "action": {"kind": "mcp_tool", "name": "aws.delete_stack", "target": "aws:prod/account"},
    "context": {
        "environment": "prod",
        "blast_radius_hints": {"writes": True, "deletes": True, "scope": "account"},
    },
}


@pytest.fixture
def session(gate_dir: Path) -> Iterator[Session]:
    opened = open_session(directory=gate_dir)
    try:
        yield opened
    finally:
        opened.close()


def ident(n: int) -> dict[str, object]:
    return {"id": f"01JB00000000000000000000{n:02d}"}


def budget_records(records: list[object]) -> list[EvidenceType]:
    return [
        r.type  # type: ignore[attr-defined]
        for r in records
        if r.type in (EvidenceType.budget_update, EvidenceType.budget_exhausted)  # type: ignore[attr-defined]
    ]


class TestWhenAChargeHappens:
    def test_an_allowed_action_is_charged(self, session: Session) -> None:
        outcome = check_proposal(session, make_proposal(ident(1)), now=NOW)
        assert outcome.verdict.decision is Decision.ALLOW
        state = session.store.load_budget(JTI)
        assert state is not None
        assert state.steps_used == 1

    def test_a_blocked_action_in_enforce_mode_is_not_charged(self, gate_dir: Path) -> None:
        """It did not run, so it cost nothing. Charging here would let a
        rejected agent burn the budget of the human who delegated to it.

        Enforce has to be asked for. The shipped default is shadow, which means
        the common case is that everything is charged.
        """
        config = gate_dir.parent / "gate.yaml"
        config.write_text("mode: enforce\n", encoding="utf-8")
        session = open_session(directory=gate_dir, config_path=config)
        try:
            assert session.config.mode is Mode.enforce
            outcome = check_proposal(session, make_proposal({**ident(2), **DESTRUCTIVE}), now=NOW)
            assert outcome.verdict.decision is Decision.BLOCK
            assert session.store.load_budget(JTI) is None
        finally:
            session.close()

    def test_a_blocked_action_in_shadow_mode_is_charged(self, session: Session) -> None:
        """Shadow records and lets through. The action really ran upstream and
        really spent the tokens, so the ledger must not pretend otherwise."""
        assert session.config.mode is Mode.shadow, "shadow is the shipped default"
        outcome = check_proposal(session, make_proposal({**ident(3), **DESTRUCTIVE}), now=NOW)
        assert outcome.verdict.decision is Decision.BLOCK
        assert outcome.effective_decision is Decision.ALLOW
        state = session.store.load_budget(JTI)
        assert state is not None
        assert state.steps_used == 1

    def test_a_pinned_budget_is_a_dry_run_and_never_written_back(self, session: Session) -> None:
        """Callers pass a state to ask "what would happen if". Persisting it
        would let a hypothetical corrupt the real ledger."""
        check_proposal(
            session,
            make_proposal(ident(4)),
            budget=BudgetState(token_jti=JTI, budget=Budget(steps=5), steps_used=4),
            now=NOW,
        )
        assert session.store.load_budget(JTI) is None

    def test_cost_is_taken_from_the_adapter_estimate(self, session: Session) -> None:
        check_proposal(
            session,
            make_proposal(
                {**ident(5), "context": {"cost_estimate": {"tokens": 900, "money_cents": 12}}}
            ),
            now=NOW,
        )
        state = session.store.load_budget(JTI)
        assert state is not None
        assert (state.tokens_used, state.money_used_cents) == (900, 12)


class TestExhaustion:
    def _cap(self, session: Session, caps: Budget) -> None:
        session.store.upsert_budget_caps(JTI, caps)

    def test_crossing_a_cap_writes_one_budget_exhausted_record(self, session: Session) -> None:
        self._cap(session, Budget(steps=2))
        first = check_proposal(session, make_proposal(ident(10)), now=NOW)
        second = check_proposal(session, make_proposal(ident(11)), now=NOW)
        assert budget_records(first.records) == []
        assert budget_records(second.records) == [EvidenceType.budget_exhausted]

    def test_the_record_comes_after_the_verdict_it_followed_from(self, session: Session) -> None:
        """A reader of the chain sees the action, then the consequence."""
        self._cap(session, Budget(steps=1))
        outcome = check_proposal(session, make_proposal(ident(12)), now=NOW)
        types = [r.type for r in outcome.records]
        assert types == [
            EvidenceType.proposal,
            EvidenceType.verdict,
            EvidenceType.budget_exhausted,
        ]

    def test_the_next_action_is_blocked_by_the_engine_short_circuit(self, session: Session) -> None:
        """AG-BUD-001 is synthetic and runs before any file rule (SPEC §4.6)."""
        self._cap(session, Budget(steps=1))
        check_proposal(session, make_proposal(ident(13)), now=NOW)
        after = check_proposal(session, make_proposal(ident(14)), now=NOW)
        assert after.verdict.decision is Decision.BLOCK
        assert "AG-BUD-001" in [hit.rule_id for hit in after.verdict.hits]

    def test_an_exhausted_token_does_not_report_exhaustion_twice(self, session: Session) -> None:
        """The second action is blocked, so it is not charged, so there is
        nothing new to report. A chain that repeated the record on every later
        attempt would bury the moment that mattered."""
        self._cap(session, Budget(steps=1))
        check_proposal(session, make_proposal(ident(15)), now=NOW)
        after = check_proposal(session, make_proposal(ident(16)), now=NOW)
        assert budget_records(after.records) == []

    def test_a_seconds_budget_blocks_without_a_charge_crossing_it(self, session: Session) -> None:
        """Time, not spend, exhausts this one. The engine reports it on the next
        action; no `budget_exhausted` is attributed to a charge."""
        self._cap(session, Budget(seconds=60))
        check_proposal(session, make_proposal(ident(17)), now=NOW)
        later = check_proposal(session, make_proposal(ident(18)), now=NOW + timedelta(seconds=120))
        assert later.verdict.decision is Decision.BLOCK
        assert "AG-BUD-001" in [hit.rule_id for hit in later.verdict.hits]
        assert budget_records(later.records) == []


class TestLedgerFeedsThePolicy:
    def test_stored_usage_reaches_the_derived_fields(self, session: Session) -> None:
        """The ledger is only useful if the next decision reads it. AG-BUD-002
        fires at 80 percent of an axis, and it ships in shadow, so the hit is
        recorded without changing the decision."""
        session.store.upsert_budget_caps(JTI, Budget(steps=5))
        # Each decision reads the state its own charge has not been applied to
        # yet, so the fifth is the first to see 4 of 5 steps spent.
        for n in range(5):
            outcome = check_proposal(session, make_proposal(ident(20 + n)), now=NOW)
        assert outcome.verdict.decision is Decision.ALLOW
        assert "AG-BUD-002" in [hit.rule_id for hit in outcome.verdict.hits]
