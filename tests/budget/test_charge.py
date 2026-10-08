"""Budget arithmetic (SPEC §8). Pure — no store, no clock."""

from __future__ import annotations

from datetime import datetime, timedelta

from gate.core.budget import Charge, apply_charge, charge_for, newly_exhausted
from gate.core.schemas import Budget, BudgetState
from tests.conftest import make_proposal

NOW = datetime.fromisoformat("2026-10-07T12:00:00+00:00")
JTI = "01JB000000000000000000JTI0"


def state(**kwargs: object) -> BudgetState:
    return BudgetState(token_jti=JTI, **kwargs)  # type: ignore[arg-type]


class TestChargeFor:
    def test_an_action_is_one_step(self) -> None:
        assert charge_for(make_proposal()).steps == 1

    def test_tokens_and_money_come_from_the_adapter_estimate(self) -> None:
        charge = charge_for(
            make_proposal({"context": {"cost_estimate": {"tokens": 1200, "money_cents": 45}}})
        )
        assert (charge.tokens, charge.money_cents) == (1200, 45)
        assert charge.cost_known is True

    def test_an_unknown_cost_charges_zero_and_says_so(self) -> None:
        """SPEC §8: a guess in a ledger an auditor reads is worse than a zero."""
        charge = charge_for(
            make_proposal({"context": {"cost_estimate": {"known": False, "tokens": 0}}})
        )
        assert (charge.tokens, charge.money_cents) == (0, 0)
        assert charge.cost_known is False

    def test_a_negative_estimate_cannot_refund_the_budget(self) -> None:
        """An adapter bug must not hand budget back."""
        charge = charge_for(
            make_proposal({"context": {"cost_estimate": {"tokens": -500, "money_cents": -10}}})
        )
        assert (charge.tokens, charge.money_cents) == (0, 0)


class TestApplyCharge:
    def test_usage_accumulates_on_every_axis(self) -> None:
        after = apply_charge(
            state(steps_used=2, tokens_used=10, money_used_cents=5),
            Charge(steps=1, tokens=90, money_cents=20),
            now=NOW,
        )
        assert (after.steps_used, after.tokens_used, after.money_used_cents) == (3, 100, 25)

    def test_first_seen_is_set_by_the_first_charge(self) -> None:
        after = apply_charge(state(), Charge(), now=NOW)
        assert after.first_seen == NOW

    def test_first_seen_is_not_moved_by_a_later_charge(self) -> None:
        """A `seconds` budget would never expire if the clock kept restarting."""
        first = apply_charge(state(), Charge(), now=NOW)
        second = apply_charge(first, Charge(), now=NOW + timedelta(minutes=5))
        assert second.first_seen == NOW

    def test_usage_is_allowed_to_exceed_the_cap(self) -> None:
        """Clamping would make the ledger disagree with what was spent, and the
        overshoot is what tells an operator the cap was set too low."""
        after = apply_charge(
            state(budget=Budget(tokens=100), tokens_used=90),
            Charge(tokens=50),
            now=NOW,
        )
        assert after.tokens_used == 140


class TestNewlyExhausted:
    def test_a_charge_that_crosses_a_cap_is_newly_exhausted(self) -> None:
        before = state(budget=Budget(steps=3), steps_used=2)
        after = apply_charge(before, Charge(), now=NOW)
        assert newly_exhausted(before, after, now=NOW) is True

    def test_a_charge_that_stays_under_the_cap_is_not(self) -> None:
        before = state(budget=Budget(steps=5), steps_used=2)
        after = apply_charge(before, Charge(), now=NOW)
        assert newly_exhausted(before, after, now=NOW) is False

    def test_an_already_exhausted_token_is_not_exhausted_again(self) -> None:
        """Otherwise every later action would write another `budget_exhausted`."""
        before = state(budget=Budget(steps=1), steps_used=5)
        after = apply_charge(before, Charge(), now=NOW)
        assert newly_exhausted(before, after, now=NOW) is False

    def test_time_alone_is_not_attributed_to_a_charge(self) -> None:
        """A `seconds` budget can run out with nothing spent. That is the
        engine's short-circuit to report on the next action, not a consequence
        of this charge, so the two states are compared at the same `now`."""
        before = state(budget=Budget(seconds=60), first_seen=NOW)
        later = NOW + timedelta(seconds=90)
        after = apply_charge(before, Charge(), now=later)
        assert after.exhausted(later) is True
        assert newly_exhausted(before, after, now=later) is False

    def test_an_uncapped_token_never_exhausts(self) -> None:
        before = state()
        after = apply_charge(before, Charge(tokens=10**9, money_cents=10**9), now=NOW)
        assert after.exhausted(NOW) is False
        assert newly_exhausted(before, after, now=NOW) is False
