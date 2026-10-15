"""Re-deriving a recorded decision (SPEC §14, `qed/core/replay.py`).

The hard part of replay is not running the engine again -- that is one call.
It is being honest about what the second run proves, and the failure modes are
symmetrical:

* claiming a replay when the policy that decided the record is not the policy
  being used, which turns "what would today's rules say" into a verdict about
  the past;
* reporting a difference caused by an input nobody could recover as though it
  were evidence of tampering, which is the kind of false alarm that teaches
  people to stop reading the tool's output.

So most of these tests are about classification rather than about the engine.
"""

from __future__ import annotations

import pytest

from qed.core.policy.engine import evaluate
from qed.core.policy.model import PolicyBundle
from qed.core.replay import (
    predicate_fields,
    replay_verdict,
    rules_reading_assumed_inputs,
)
from qed.core.schemas import (
    ActionProposal,
    Budget,
    BudgetState,
    Decision,
    EvalContext,
    Verdict,
)
from tests.conftest import make_proposal


def _nearly_spent(proposal: ActionProposal) -> BudgetState:
    """A ledger with most of its money gone.

    The shipped pack has rules on `derived.budget.money_pct_used >= 80` and
    on `money_remaining_cents` existing at all, so this reads differently from
    an empty state -- which is what makes it usable as a fixture for
    classification.
    """
    return BudgetState(
        token_jti=proposal.principal.token_jti,
        budget=Budget(steps=50, money_cents=5000),
        steps_used=45,
        money_used_cents=4800,
    )


@pytest.fixture
def recorded(
    proposal: ActionProposal, baseline_bundle: PolicyBundle, budget: BudgetState, ctx: EvalContext
) -> Verdict:
    """What the kernel would have written for this proposal."""
    return evaluate(proposal, baseline_bundle, budget, ctx)


class TestAFaithfulReplay:
    def test_the_same_inputs_reproduce_the_record(
        self,
        proposal: ActionProposal,
        recorded: Verdict,
        baseline_bundle: PolicyBundle,
        budget: BudgetState,
        ctx: EvalContext,
    ) -> None:
        report = replay_verdict(proposal, recorded, baseline_bundle, budget, ctx)
        assert report.reproduced
        assert report.differences == ()
        assert report.policy_matches
        assert "reproduced" in report.summary()

    def test_nothing_is_assumed_when_nothing_is_declared(
        self,
        proposal: ActionProposal,
        recorded: Verdict,
        baseline_bundle: PolicyBundle,
        budget: BudgetState,
        ctx: EvalContext,
    ) -> None:
        """A caller that recovered every input gets a report in which no
        difference could be excused. Assumptions are declared by the caller
        and never inferred here."""
        report = replay_verdict(proposal, recorded, baseline_bundle, budget, ctx)
        assert report.assumed_inputs == ()


class TestADifferentPolicy:
    def test_a_hash_mismatch_refuses_rather_than_diffing(
        self,
        proposal: ActionProposal,
        recorded: Verdict,
        baseline_bundle: PolicyBundle,
        budget: BudgetState,
        ctx: EvalContext,
    ) -> None:
        """The record was decided under rules this bundle is not. Diffing
        anyway would read as a replay that disagreed, when the honest answer
        is that the question cannot be asked of this bundle."""
        elsewhere = recorded.model_copy(update={"policy_hash": "0" * 64})
        report = replay_verdict(proposal, elsewhere, baseline_bundle, budget, ctx)
        assert not report.policy_matches
        assert not report.reproduced
        assert report.differences == ()
        assert "cannot replay" in report.summary()

    def test_the_summary_names_both_hashes(
        self,
        proposal: ActionProposal,
        recorded: Verdict,
        baseline_bundle: PolicyBundle,
        budget: BudgetState,
        ctx: EvalContext,
    ) -> None:
        """An operator has to be able to find the bundle that was in force,
        and "the policy differs" does not help them do that."""
        elsewhere = recorded.model_copy(update={"policy_hash": "a" * 64})
        report = replay_verdict(proposal, elsewhere, baseline_bundle, budget, ctx)
        assert "aaaaaaaaaaaaaaaa" in report.summary()
        assert baseline_bundle.hash[:16] in report.summary()


class TestAnApprovalIsAnOverlayAndNotADecision:
    """`check_proposal` runs `evaluate` and *then* consults the approval store.

    An open window turns REQUIRE_APPROVAL into ALLOW with `via_approval`; a
    recent denial turns it into BLOCK. Comparing the recorded decision to the
    engine's directly would report a mismatch for every correctly approved
    action in the chain, which is every chain that has ever been used.
    """

    @pytest.fixture
    def needs_approval(
        self, baseline_bundle: PolicyBundle, budget: BudgetState, ctx: EvalContext
    ) -> tuple[ActionProposal, Verdict]:
        proposal = make_proposal(
            {
                "action": {"name": "postgres.execute_sql", "target": "db:prod/orders"},
                "context": {
                    "environment": "prod",
                    "blast_radius_hints": {"writes": True, "deletes": True},
                },
            }
        )
        verdict = evaluate(proposal, baseline_bundle, budget, ctx)
        assert verdict.decision is Decision.REQUIRE_APPROVAL, verdict.decision
        return proposal, verdict

    def test_an_allow_through_a_window_still_reproduces(
        self,
        needs_approval: tuple[ActionProposal, Verdict],
        baseline_bundle: PolicyBundle,
        budget: BudgetState,
        ctx: EvalContext,
    ) -> None:
        proposal, engine_verdict = needs_approval
        as_recorded = engine_verdict.model_copy(
            update={"decision": Decision.ALLOW, "via_approval": "apr_01TEST"}
        )
        report = replay_verdict(proposal, as_recorded, baseline_bundle, budget, ctx)
        assert report.reproduced
        assert "apr_01TEST" in report.approval_overlay

    def test_a_block_from_a_recent_denial_still_reproduces(
        self,
        needs_approval: tuple[ActionProposal, Verdict],
        baseline_bundle: PolicyBundle,
        budget: BudgetState,
        ctx: EvalContext,
    ) -> None:
        proposal, engine_verdict = needs_approval
        as_recorded = engine_verdict.model_copy(
            update={"decision": Decision.BLOCK, "approval_id": "apr_01DENIED"}
        )
        report = replay_verdict(proposal, as_recorded, baseline_bundle, budget, ctx)
        assert report.reproduced
        assert "denial" in report.approval_overlay

    def test_a_pending_link_leaves_the_decision_alone(
        self,
        needs_approval: tuple[ActionProposal, Verdict],
        baseline_bundle: PolicyBundle,
        budget: BudgetState,
        ctx: EvalContext,
    ) -> None:
        proposal, engine_verdict = needs_approval
        as_recorded = engine_verdict.model_copy(update={"approval_id": "apr_01PENDING"})
        report = replay_verdict(proposal, as_recorded, baseline_bundle, budget, ctx)
        assert report.reproduced
        assert "pending" in report.approval_overlay

    def test_an_allow_with_no_approval_behind_it_is_a_finding(
        self,
        needs_approval: tuple[ActionProposal, Verdict],
        baseline_bundle: PolicyBundle,
        budget: BudgetState,
        ctx: EvalContext,
    ) -> None:
        """The overlay is itself a claim. An ALLOW that the policy says needed
        an approval, carrying no approval, is exactly the record somebody
        would forge -- and nothing excuses it."""
        proposal, engine_verdict = needs_approval
        forged = engine_verdict.model_copy(update={"decision": Decision.ALLOW})
        report = replay_verdict(proposal, forged, baseline_bundle, budget, ctx)
        assert not report.reproduced
        assert [d.field for d in report.unexplained] == ["decision"]


class TestWhatAnAssumedInputExcuses:
    def test_a_budget_difference_is_attributed_when_the_budget_was_assumed(
        self,
        proposal: ActionProposal,
        baseline_bundle: PolicyBundle,
        ctx: EvalContext,
    ) -> None:
        """Decided against a real ledger, replayed against an empty one. The
        rules reading `derived.budget.*` come out differently, and that is
        a statement about the replay rather than about the record."""
        real = _nearly_spent(proposal)
        recorded = evaluate(proposal, baseline_bundle, real, ctx)
        empty = BudgetState(token_jti=proposal.principal.token_jti)

        report = replay_verdict(
            proposal, recorded, baseline_bundle, empty, ctx, assumed_inputs=("budget",)
        )
        assert report.differences, "the fixture should produce a difference to classify"
        assert report.inconclusive
        assert report.unexplained == ()
        assert all(d.attributed_to == "budget" for d in report.differences)
        assert "inconclusive" in report.summary()

    def test_the_same_difference_is_a_finding_when_nothing_was_assumed(
        self,
        proposal: ActionProposal,
        baseline_bundle: PolicyBundle,
        ctx: EvalContext,
    ) -> None:
        """The identical diff, with the caller claiming it had the real
        ledger. Then there is nothing to explain it and it must be reported."""
        real = _nearly_spent(proposal)
        recorded = evaluate(proposal, baseline_bundle, real, ctx)
        empty = BudgetState(token_jti=proposal.principal.token_jti)

        report = replay_verdict(proposal, recorded, baseline_bundle, empty, ctx)
        assert report.unexplained
        assert not report.inconclusive
        assert "DIFFERS" in report.summary()

    def test_blast_radius_is_never_excused(
        self,
        proposal: ActionProposal,
        recorded: Verdict,
        baseline_bundle: PolicyBundle,
        budget: BudgetState,
        ctx: EvalContext,
    ) -> None:
        """It is computed from the proposal, which the chain records in full.
        No assumed input can account for it differing, so an edited
        `blast_radius` is always a finding."""
        edited = recorded.model_copy(update={"blast_radius": (recorded.blast_radius + 7) % 101})
        report = replay_verdict(
            proposal,
            edited,
            baseline_bundle,
            budget,
            ctx,
            assumed_inputs=("budget", "mandate"),
        )
        assert [d.field for d in report.unexplained] == ["blast_radius"]
        assert report.differences[0].attributed_to == ""

    def test_an_assumption_no_rule_could_read_is_not_reported(
        self,
        proposal: ActionProposal,
        recorded: Verdict,
        baseline_bundle: PolicyBundle,
        budget: BudgetState,
        ctx: EvalContext,
    ) -> None:
        """A caveat printed on every run is a caveat nobody reads. `history`
        survives only if some rule reads `derived.history.*`; `budget` and
        `mandate` always survive, because the engine's own synthetic gates
        read them before any rule is consulted."""
        report = replay_verdict(
            proposal,
            recorded,
            baseline_bundle,
            budget,
            ctx,
            assumed_inputs=("budget", "mandate", "nonsense"),
        )
        assert set(report.assumed_inputs) == {"budget", "mandate"}


class TestFindingWhichRulesReadWhat:
    def test_a_nested_reference_is_found(self) -> None:
        """A `derived.budget.*` read three levels inside an `any`/`not` tree
        counts exactly as much as one at the top, so the walk has to recurse
        rather than look at the first key."""
        when = {
            "any": [
                {"field": "action.kind", "equals": "db"},
                {"all": [{"not": {"field": "derived.budget.steps_pct_used", "gte": 80}}]},
            ]
        }
        assert predicate_fields(when) == {
            "action.kind",
            "derived.budget.steps_pct_used",
        }

    def test_a_rule_with_no_predicate_reads_nothing(self) -> None:
        assert predicate_fields(None) == set()
        assert predicate_fields({}) == set()

    def test_the_shipped_pack_has_budget_reading_rules(self, baseline_bundle: PolicyBundle) -> None:
        reading = rules_reading_assumed_inputs(baseline_bundle)
        assert "budget" in set(reading.values())

    def test_proposal_derived_values_are_not_treated_as_assumed(
        self, baseline_bundle: PolicyBundle
    ) -> None:
        """`derived.blast_radius` and `derived.chain_depth` are computed from
        the proposal, which is recorded, so a rule reading only those is
        fully replayable and must not be excused."""
        reading = rules_reading_assumed_inputs(baseline_bundle)
        for rule in baseline_bundle.rules:
            if rule.when is None:
                continue
            fields = predicate_fields(rule.when)
            if fields <= {"derived.blast_radius", "derived.chain_depth"} and fields:
                assert rule.rule_id not in reading, rule.rule_id


class TestTheHistoryCountersAreNotAnAssumption:
    """Pins a fact about the product, so that changing it is deliberate.

    `HistoryDerived` is threaded through `check_proposal` into `EvalContext`
    and **nothing in `qed` ever passes it**: every decision this product has
    made saw zeros. Replay therefore uses zeros and does not call history
    assumed, which is only true while that holds.

    If this test fails because something now supplies real counters, the fix
    is not to change the number here: it is to decide what `qed replay` should
    do about an input that has become unrecoverable.
    """

    def test_no_decision_path_supplies_history(self, qed_dir: object, tmp_path: object) -> None:
        from pathlib import Path

        from qed.runtime import check_proposal, open_session

        directory = Path(str(qed_dir))
        session = open_session(directory=directory, strict_policy=False)
        try:
            outcome = check_proposal(session, make_proposal({"id": "01M5REPLAYHIST0000000000AA"}))
        finally:
            session.close()

        # AG-BUD-007 fires at calls_24h >= 500 and AG-IDN-010 at
        # blocks_24h >= 5. Neither can fire while the counters are zero, and
        # neither appears here.
        fired = {hit.rule_id for hit in outcome.verdict.hits}
        assert "AG-BUD-007" not in fired
        assert "AG-IDN-010" not in fired
