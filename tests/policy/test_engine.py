"""Engine precedence, determinism and shadow semantics (SPEC §4.5, §5, ADR-003)."""

from __future__ import annotations

from pathlib import Path
from typing import Final

import pytest
import yaml

from qed.core.policy.engine import PREDICATE_FAILED, approval_spec, evaluate, explain
from qed.core.policy.loader import load_bundle
from qed.core.policy.model import PolicyBundle
from qed.core.schemas import (
    ActionProposal,
    Budget,
    BudgetState,
    Decision,
    EvalContext,
    Mode,
    RuleHit,
    Verdict,
)
from tests.conftest import NOW, make_proposal

BLOCKER = {
    "rule_id": "TT-BLK-001",
    "name": "Block prod",
    "message": "No.",
    "verdict": "BLOCK",
    "applies_to": {"environments": ["prod"]},
}
APPROVER = {
    "rule_id": "TT-APP-001",
    "name": "Approve prod",
    "message": "Ask.",
    "verdict": "REQUIRE_APPROVAL",
    "severity": "HIGH",
    "approval": {"approvers": ["sre"], "timeout": "10m"},
    "applies_to": {"environments": ["prod"]},
}
SHADOW_BLOCKER = {**BLOCKER, "rule_id": "TT-SHD-001", "mode": "shadow"}


def bundle_of(tmp_path: Path, *entries: dict[str, object], **kwargs: object) -> PolicyBundle:
    path = tmp_path / "rules.yaml"
    path.write_text(yaml.safe_dump(list(entries)), encoding="utf-8")
    result = load_bundle([path], **kwargs)  # type: ignore[arg-type]
    assert result.ok, [f.format() for f in result.findings]
    return result.bundle


@pytest.fixture
def prod() -> ActionProposal:
    return make_proposal({"context": {"environment": "prod"}})


def run(
    proposal: ActionProposal, bundle: PolicyBundle, budget: BudgetState | None = None
) -> Verdict:
    state = budget or BudgetState(token_jti=proposal.principal.token_jti)
    return evaluate(proposal, bundle, state, EvalContext(now=NOW))


class TestPrecedence:
    def test_block_beats_require_approval(self, tmp_path: Path, prod) -> None:
        verdict = run(prod, bundle_of(tmp_path, APPROVER, BLOCKER))
        assert verdict.decision is Decision.BLOCK
        assert [h.rule_id for h in verdict.hits] == ["TT-APP-001", "TT-BLK-001"]

    def test_severity_does_not_affect_the_decision(self, tmp_path: Path, prod) -> None:
        low_block = {**BLOCKER, "severity": "LOW"}
        verdict = run(prod, bundle_of(tmp_path, APPROVER, low_block))
        assert verdict.decision is Decision.BLOCK

    def test_default_applies_when_nothing_matches(self, tmp_path: Path) -> None:
        verdict = run(make_proposal(), bundle_of(tmp_path, BLOCKER))
        assert verdict.decision is Decision.ALLOW
        assert verdict.default_applied
        assert [h.rule_id for h in verdict.hits] == ["AG-DEF-001"]

    def test_configured_default_verdict_is_used_and_recorded(self, tmp_path: Path) -> None:
        bundle = bundle_of(tmp_path, BLOCKER, default_verdict=Decision.REQUIRE_APPROVAL)
        verdict = run(make_proposal(), bundle)
        assert verdict.decision is Decision.REQUIRE_APPROVAL
        default_hit = next(h for h in verdict.hits if h.rule_id == "AG-DEF-001")
        assert default_hit.verdict is Decision.REQUIRE_APPROVAL

    def test_disabled_rules_do_not_fire(self, tmp_path: Path, prod) -> None:
        off = {"rule_id": BLOCKER["rule_id"], "disabled": True, "reason": "not yet"}
        verdict = run(prod, bundle_of(tmp_path, BLOCKER, off))
        assert verdict.decision is Decision.ALLOW


class TestShadow:
    def test_a_shadow_hit_does_not_decide(self, tmp_path: Path, prod) -> None:
        verdict = run(prod, bundle_of(tmp_path, SHADOW_BLOCKER))
        assert verdict.decision is Decision.ALLOW
        assert verdict.would_decision is Decision.BLOCK
        assert verdict.default_applied
        assert {h.rule_id for h in verdict.hits} == {"AG-DEF-001", "TT-SHD-001"}

    def test_a_shadow_hit_is_recorded_with_its_mode(self, tmp_path: Path, prod) -> None:
        verdict = run(prod, bundle_of(tmp_path, SHADOW_BLOCKER))
        hit = next(h for h in verdict.hits if h.rule_id == "TT-SHD-001")
        assert hit.mode is Mode.shadow

    def test_enforce_and_shadow_together(self, tmp_path: Path, prod) -> None:
        verdict = run(prod, bundle_of(tmp_path, APPROVER, SHADOW_BLOCKER))
        assert verdict.decision is Decision.REQUIRE_APPROVAL
        assert verdict.would_decision is Decision.BLOCK
        assert not verdict.default_applied


class TestAppliesTo:
    @pytest.mark.parametrize(
        ("constraint", "patch", "fires"),
        [
            ({"kinds": ["http"]}, {}, False),
            ({"kinds": ["mcp_tool"]}, {}, True),
            ({"name_globs": ["github.*"]}, {}, True),
            ({"name_globs": ["gitlab.*"]}, {}, False),
            ({"target_globs": ["repo:acme/*"]}, {}, True),
            ({"target_globs": ["db:*"]}, {}, False),
            ({"adapters": ["mcp-proxy/*"]}, {}, True),
            ({"adapters": ["hook/*"]}, {}, False),
            ({"environments": ["dev"]}, {}, True),
        ],
    )
    def test_each_axis(
        self, tmp_path: Path, constraint: dict[str, object], patch: dict[str, object], fires: bool
    ) -> None:
        rule = {**BLOCKER, "applies_to": constraint}
        verdict = run(make_proposal(patch), bundle_of(tmp_path, rule))
        assert (verdict.decision is Decision.BLOCK) is fires

    def test_axes_are_combined_with_and(self, tmp_path: Path) -> None:
        rule = {**BLOCKER, "applies_to": {"kinds": ["mcp_tool"], "environments": ["prod"]}}
        bundle = bundle_of(tmp_path, rule)
        assert run(make_proposal(), bundle).decision is Decision.ALLOW
        prod = make_proposal({"context": {"environment": "prod"}})
        assert run(prod, bundle).decision is Decision.BLOCK

    def test_an_empty_applies_to_matches_everything(self, tmp_path: Path) -> None:
        rule = {k: v for k, v in BLOCKER.items() if k != "applies_to"}
        assert run(make_proposal(), bundle_of(tmp_path, rule)).decision is Decision.BLOCK


class TestDeterminism:
    def test_identical_inputs_give_identical_bytes(self, tmp_path: Path, prod) -> None:
        bundle = bundle_of(tmp_path, APPROVER, SHADOW_BLOCKER)
        budget = BudgetState(token_jti="j", budget=Budget(steps=10), steps_used=3)
        ctx = EvalContext(now=NOW)
        runs = {evaluate(prod, bundle, budget, ctx).model_dump_json() for _ in range(25)}
        assert len(runs) == 1

    def test_the_policy_hash_travels_with_the_verdict(self, tmp_path: Path, prod) -> None:
        bundle = bundle_of(tmp_path, APPROVER)
        assert run(prod, bundle).policy_hash == bundle.hash

    def test_hits_are_always_sorted_by_rule_id(self, tmp_path: Path, prod) -> None:
        zz = {**BLOCKER, "rule_id": "ZZ-BLK-999"}
        aa = {**APPROVER, "rule_id": "AA-APP-001"}
        verdict = run(prod, bundle_of(tmp_path, zz, aa))
        ids = [h.rule_id for h in verdict.hits]
        assert ids == sorted(ids)


class TestSyntheticShortCircuits:
    def test_budget_exhaustion_precedes_rule_evaluation(self, tmp_path: Path, prod) -> None:
        budget = BudgetState(token_jti="j", budget=Budget(steps=1), steps_used=1)
        verdict = run(prod, bundle_of(tmp_path, BLOCKER), budget)
        assert [h.rule_id for h in verdict.hits] == ["AG-BUD-001"]

    def test_a_short_circuit_still_carries_the_blast_radius(self, tmp_path: Path) -> None:
        """An approver seeing only "budget spent" cannot judge the risk."""
        proposal = make_proposal(
            {
                "context": {
                    "environment": "prod",
                    "blast_radius_hints": {"deletes": True, "scope": "account"},
                }
            }
        )
        budget = BudgetState(token_jti="j", budget=Budget(steps=1), steps_used=1)
        verdict = run(proposal, bundle_of(tmp_path, BLOCKER), budget)
        assert verdict.blast_radius == 100

    def test_a_short_circuit_still_carries_the_policy_hash(self, tmp_path: Path) -> None:
        bundle = bundle_of(tmp_path, BLOCKER)
        budget = BudgetState(token_jti="j", budget=Budget(steps=1), steps_used=1)
        assert run(make_proposal(), bundle, budget).policy_hash == bundle.hash


class TestARuleThatCannotBeEvaluated:
    """A `when` that raises skips its rule and is recorded (ADR-0016).

    The case that put this here: a masking rule's regex spent its budget on a
    loaded CI runner. A rule that cannot be evaluated is not an allow and not a
    block, and until this was decided it was neither recorded -- the verdict
    came out as though the bundle had one fewer rule in it.

    `(a|a)*$` is the pattern, measured rather than assumed: of six textbook
    catastrophic patterns the `regex` module optimises five away, and this is
    the one that still times out. See `tests/policy/test_predicates.py`.
    """

    CATASTROPHIC: Final = {
        "rule_id": "TT-RDS-001",
        "name": "A rule nobody can evaluate",
        "message": "No.",
        "verdict": "BLOCK",
        "when": {"field": "action.name", "regex": "(a|a)*$"},
    }

    @pytest.fixture
    def defeats_it(self) -> ActionProposal:
        return make_proposal({"action": {"name": "a" * 30 + "b"}})

    def _hit(self, verdict: Verdict) -> RuleHit:
        return next(h for h in verdict.hits if h.rule_id == PREDICATE_FAILED)

    def test_the_rule_is_skipped_rather_than_fired(self, tmp_path: Path, defeats_it) -> None:
        verdict = run(defeats_it, bundle_of(tmp_path, self.CATASTROPHIC))
        assert verdict.decision is Decision.ALLOW
        assert "TT-RDS-001" not in {h.rule_id for h in verdict.hits}

    def test_the_skip_is_recorded_with_the_rule_and_the_reason(
        self, tmp_path: Path, defeats_it
    ) -> None:
        """The reason, not just the fact: it is what separates a pattern that
        is catastrophic from a machine that was busy, and an operator reading
        the chain six weeks later has nothing else to go on."""
        hit = self._hit(run(defeats_it, bundle_of(tmp_path, self.CATASTROPHIC)))
        assert "TT-RDS-001" in hit.message
        assert "timed out" in hit.message
        assert "\n" not in hit.message
        assert hit.fix is not None

    def test_the_skip_hit_does_not_decide(self, tmp_path: Path, defeats_it) -> None:
        """`mode: shadow` and `ALLOW`, so that anything recomputing the decision
        from the enforce-mode hits still gets the decision the kernel gave."""
        hit = self._hit(run(defeats_it, bundle_of(tmp_path, self.CATASTROPHIC)))
        assert hit.mode is Mode.shadow
        assert hit.verdict is Decision.ALLOW

    def test_the_other_rules_still_decide(self, tmp_path: Path) -> None:
        """One unevaluable rule must not take the rest of the bundle with it."""
        proposal = make_proposal(
            {"action": {"name": "a" * 30 + "b"}, "context": {"environment": "prod"}}
        )
        verdict = run(proposal, bundle_of(tmp_path, self.CATASTROPHIC, BLOCKER))
        assert verdict.decision is Decision.BLOCK
        assert {h.rule_id for h in verdict.hits} == {"TT-BLK-001", PREDICATE_FAILED}

    def test_the_bundle_default_is_still_what_applied(self, tmp_path: Path, defeats_it) -> None:
        """Both hits, and both true: no rule matched, and one never got to say."""
        verdict = run(defeats_it, bundle_of(tmp_path, self.CATASTROPHIC))
        assert verdict.default_applied
        assert {h.rule_id for h in verdict.hits} == {"AG-DEF-001", PREDICATE_FAILED}

    def test_a_configured_default_is_not_overridden_by_the_skip(
        self, tmp_path: Path, defeats_it
    ) -> None:
        """The skip hit is appended after the decision. An instance configured
        to require approval by default must not come out ALLOW because an
        ALLOW-shaped record was appended to its hits."""
        bundle = bundle_of(tmp_path, self.CATASTROPHIC, default_verdict=Decision.REQUIRE_APPROVAL)
        verdict = run(defeats_it, bundle)
        assert verdict.decision is Decision.REQUIRE_APPROVAL
        assert verdict.would_decision is Decision.REQUIRE_APPROVAL

    def test_nothing_is_recorded_when_every_predicate_evaluates(self, tmp_path: Path, prod) -> None:
        verdict = run(prod, bundle_of(tmp_path, BLOCKER))
        assert PREDICATE_FAILED not in {h.rule_id for h in verdict.hits}

    def test_explain_names_the_skipped_rule(self, tmp_path: Path, defeats_it) -> None:
        report = explain(
            defeats_it,
            bundle_of(tmp_path, self.CATASTROPHIC),
            BudgetState(token_jti="j"),
            EvalContext(now=NOW),
        )
        skipped = report["rules_skipped"]
        assert isinstance(skipped, list)
        assert [entry["rule_id"] for entry in skipped] == ["TT-RDS-001"]

    def test_the_recorded_reason_is_bounded(self, tmp_path: Path) -> None:
        """A rule's own regex ends up in an evidence record, so the text that
        carries it is clipped rather than however long the author made it."""
        # The catastrophic branch first, so the pattern still times out; the
        # second branch is there only to make the text long.
        long_pattern = "(a|a)*$|" + "x" * 400
        rule = {**self.CATASTROPHIC, "when": {"field": "action.name", "regex": long_pattern}}
        verdict = run(
            make_proposal({"action": {"name": "a" * 30 + "b"}}), bundle_of(tmp_path, rule)
        )
        assert len(self._hit(verdict).message) < 300


def test_approval_spec_picks_the_most_severe_rule(tmp_path: Path, prod) -> None:
    low = {
        **APPROVER,
        "rule_id": "TT-APP-002",
        "severity": "LOW",
        "approval": {"approvers": ["junior"]},
    }
    bundle = bundle_of(tmp_path, APPROVER, low)
    verdict = run(prod, bundle)
    spec = approval_spec(bundle, verdict)  # type: ignore[arg-type]
    assert spec is not None and spec.approvers == ["sre"]


def test_approval_spec_is_none_when_nothing_asked_for_approval(tmp_path: Path, prod) -> None:
    bundle = bundle_of(tmp_path, BLOCKER)
    assert approval_spec(bundle, run(prod, bundle)) is None  # type: ignore[arg-type]


def test_explain_reports_the_rules_in_scope(tmp_path: Path, prod) -> None:
    bundle = bundle_of(tmp_path, APPROVER, BLOCKER)
    report = explain(prod, bundle, BudgetState(token_jti="j"), EvalContext(now=NOW))
    assert report["rules_total"] == 2
    assert {r["rule_id"] for r in report["rules_in_scope"]} == {
        "TT-APP-001",
        "TT-BLK-001",
    }
    assert report["blast_radius_contributions"]


class TestOneAllowanceOfRegexPerDecision:
    """A bundle cannot cost its rule count times the per-pattern worst case.

    Each rule used to start a fresh budget, so 46 unevaluable patterns was
    `46 * ATTEMPTS * BUDGET` -- over two minutes, in the request path, from one
    proposal. ADR-0018 gives the whole bundle one allowance.

    Built from the same measured catastrophic pattern as
    `TestARuleThatCannotBeEvaluated`, not a stub, because the thing being
    bounded is real regex time.
    """

    PATTERN: Final = "(a|a)*$"

    def _bundle(self, tmp_path: Path, count: int) -> PolicyBundle:
        return bundle_of(
            tmp_path,
            *[
                {
                    "rule_id": f"TT-RDS-{n:03d}",
                    "name": f"Unevaluable {n}",
                    "message": "No.",
                    "verdict": "BLOCK",
                    "when": {"field": "action.name", "regex": self.PATTERN},
                }
                for n in range(1, count + 1)
            ],
        )

    @pytest.fixture
    def defeats_it(self) -> ActionProposal:
        return make_proposal({"action": {"name": "a" * 30 + "b"}})

    def _reasons(self, verdict: Verdict) -> str:
        return next(h for h in verdict.hits if h.rule_id == PREDICATE_FAILED).message

    def test_the_rules_behind_the_first_bad_pattern_are_refused_not_retried(
        self, tmp_path: Path, defeats_it, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The bound, asserted through the reason rather than through a clock.

        A timing assertion is what #69 was about, and it would measure the
        host. What is checkable without one is the mechanism: once the
        allowance is gone the remaining rules are *refused*, and a refusal says
        so in words that differ from a pattern that spent its own budget.

        The allowance is shrunk so the test does not spend five seconds; the
        number is not what is under test, the behaviour at its edge is.
        """
        import qed.core.regex_budget as rb

        monkeypatch.setattr(rb, "POOL", rb.BUDGET * 1.5)
        verdict = run(defeats_it, self._bundle(tmp_path, 6))
        reasons = self._reasons(verdict)

        for n in range(1, 7):
            assert f"TT-RDS-{n:03d}" in reasons, (
                f"TT-RDS-{n:03d} was neither evaluated nor reported -- a rule dropped "
                "silently is the one outcome ADR-0016 exists to prevent"
            )
        assert "allowance" in reasons, (
            "no rule was refused by the allowance, so six unevaluable patterns each got "
            "their own full set of attempts and the bundle's cost still scales with its "
            "rule count"
        )

    def test_the_rule_that_spent_the_allowance_is_not_blamed_on_the_allowance(
        self, tmp_path: Path, defeats_it, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Attribution. The first rule's pattern really is at fault; the rest are not.

        Reporting them identically would point an operator at the last rule in
        the bundle instead of the one pattern that needs fixing.
        """
        import qed.core.regex_budget as rb

        monkeypatch.setattr(rb, "POOL", rb.BUDGET * 1.5)
        reasons = self._reasons(run(defeats_it, self._bundle(tmp_path, 6)))
        first, rest = reasons.split("TT-RDS-002", 1)

        assert "timed out" in first, (
            "the first rule, which spent the allowance on its own attempts, was reported "
            "as a victim of the allowance rather than as the pattern at fault"
        )
        assert "allowance" in rest

    def test_one_bad_pattern_does_not_cost_the_rules_behind_it(
        self, tmp_path: Path, defeats_it
    ) -> None:
        """The realistic case, at the real allowance: the bound never bites.

        A bundle has one bad pattern, not forty-six. The rules behind it need
        microseconds each, so they evaluate normally and still decide -- which
        is what keeps this bound from being a denial of service on the bundle.
        """
        bundle = bundle_of(
            tmp_path,
            {
                "rule_id": "TT-RDS-001",
                "name": "Unevaluable",
                "message": "No.",
                "verdict": "BLOCK",
                "when": {"field": "action.name", "regex": self.PATTERN},
            },
            BLOCKER,
        )
        proposal = make_proposal(
            {"action": {"name": "a" * 30 + "b"}, "context": {"environment": "prod"}}
        )
        verdict = run(proposal, bundle)

        assert verdict.decision is Decision.BLOCK, (
            "the rule behind the bad pattern did not get to decide, so the allowance is "
            "starving a working bundle rather than bounding a broken one"
        )
        assert "allowance" not in self._reasons(verdict)
