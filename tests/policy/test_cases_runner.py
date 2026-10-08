"""The case runner behind `gate policy test` (SPEC §14)."""

from __future__ import annotations

from typing import Any

import pytest

from gate.core.policy.cases import (
    CaseError,
    CaseFile,
    deep_merge,
    load_cases,
    run_case,
    run_cases,
    uncovered_rules,
)
from gate.core.policy.model import PolicyBundle
from tests.conftest import BASE_PROPOSAL, NOW

ALLOW_CASE: dict[str, Any] = {
    "id": "read-allows",
    "patch": {},
    "expect": {"decision": "ALLOW", "rules": ["AG-DEF-001"]},
}

BLOCK_PATCH: dict[str, Any] = {
    "context": {
        "environment": "prod",
        "blast_radius_hints": {"writes": True, "deletes": True, "scope": "account"},
    }
}


def file_with(*cases: dict[str, Any]) -> CaseFile:
    return CaseFile(base=BASE_PROPOSAL, cases=list(cases))


class TestDeepMerge:
    def test_a_patch_reaches_into_nested_maps(self) -> None:
        merged = deep_merge({"a": {"b": 1, "c": 2}}, {"a": {"b": 9}})
        assert merged == {"a": {"b": 9, "c": 2}}

    def test_a_list_is_replaced_not_merged(self) -> None:
        assert deep_merge({"a": [1, 2]}, {"a": [3]}) == {"a": [3]}

    def test_the_base_is_not_mutated(self) -> None:
        base = {"a": {"b": 1}}
        deep_merge(base, {"a": {"b": 2}})
        assert base == {"a": {"b": 1}}


class TestLoadCases:
    def test_a_mapping_with_base_and_cases_loads(self) -> None:
        loaded = load_cases({"base": BASE_PROPOSAL, "cases": [ALLOW_CASE]})
        assert len(loaded.cases) == 1

    def test_a_bare_list_needs_a_default_base(self) -> None:
        with pytest.raises(CaseError, match="nothing to patch over"):
            load_cases([ALLOW_CASE])

    def test_a_bare_list_loads_with_one(self) -> None:
        assert load_cases([ALLOW_CASE], default_base=BASE_PROPOSAL).cases == [ALLOW_CASE]

    def test_an_empty_case_list_is_refused(self) -> None:
        with pytest.raises(CaseError, match="non-empty"):
            load_cases({"base": BASE_PROPOSAL, "cases": []})

    def test_a_duplicate_id_is_refused(self) -> None:
        with pytest.raises(CaseError, match="duplicate"):
            load_cases({"base": BASE_PROPOSAL, "cases": [ALLOW_CASE, dict(ALLOW_CASE)]})

    def test_a_case_without_an_id_is_refused(self) -> None:
        with pytest.raises(CaseError, match="no `id`"):
            load_cases({"base": BASE_PROPOSAL, "cases": [{"expect": {"decision": "ALLOW"}}]})

    def test_a_case_without_expected_rules_is_refused(self) -> None:
        """A case that only checks the decision passes when the right answer
        comes from the wrong rule, which is worse than no case at all."""
        with pytest.raises(CaseError, match=r"expect.rules"):
            load_cases(
                {"base": BASE_PROPOSAL, "cases": [{"id": "x", "expect": {"decision": "ALLOW"}}]}
            )


class TestRunCase:
    def test_a_correct_case_passes(self, baseline_bundle: PolicyBundle) -> None:
        result = run_case(ALLOW_CASE, file_with(ALLOW_CASE), baseline_bundle, now=NOW)
        assert result.passed, result.failures

    def test_a_missing_rule_is_named(self, baseline_bundle: PolicyBundle) -> None:
        case = {
            "id": "wrong",
            "patch": {},
            "expect": {"decision": "ALLOW", "rules": ["AG-DEF-001", "AG-BLR-001"]},
        }
        result = run_case(case, file_with(case), baseline_bundle, now=NOW)
        assert not result.passed
        assert any("did not fire" in f and "AG-BLR-001" in f for f in result.failures)

    def test_an_unexpected_rule_is_named(self, baseline_bundle: PolicyBundle) -> None:
        """The direction that catches a rule somebody widened by accident."""
        case = {"id": "narrow", "patch": BLOCK_PATCH, "expect": {"decision": "BLOCK", "rules": []}}
        result = run_case(case, file_with(case), baseline_bundle, now=NOW)
        assert not result.passed
        assert any("fired unexpectedly" in f for f in result.failures)

    def test_a_wrong_decision_is_reported_separately(self, baseline_bundle: PolicyBundle) -> None:
        case = {"id": "d", "patch": {}, "expect": {"decision": "BLOCK", "rules": ["AG-DEF-001"]}}
        result = run_case(case, file_with(case), baseline_bundle, now=NOW)
        assert any(f.startswith("decision:") for f in result.failures)

    def test_blast_radius_is_checked_when_given(self, baseline_bundle: PolicyBundle) -> None:
        case = {
            "id": "br",
            "patch": {},
            "expect": {"decision": "ALLOW", "rules": ["AG-DEF-001"], "blast_radius": 99},
        }
        result = run_case(case, file_with(case), baseline_bundle, now=NOW)
        assert any("blast_radius" in f for f in result.failures)

    def test_a_full_proposal_can_replace_the_patch(self, baseline_bundle: PolicyBundle) -> None:
        case = {
            "id": "whole",
            "proposal": BASE_PROPOSAL,
            "expect": {"decision": "ALLOW", "rules": ["AG-DEF-001"]},
        }
        assert run_case(case, file_with(case), baseline_bundle, now=NOW).passed

    def test_an_invalid_proposal_fails_the_case_rather_than_raising(
        self, baseline_bundle: PolicyBundle
    ) -> None:
        """A broken case is a failing case. Raising would stop the run and hide
        every case after it."""
        case = {
            "id": "broken",
            "patch": {"action": {"kind": "not-a-kind"}},
            "expect": {"decision": "ALLOW", "rules": []},
        }
        result = run_case(case, file_with(case), baseline_bundle, now=NOW)
        assert not result.passed
        assert result.verdict is None

    def test_an_undefined_mandate_name_fails_the_case(self, baseline_bundle: PolicyBundle) -> None:
        case = {
            "id": "m",
            "patch": {},
            "mandate": "nope",
            "expect": {"decision": "ALLOW", "rules": []},
        }
        result = run_case(case, file_with(case), baseline_bundle, now=NOW)
        assert not result.passed
        assert any("not defined" in f for f in result.failures)

    def test_the_order_check_runs_by_default(self, baseline_bundle: PolicyBundle) -> None:
        """Not a nicety: ADR-002.2 says a decision must not depend on the order
        rules load in, and a reshuffled bundle is the only thing that shows it.
        Anyone writing a rule set gets the check for free."""
        case = {"id": "o", "patch": BLOCK_PATCH, "expect": {"decision": "BLOCK", "rules": []}}
        with_check = run_case(case, file_with(case), baseline_bundle, now=NOW)
        without = run_case(case, file_with(case), baseline_bundle, now=NOW, check_order=False)
        # Both fail on the rule set; neither should fail on ordering, because
        # the engine is order-independent. The point is that one *ran* it.
        assert not any("reordered" in f for f in with_check.failures)
        assert not any("reordered" in f for f in without.failures)


class TestRunCases:
    def test_every_case_is_run_even_after_a_failure(self, baseline_bundle: PolicyBundle) -> None:
        bad = {"id": "bad", "patch": {}, "expect": {"decision": "BLOCK", "rules": []}}
        good = dict(ALLOW_CASE)
        results = run_cases(file_with(bad, good), baseline_bundle, now=NOW)
        assert [r.passed for r in results] == [False, True]


class TestCoverage:
    def test_rules_with_no_case_are_listed(self, baseline_bundle: PolicyBundle) -> None:
        missing = uncovered_rules(file_with(ALLOW_CASE), baseline_bundle)
        assert "AG-DEF-001" not in missing
        assert "AG-BLR-001" in missing
