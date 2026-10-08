"""Golden policy cases (SPEC §21).

Each case in ``golden/cases.yaml`` is run twice: once against the bundle as
loaded, and once against the same rules shuffled. ADR-002.2 requires the result
to be independent of rule order, and the second pass is the only thing that
actually proves it.
"""

from __future__ import annotations

import random
from pathlib import Path
from typing import Any

import pytest
import yaml

from gate.core.policy.engine import evaluate
from gate.core.policy.model import PolicyBundle
from gate.core.schemas import (
    ActionProposal,
    BudgetState,
    Decision,
    EvalContext,
    Mandate,
    Verdict,
)
from tests.conftest import NOW, make_proposal

CASES_FILE = Path(__file__).parent / "golden" / "cases.yaml"
CASES: list[dict[str, Any]] = yaml.safe_load(CASES_FILE.read_text(encoding="utf-8"))

_VALID = {"from": "2026-01-01T00:00:00.000Z", "until": "2026-12-31T23:59:59.000Z"}
_BASE_MANDATE: dict[str, Any] = {
    "schema_version": "1.0",
    "id": "md_01",
    "issued_by_hash": "b" * 64,
    "for_agent": "svc:test-agent",
    "purpose": "golden test fixture",
    "allowed": {
        "kinds": ["mcp_tool"],
        "name_globs": ["github.list_*", "github.get_*"],
        "target_globs": ["repo:acme/*"],
        "environments": ["dev"],
    },
    "valid": dict(_VALID),
}

MANDATES: dict[str, dict[str, Any]] = {
    "within": _BASE_MANDATE,
    "http_only": {**_BASE_MANDATE, "allowed": {**_BASE_MANDATE["allowed"], "kinds": ["http"]}},
    "expired": {
        **_BASE_MANDATE,
        "valid": {"from": "2026-01-01T00:00:00.000Z", "until": "2026-01-02T00:00:00.000Z"},
    },
    "revoked": {**_BASE_MANDATE, "revoked_at": "2026-05-01T00:00:00.000Z"},
}


def _build(case: dict[str, Any]) -> tuple[ActionProposal, BudgetState, EvalContext]:
    proposal = make_proposal(case.get("patch") or {})
    budget_patch = case.get("budget")
    if budget_patch is None:
        budget = BudgetState(token_jti=proposal.principal.token_jti)
    else:
        budget = BudgetState.model_validate(
            {"token_jti": proposal.principal.token_jti, **budget_patch}
        )
    mandate_name = case.get("mandate")
    mandate = Mandate.model_validate(MANDATES[mandate_name]) if mandate_name else None
    return proposal, budget, EvalContext(now=NOW, mandate=mandate)


def _assert_expected(case: dict[str, Any], verdict: Verdict) -> None:
    expected = case["expect"]
    label = case["id"]
    hit_ids = [h.rule_id for h in verdict.hits]

    assert hit_ids == sorted(hit_ids), f"{label}: hits are not sorted by rule_id"
    assert hit_ids == sorted(expected["rules"]), (
        f"{label}: expected rules {sorted(expected['rules'])}, got {hit_ids}"
    )
    assert verdict.decision is Decision(expected["decision"]), (
        f"{label}: expected {expected['decision']}, got {verdict.decision.value}"
    )
    if "would" in expected:
        assert verdict.would_decision is Decision(expected["would"]), (
            f"{label}: expected would_decision {expected['would']}, "
            f"got {verdict.would_decision.value}"
        )
    if "blast_radius" in expected:
        assert verdict.blast_radius == expected["blast_radius"], (
            f"{label}: expected blast radius {expected['blast_radius']}, got {verdict.blast_radius}"
        )
    if "default_applied" in expected:
        assert verdict.default_applied is expected["default_applied"], label


@pytest.mark.parametrize("case", CASES, ids=[c["id"] for c in CASES])
def test_golden_case(case: dict[str, Any], baseline_bundle: PolicyBundle) -> None:
    proposal, budget, ctx = _build(case)
    _assert_expected(case, evaluate(proposal, baseline_bundle, budget, ctx))


@pytest.mark.parametrize("case", CASES, ids=[c["id"] for c in CASES])
def test_golden_case_is_order_independent(
    case: dict[str, Any], baseline_bundle: PolicyBundle
) -> None:
    shuffled = list(baseline_bundle.rules)
    random.Random(case["id"]).shuffle(shuffled)
    bundle = baseline_bundle.model_copy(update={"rules": shuffled})

    proposal, budget, ctx = _build(case)
    first = evaluate(proposal, baseline_bundle, budget, ctx)
    second = evaluate(proposal, bundle, budget, ctx)
    assert first.model_dump_json() == second.model_dump_json(), (
        f"{case['id']}: verdict changed when the rule list was reordered"
    )


def test_every_shipped_rule_is_exercised(baseline_bundle: PolicyBundle) -> None:
    """A rule nobody has a golden case for is a rule nobody has tested."""
    covered: set[str] = set()
    for case in CASES:
        covered.update(case["expect"]["rules"])
    missing = {r.rule_id for r in baseline_bundle.rules} - covered
    assert not missing, f"baseline rules with no golden case: {sorted(missing)}"


def test_case_count_meets_the_week_one_bar() -> None:
    assert len(CASES) >= 60, "SPEC §22 week 1 exit criterion is 60 golden tests"
