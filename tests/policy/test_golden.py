"""Golden policy cases (SPEC §21).

Each case in ``golden/cases.yaml`` is run twice: once against the bundle as
loaded, and once against the same rules shuffled. ADR-002.2 requires the result
to be independent of rule order, and the second pass is the only thing that
actually proves it.

The comparison itself lives in ``gate.core.policy.cases`` and is shared with
``gate policy test``. Two comparison routines would drift, and the one that
drifted would be the user's -- ours is the one with a CI job behind it.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

from gate.core.policy.cases import CaseFile, run_case, uncovered_rules
from gate.core.policy.engine import evaluate
from gate.core.policy.model import PolicyBundle
from gate.core.schemas import ActionProposal, BudgetState, EvalContext, Mandate
from tests.conftest import BASE_PROPOSAL, NOW, make_proposal

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


CASE_FILE = CaseFile(base=BASE_PROPOSAL, cases=CASES, mandates=MANDATES)


@pytest.mark.parametrize("case", CASES, ids=[c["id"] for c in CASES])
def test_golden_case(case: dict[str, Any], baseline_bundle: PolicyBundle) -> None:
    """Runs the shuffle check too: `run_case` does both by default."""
    result = run_case(case, CASE_FILE, baseline_bundle, now=NOW)
    assert result.passed, f"{case['id']}: " + "; ".join(result.failures)


def test_the_shared_runner_builds_the_same_inputs_the_engine_sees(
    baseline_bundle: PolicyBundle,
) -> None:
    """Guards the refactor above: the shared builder must produce the same
    verdict as building the inputs by hand, or the golden suite would be
    testing something other than what `gate check` does."""
    case = next(c for c in CASES if c["id"] == "def-001-plain-read-allows")
    proposal, budget, ctx = _build(case)
    by_hand = evaluate(proposal, baseline_bundle, budget, ctx)
    shared = run_case(case, CASE_FILE, baseline_bundle, now=NOW, check_order=False)
    assert shared.verdict is not None
    assert shared.verdict.model_dump_json() == by_hand.model_dump_json()


def test_every_shipped_rule_is_exercised(baseline_bundle: PolicyBundle) -> None:
    """A rule nobody has a golden case for is a rule nobody has tested."""
    missing = uncovered_rules(CASE_FILE, baseline_bundle)
    assert not missing, f"baseline rules with no golden case: {missing}"


def test_case_count_meets_the_week_one_bar() -> None:
    assert len(CASES) >= 60, "SPEC §22 week 1 exit criterion is 60 golden tests"
