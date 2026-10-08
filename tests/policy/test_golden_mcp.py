"""Golden cases for proposals the MCP proxy actually builds (SPEC §21, §22).

The table in ``golden/cases.yaml`` is written against the proposal schema. This
one starts one step earlier: each case is a tool name and an argument object,
exactly what arrives on the wire, and the proposal is built by the real adapter
code before the real engine decides it.

That closes the gap the week 1 review was about. A verdict is only as good as
the hints the adapter supplied, so a table that hand-writes
``blast_radius_hints`` cannot catch an adapter that stops deriving them. These
cases would have caught the original ``execute_sql`` / ``DROP TABLE`` bug;
``cases.yaml`` could not have.

Each case is run twice with the rule list shuffled, for the same reason
``test_golden.py`` does it (ADR-002.2).
"""

from __future__ import annotations

import random
from typing import Any

import pytest

from gate.adapters.mcp.proxy import ProxyOptions, UpstreamSpec, build_tool_proposal
from gate.core.evidence.hashing import principal_hash
from gate.core.policy.engine import evaluate
from gate.core.policy.model import PolicyBundle
from gate.core.schemas import (
    BudgetState,
    Decision,
    Enforcement,
    EvalContext,
    Mode,
    Scope,
)
from tests.conftest import NOW

HUMAN = principal_hash("tester@example.com", issuer="local")

#: Each case: the tool name and arguments as they arrive on the wire, the
#: environment, and what the kernel must decide.
#:
#: ``rules`` is the exact sorted set, so a case fails both when a rule stops
#: firing and when an unrelated one starts. ``blast`` and ``hints`` pin the two
#: numbers in between -- what the adapter derived, and what the kernel scored
#: from it -- so a regression names itself instead of showing up as a rule that
#: mysteriously stopped matching.
CASES: list[dict[str, Any]] = [
    # ---------------------------------------------------------------- reads
    {
        "id": "read-in-dev-allows",
        "tool": "list_tables",
        "arguments": {},
        "env": "dev",
        "decision": "ALLOW",
        "rules": ["AG-DEF-001"],
        "blast": 10,
        "hints": (False, False, "single_resource"),
    },
    {
        "id": "read-in-prod-allows",
        "tool": "get_order",
        "arguments": {"id": 42},
        "env": "prod",
        "decision": "ALLOW",
        "rules": ["AG-DEF-001"],
        "blast": 25,
        "hints": (False, False, "single_resource"),
    },
    # --------------------------------- the bug the week 1 review carried on
    {
        "id": "execute-sql-carrying-drop-table-in-prod-needs-approval",
        "tool": "execute_sql",
        "arguments": {"sql": "DROP TABLE orders_archive;", "table": "orders_archive"},
        "env": "prod",
        "decision": "REQUIRE_APPROVAL",
        "rules": ["AG-BLR-003", "AG-BLR-005", "AG-BLR-009", "AG-BUD-005"],
        "blast": 75,
        "hints": (True, True, "single_resource"),
    },
    {
        "id": "execute-sql-carrying-select-in-prod-allows",
        "tool": "execute_sql",
        "arguments": {"sql": "SELECT count(*) FROM orders", "table": "orders"},
        "env": "prod",
        "decision": "ALLOW",
        "rules": ["AG-BLR-009", "AG-BUD-005", "AG-DAT-004", "AG-DEF-001"],
        "blast": 35,
        "hints": (True, False, "single_resource"),
    },
    {
        # Exactly 60, and AG-BLR-005 triggers above 60. The boundary is
        # pinned on purpose: `gt` vs `gte` here is a one-character change
        # that would quietly start routing every dev drop to approval.
        "id": "the-same-drop-in-dev-scores-exactly-on-the-threshold",
        "tool": "execute_sql",
        "arguments": {"sql": "DROP TABLE scratch;", "table": "scratch"},
        "env": "dev",
        "decision": "ALLOW",
        "rules": ["AG-DEF-001"],
        "blast": 60,
        "hints": (True, True, "single_resource"),
    },
    # ------------------------------------------------------ destructive verbs
    {
        "id": "delete-with-a-selector-in-prod-is-a-multi-resource-delete",
        "tool": "delete_rows",
        "arguments": {"table": "payments", "selector": "status=old"},
        "env": "prod",
        "decision": "REQUIRE_APPROVAL",
        "rules": ["AG-BLR-002", "AG-BLR-003", "AG-BLR-005", "AG-BLR-009", "AG-BUD-005"],
        "blast": 95,
        "hints": (True, True, "multi_resource"),
    },
    {
        "id": "a-single-row-delete-in-prod-does-not-fire-multi-resource",
        "tool": "delete_row",
        "arguments": {"table": "payments", "id": 7},
        "env": "prod",
        "decision": "REQUIRE_APPROVAL",
        "rules": ["AG-BLR-003", "AG-BLR-005", "AG-BLR-009", "AG-BUD-005"],
        "blast": 75,
        "hints": (True, True, "single_resource"),
    },
    {
        "id": "an-account-wide-delete-in-prod-is-blocked",
        "tool": "delete_everything",
        "arguments": {"account": "123456789012"},
        "env": "prod",
        "decision": "BLOCK",
        "rules": [
            "AG-BLR-001",
            "AG-BLR-002",
            "AG-BLR-003",
            "AG-BLR-005",
            "AG-BLR-009",
            "AG-BUD-005",
        ],
        "blast": 100,
        "hints": (True, True, "account"),
    },
    # ------------------------------------------------------- identity surface
    {
        "id": "a-write-to-the-iam-surface-needs-security-approval",
        "tool": "put_role_policy",
        "arguments": {"role": "deploy", "policy": "AdministratorAccess"},
        "env": "prod",
        "decision": "REQUIRE_APPROVAL",
        "rules": ["AG-BLR-004", "AG-BLR-009", "AG-BUD-005", "AG-IDN-004"],
        "blast": 50,
        "hints": (True, False, "single_resource"),
        "template": "aws:iam:roles/{args.role}",
    },
    # ------------------------------------------------------------------- data
    {
        "id": "a-secret-in-the-arguments-is-blocked",
        "tool": "set_config",
        "arguments": {"body": "aws_key=AKIAIOSFODNN7EXAMPLE"},
        "env": "dev",
        "decision": "BLOCK",
        "rules": ["AG-DAT-001"],
        "blast": 20,
        "hints": (True, False, "single_resource"),
    },
    {
        "id": "personal-data-in-the-arguments-needs-privacy-approval",
        "tool": "update_record",
        "arguments": {"body": "contact ali@acme.com about the order"},
        "env": "dev",
        "decision": "REQUIRE_APPROVAL",
        "rules": ["AG-DAT-002"],
        "blast": 20,
        "hints": (True, False, "single_resource"),
    },
    # ------------------------------------------------------------ read-through
    {
        "id": "a-resource-read-is-an-ordinary-read",
        "tool": "resources/read",
        "arguments": {"uri": "db://orders/schema"},
        "env": "prod",
        "decision": "ALLOW",
        "rules": ["AG-DEF-001"],
        "blast": 25,
        "hints": (False, False, "single_resource"),
    },
    # --------------------------------------------------------- unknown verbs
    {
        "id": "an-unknown-verb-is-not-assumed-safe-but-still-allows-by-default",
        "tool": "frobnicate",
        "arguments": {"thing": "widget"},
        "env": "prod",
        "decision": "ALLOW",
        "rules": ["AG-DEF-001"],
        "blast": 25,
        "hints": (False, False, "single_resource"),
    },
    {
        "id": "a-wildcard-argument-widens-the-scope",
        "tool": "delete_objects",
        "arguments": {"bucket": "backups", "key": "2026/*"},
        "env": "prod",
        "decision": "REQUIRE_APPROVAL",
        "rules": ["AG-BLR-002", "AG-BLR-003", "AG-BLR-005", "AG-BLR-009", "AG-BUD-005"],
        "blast": 95,
        "hints": (True, True, "multi_resource"),
    },
]

UPSTREAM = UpstreamSpec(name="orders", command="true")
OPTIONS = ProxyOptions(human_hash=HUMAN, enforcement=Enforcement.enforcing)


def build(case: dict[str, Any]) -> Any:
    upstream = (
        UPSTREAM
        if "template" not in case
        else UpstreamSpec(name="orders", command="true", target_template=case["template"])
    )
    options = ProxyOptions(
        human_hash=HUMAN,
        enforcement=Enforcement.enforcing,
        environment=case["env"],
    )
    proposal, _ = build_tool_proposal(
        upstream=upstream,
        tool=case["tool"],
        arguments=case["arguments"],
        options=options,
        mode=Mode.enforce,
    )
    return proposal


@pytest.mark.parametrize("case", CASES, ids=[c["id"] for c in CASES])
def test_golden_mcp_case(case: dict[str, Any], baseline_bundle: PolicyBundle) -> None:
    proposal = build(case)
    verdict = evaluate(
        proposal,
        baseline_bundle,
        BudgetState(token_jti=proposal.principal.token_jti),
        EvalContext(now=NOW),
    )
    hit_ids = [hit.rule_id for hit in verdict.hits]
    assert hit_ids == sorted(case["rules"]), case["id"]
    assert verdict.decision is Decision(case["decision"]), (
        f"{case['id']}: expected {case['decision']}, got {verdict.decision.value}"
    )
    assert verdict.blast_radius == case["blast"], (
        f"{case['id']}: expected blast radius {case['blast']}, got {verdict.blast_radius}"
    )


@pytest.mark.parametrize("case", CASES, ids=[c["id"] for c in CASES])
def test_the_adapter_derived_the_hints_the_rules_relied_on(case: dict[str, Any]) -> None:
    """Pinned separately, so a hint regression names itself.

    Without this, an adapter that stopped deriving ``deletes`` would show up as
    a rule that mysteriously stopped firing.
    """
    hints = build(case).context.blast_radius_hints
    expected: tuple[bool, bool, Scope] = case["hints"]
    assert (hints.writes, hints.deletes, hints.scope) == expected, case["id"]


@pytest.mark.parametrize("case", CASES, ids=[c["id"] for c in CASES])
def test_golden_mcp_case_is_order_independent(
    case: dict[str, Any], baseline_bundle: PolicyBundle
) -> None:
    shuffled = list(baseline_bundle.rules)
    random.Random(case["id"]).shuffle(shuffled)
    reordered = baseline_bundle.model_copy(update={"rules": shuffled})

    proposal = build(case)
    budget = BudgetState(token_jti=proposal.principal.token_jti)
    ctx = EvalContext(now=NOW)
    first = evaluate(proposal, baseline_bundle, budget, ctx)
    second = evaluate(proposal, reordered, budget, ctx)
    assert first.model_dump_json() == second.model_dump_json()


def test_the_proposal_the_adapter_builds_is_schema_valid_and_bounded() -> None:
    """A proposal the API would refuse is a call that leaves no record."""
    from gate.adapters.common import MAX_PARAMS_BYTES, MAX_PROPOSAL_BYTES

    proposal, _ = build_tool_proposal(
        upstream=UPSTREAM,
        tool="execute_sql",
        arguments={"sql": "x" * 500_000, "rows": ["y" * 1000] * 500},
        options=OPTIONS,
        mode=Mode.shadow,
    )
    body = proposal.model_dump_json()
    assert len(body) <= MAX_PROPOSAL_BYTES
    from gate.core import jcs

    assert len(jcs.dumps(proposal.action.params_redacted)) <= MAX_PARAMS_BYTES


def test_every_mcp_case_names_a_rule_that_exists(baseline_bundle: PolicyBundle) -> None:
    from gate.core.policy.engine import SYNTHETIC_RULES

    known = {rule.rule_id for rule in baseline_bundle.rules} | set(SYNTHETIC_RULES)
    for case in CASES:
        unknown = set(case["rules"]) - known
        assert not unknown, f"{case['id']} expects rules that do not exist: {sorted(unknown)}"
