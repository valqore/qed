"""Policy test cases: the shape, and what it means to pass (SPEC §14, §21).

A case is a proposal plus the verdict it should get. That is the whole idea,
and it is the only way to change a rule set without guessing: write down what
should happen, then let the engine disagree with you.

Pure. The CLI reads the file and prints the results; everything here takes a
bundle and some cases and returns what happened.

Shared on purpose
-----------------

``tests/policy/test_golden.py`` and ``qed policy test`` compare results
through this module. Two comparison routines would drift, and the one that
drifted would be the user's -- ours is the one with a CI job behind it.

What a case asserts
-------------------

``rules`` is the **exact** set of rule ids in the verdict, not a subset. A case
therefore fails in two directions: when a rule stops firing, and when an
unrelated rule starts firing. The second is what catches a rule somebody
widened by accident, and it is the reason this is worth writing down at all.
"""

from __future__ import annotations

import copy
import random
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from qed.core.policy.engine import evaluate
from qed.core.policy.model import PolicyBundle
from qed.core.schemas import (
    ActionProposal,
    BudgetState,
    Decision,
    EvalContext,
    HistoryDerived,
    Mandate,
    Verdict,
)

__all__ = [
    "CaseFile",
    "CaseResult",
    "deep_merge",
    "load_cases",
    "run_case",
    "run_cases",
]


def deep_merge(base: dict[str, Any], patch: dict[str, Any]) -> dict[str, Any]:
    """``patch`` over ``base``, recursing into dicts.

    Keeps a case down to the two or three fields it is actually about, which
    is what makes a hundred of them readable instead of a hundred pages of
    JSON.
    """
    out = copy.deepcopy(base)
    for key, value in patch.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = deep_merge(out[key], value)
        else:
            out[key] = copy.deepcopy(value)
    return out


@dataclass(frozen=True)
class CaseFile:
    """A parsed case file: a base proposal, named mandates, and the cases."""

    base: dict[str, Any]
    cases: list[dict[str, Any]]
    mandates: dict[str, dict[str, Any]] = field(default_factory=dict)


@dataclass(frozen=True)
class CaseResult:
    case_id: str
    passed: bool
    failures: list[str]
    verdict: Verdict | None = None


class CaseError(ValueError):
    """The case file itself is wrong, as opposed to a case failing."""


def load_cases(document: Any, *, default_base: dict[str, Any] | None = None) -> CaseFile:
    """Validate the shape of a parsed YAML/JSON case document.

    Two layouts are accepted: a bare list of cases, which is what the shipped
    golden file is, and a mapping with ``base``, ``mandates`` and ``cases``.
    The bare list needs a ``default_base`` from the caller.
    """
    if isinstance(document, list):
        if default_base is None:
            raise CaseError(
                "this file is a bare list of cases, so it has nothing to patch over. "
                "Add a top-level `base:` with a complete proposal."
            )
        return CaseFile(base=default_base, cases=list(document))
    if not isinstance(document, dict):
        raise CaseError("a case file is either a list of cases or a mapping")

    cases = document.get("cases")
    if not isinstance(cases, list) or not cases:
        raise CaseError("`cases` must be a non-empty list")
    base = document.get("base", default_base)
    if not isinstance(base, dict):
        raise CaseError("`base` must be a complete proposal, as a mapping")
    mandates = document.get("mandates") or {}
    if not isinstance(mandates, dict):
        raise CaseError("`mandates` must be a mapping of name to mandate")

    seen: set[str] = set()
    for index, case in enumerate(cases):
        if not isinstance(case, dict):
            raise CaseError(f"case {index} is not a mapping")
        case_id = case.get("id")
        if not isinstance(case_id, str) or not case_id:
            raise CaseError(f"case {index} has no `id`")
        if case_id in seen:
            raise CaseError(f"duplicate case id {case_id!r}")
        seen.add(case_id)
        expect = case.get("expect")
        if not isinstance(expect, dict) or "decision" not in expect:
            raise CaseError(f"case {case_id!r} has no `expect.decision`")
        if "rules" not in expect:
            raise CaseError(
                f"case {case_id!r} has no `expect.rules`. List the exact rule ids you "
                "expect, including none at all as `[]` -- a case that only checks the "
                "decision passes when the right answer comes from the wrong rule."
            )

    return CaseFile(base=base, cases=cases, mandates=mandates)


def build_inputs(
    case: dict[str, Any], case_file: CaseFile, *, now: datetime
) -> tuple[ActionProposal, BudgetState, EvalContext]:
    """Turn one case into the three things the engine takes."""
    document = (
        case["proposal"]
        if isinstance(case.get("proposal"), dict)
        else deep_merge(case_file.base, case.get("patch") or {})
    )
    proposal = ActionProposal.model_validate(document)

    budget_patch = case.get("budget")
    if budget_patch is None:
        budget = BudgetState(token_jti=proposal.principal.token_jti)
    else:
        budget = BudgetState.model_validate(
            {"token_jti": proposal.principal.token_jti, **budget_patch}
        )

    mandate: Mandate | None = None
    name = case.get("mandate")
    if name is not None:
        if name not in case_file.mandates:
            raise CaseError(f"case {case['id']!r} names mandate {name!r}, which is not defined")
        mandate = Mandate.model_validate(case_file.mandates[name])

    # `derived.history` is a documented field path and rules read it, so a
    # case has to be able to set it. Without this a rule keyed on call or
    # block counts is untestable, and an untestable rule is one nobody can
    # change safely.
    history_patch = case.get("history")
    history = (
        HistoryDerived.model_validate(history_patch)
        if isinstance(history_patch, dict)
        else HistoryDerived()
    )

    return proposal, budget, EvalContext(now=now, mandate=mandate, history=history)


def _compare(case: dict[str, Any], verdict: Verdict) -> list[str]:
    expected = case["expect"]
    failures: list[str] = []
    hit_ids = [hit.rule_id for hit in verdict.hits]

    if hit_ids != sorted(hit_ids):
        failures.append(f"hits are not sorted by rule_id: {hit_ids}")
    wanted = sorted(expected["rules"])
    if hit_ids != wanted:
        extra = sorted(set(hit_ids) - set(wanted))
        missing = sorted(set(wanted) - set(hit_ids))
        detail = []
        if missing:
            detail.append(f"did not fire: {missing}")
        if extra:
            detail.append(f"fired unexpectedly: {extra}")
        failures.append("; ".join(detail) or f"expected {wanted}, got {hit_ids}")

    if verdict.decision is not Decision(expected["decision"]):
        failures.append(f"decision: expected {expected['decision']}, got {verdict.decision.value}")
    if "would" in expected and verdict.would_decision is not Decision(expected["would"]):
        failures.append(
            f"would_decision: expected {expected['would']}, got {verdict.would_decision.value}"
        )
    if "blast_radius" in expected and verdict.blast_radius != expected["blast_radius"]:
        failures.append(
            f"blast_radius: expected {expected['blast_radius']}, got {verdict.blast_radius}"
        )
    if "default_applied" in expected and verdict.default_applied is not expected["default_applied"]:
        failures.append(
            f"default_applied: expected {expected['default_applied']}, "
            f"got {verdict.default_applied}"
        )
    return failures


def run_case(
    case: dict[str, Any],
    case_file: CaseFile,
    bundle: PolicyBundle,
    *,
    now: datetime,
    check_order: bool = True,
) -> CaseResult:
    """Evaluate one case, and by default prove the answer is order-independent.

    The shuffle is not a nicety. ADR-002.2 says a decision must not depend on
    the order rules happen to load in, and running the same case against a
    reordered bundle is the only thing that actually demonstrates it. Anyone
    who writes a rule set gets that check for free.
    """
    try:
        proposal, budget, ctx = build_inputs(case, case_file, now=now)
    except (CaseError, ValueError) as exc:
        return CaseResult(case_id=case["id"], passed=False, failures=[str(exc)])

    verdict = evaluate(proposal, bundle, budget, ctx)
    failures = _compare(case, verdict)

    if check_order:
        shuffled = list(bundle.rules)
        random.Random(case["id"]).shuffle(shuffled)
        again = evaluate(proposal, bundle.model_copy(update={"rules": shuffled}), budget, ctx)
        if again.model_dump_json() != verdict.model_dump_json():
            failures.append(
                "the verdict changed when the rule list was reordered; a decision "
                "must not depend on the order rules load in (ADR-002.2)"
            )

    return CaseResult(case_id=case["id"], passed=not failures, failures=failures, verdict=verdict)


def run_cases(
    case_file: CaseFile, bundle: PolicyBundle, *, now: datetime, check_order: bool = True
) -> list[CaseResult]:
    return [
        run_case(case, case_file, bundle, now=now, check_order=check_order)
        for case in case_file.cases
    ]


def uncovered_rules(case_file: CaseFile, bundle: PolicyBundle) -> list[str]:
    """Rules no case mentions. A rule nobody tested is a rule nobody tested."""
    covered: set[str] = set()
    for case in case_file.cases:
        covered.update(case.get("expect", {}).get("rules") or [])
    return sorted({rule.rule_id for rule in bundle.rules} - covered)
