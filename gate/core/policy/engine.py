"""The policy engine (SPEC §5, precedence per SPEC §4.5).

``evaluate`` is a pure function. Same proposal, bundle, budget state and context
produce a byte-identical verdict. No clock, no I/O, no LLM: the only time source
is ``ctx.now``, supplied by the caller, which is what makes a decision
replayable months later from the evidence chain alone.

Ordering differs from the §5 pseudo-code in one harmless way: derived values are
computed *before* the budget short-circuit, so a budget-exhausted BLOCK still
carries a real ``blast_radius`` for the approver and the auditor. ``compute_derived``
is pure, so this cannot change any decision. SPEC §4.5 requires the budget check
to precede *rule evaluation*, and it still does.
"""

from __future__ import annotations

from typing import Final

from gate.core.policy.derived import compute_derived
from gate.core.policy.model import ApprovalSpec, PolicyBundle, Rule
from gate.core.policy.predicates import evaluate_predicate
from gate.core.schemas import (
    ENGINE_VERSION,
    ActionProposal,
    BudgetState,
    ComplianceRef,
    Decision,
    Derived,
    EvalContext,
    Mode,
    RuleHit,
    Severity,
    Verdict,
)

__all__ = ["SYNTHETIC_RULES", "evaluate", "explain"]

_RANK: Final[dict[Decision, int]] = {
    Decision.ALLOW: 0,
    Decision.REQUIRE_APPROVAL: 1,
    Decision.BLOCK: 2,
}


class _Synthetic:
    """A hit the engine raises itself, not from the bundle."""

    __slots__ = ("compliance", "fix", "message", "rule_id", "severity", "verdict")

    def __init__(
        self,
        rule_id: str,
        verdict: Decision,
        severity: Severity,
        message: str,
        fix: str | None = None,
        compliance: tuple[tuple[str, str], ...] = (),
    ) -> None:
        self.rule_id = rule_id
        self.verdict = verdict
        self.severity = severity
        self.message = message
        self.fix = fix
        self.compliance = compliance

    def hit(self) -> RuleHit:
        return RuleHit(
            rule_id=self.rule_id,
            verdict=self.verdict,
            severity=self.severity,
            mode=Mode.enforce,
            message=self.message,
            fix=self.fix,
            compliance=[ComplianceRef(framework=f, control=c) for f, c in self.compliance],
        )


SYNTHETIC_RULES: Final[dict[str, _Synthetic]] = {
    "AG-BUD-001": _Synthetic(
        "AG-BUD-001",
        Decision.BLOCK,
        Severity.HIGH,
        "The delegation token's budget is exhausted.",
        "Request a new token, or raise the budget cap for this group.",
        (("eu_ai_act", "Art. 14"), ("nist_ai_rmf", "MANAGE-2.2")),
    ),
    "AG-IDN-006": _Synthetic(
        "AG-IDN-006",
        Decision.BLOCK,
        Severity.CRITICAL,
        "The action is outside the mandate that authorises this unattended agent.",
        "Widen the mandate deliberately, or have a human run this action.",
        (("eu_ai_act", "Art. 14"), ("owasp_agentic", "ASI02")),
    ),
    "AG-IDN-007": _Synthetic(
        "AG-IDN-007",
        Decision.BLOCK,
        Severity.CRITICAL,
        "An unattended agent acted with no mandate on record.",
        "Issue a mandate with `gate mandate sign` before running this agent.",
        (("eu_ai_act", "Art. 14"), ("owasp_agentic", "ASI02")),
    ),
    "AG-DEF-001": _Synthetic(
        "AG-DEF-001",
        Decision.ALLOW,
        Severity.LOW,
        "No rule matched this action; the bundle default was applied.",
        "If this class of action should be governed, add a rule for it.",
        (("nist_ai_rmf", "MEASURE-2.7"),),
    ),
}


def _max_decision(hits: list[RuleHit], fallback: Decision) -> Decision:
    if not hits:
        return fallback
    return max((h.verdict for h in hits), key=lambda d: _RANK[d])


def _applies(rule: Rule, proposal: ActionProposal) -> bool:
    from fnmatch import fnmatchcase

    at = rule.applies_to
    if at.kinds is not None and proposal.action.kind not in at.kinds:
        return False
    if at.environments is not None and proposal.context.environment not in at.environments:
        return False
    if at.name_globs is not None and not any(
        fnmatchcase(proposal.action.name, g) for g in at.name_globs
    ):
        return False
    if at.target_globs is not None and not any(
        fnmatchcase(proposal.action.target, g) for g in at.target_globs
    ):
        return False
    return at.adapters is None or any(fnmatchcase(proposal.context.adapter, g) for g in at.adapters)


def _rule_hit(rule: Rule) -> RuleHit:
    return RuleHit(
        rule_id=rule.rule_id,
        verdict=rule.verdict,
        severity=rule.severity,
        mode=rule.mode,
        message=rule.message,
        fix=rule.fix,
        compliance=list(rule.compliance),
    )


def _synthetic_verdict(
    proposal: ActionProposal, rule_id: str, bundle: PolicyBundle, derived: Derived
) -> Verdict:
    hit = SYNTHETIC_RULES[rule_id].hit()
    return Verdict(
        proposal_id=proposal.id,
        decision=hit.verdict,
        would_decision=hit.verdict,
        hits=[hit],
        blast_radius=derived.blast_radius,
        policy_hash=bundle.hash,
        engine_version=ENGINE_VERSION,
        default_applied=False,
    )


def matching_rules(proposal: ActionProposal, bundle: PolicyBundle, derived: Derived) -> list[Rule]:
    """Active rules whose ``applies_to`` and ``when`` both hold.

    Sorted by ``rule_id``, so the result cannot depend on which file a rule was
    read from or in what order the files were read.
    """
    proposal_json = proposal.model_dump(mode="json")
    derived_json = derived.model_dump(mode="json")
    out: list[Rule] = []
    for rule in sorted(bundle.active_rules(), key=lambda r: r.rule_id):
        if not _applies(rule, proposal):
            continue
        if rule.when is None or evaluate_predicate(rule.when, proposal_json, derived_json):
            out.append(rule)
    return out


def evaluate(
    proposal: ActionProposal,
    bundle: PolicyBundle,
    budget: BudgetState,
    ctx: EvalContext,
) -> Verdict:
    """Decide one proposal. Pure."""
    derived = compute_derived(proposal, budget, ctx)

    if budget.exhausted(ctx.now):
        return _synthetic_verdict(proposal, "AG-BUD-001", bundle, derived)
    if proposal.principal.human_hash is None and not derived.mandate.present:
        return _synthetic_verdict(proposal, "AG-IDN-007", bundle, derived)
    if derived.mandate.present and not derived.mandate.within:
        return _synthetic_verdict(proposal, "AG-IDN-006", bundle, derived)

    hits = [_rule_hit(rule) for rule in matching_rules(proposal, bundle, derived)]
    enforce_hits = [h for h in hits if h.mode is Mode.enforce]

    decision = _max_decision(enforce_hits, bundle.default_verdict)
    would_decision = _max_decision(hits, bundle.default_verdict)
    default_applied = not enforce_hits
    if default_applied:
        # The recorded hit carries the bundle's own default, not a hardcoded
        # ALLOW: an instance configured `default_verdict: REQUIRE_APPROVAL`
        # must not leave an auditor reading "ALLOW" in the chain.
        hits.append(
            SYNTHETIC_RULES["AG-DEF-001"]
            .hit()
            .model_copy(update={"verdict": bundle.default_verdict})
        )

    return Verdict(
        proposal_id=proposal.id,
        decision=decision,
        would_decision=would_decision,
        hits=sorted(hits, key=lambda h: h.rule_id),
        blast_radius=derived.blast_radius,
        policy_hash=bundle.hash,
        engine_version=ENGINE_VERSION,
        default_applied=default_applied,
    )


def approval_spec(bundle: PolicyBundle, verdict: Verdict) -> ApprovalSpec | None:
    """The approval block of the highest-severity enforcing rule that asked for one."""
    candidates = [
        rule
        for hit in verdict.hits
        if (rule := bundle.by_id(hit.rule_id)) is not None
        and rule.verdict is Decision.REQUIRE_APPROVAL
        and rule.mode is Mode.enforce
        and rule.approval is not None
    ]
    if not candidates:
        return None
    order = {Severity.CRITICAL: 3, Severity.HIGH: 2, Severity.MEDIUM: 1, Severity.LOW: 0}
    best = max(candidates, key=lambda r: (order[r.severity], r.rule_id))
    return best.approval


def explain(
    proposal: ActionProposal, bundle: PolicyBundle, budget: BudgetState, ctx: EvalContext
) -> dict[str, object]:
    """Operator debug view: the verdict plus why each number came out that way."""
    from gate.core.policy import blast_radius

    derived = compute_derived(proposal, budget, ctx)
    verdict = evaluate(proposal, bundle, budget, ctx)
    considered = [
        {"rule_id": r.rule_id, "applies": True, "mode": r.mode.value}
        for r in sorted(bundle.active_rules(), key=lambda r: r.rule_id)
        if _applies(r, proposal)
    ]
    return {
        "verdict": verdict.model_dump(mode="json"),
        "derived": derived.model_dump(mode="json"),
        "blast_radius_contributions": [
            {"reason": reason, "points": points}
            for reason, points in blast_radius.explain(proposal)
        ],
        "rules_in_scope": considered,
        "policy_hash": bundle.hash,
        "rules_total": len(bundle.rules),
        "rules_active": len(bundle.active_rules()),
    }
