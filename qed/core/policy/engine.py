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

from qed.core.policy.derived import compute_derived
from qed.core.policy.model import ApprovalSpec, PolicyBundle, Rule
from qed.core.policy.predicates import PredicateError, evaluate_predicate
from qed.core.regex_budget import pooled
from qed.core.schemas import (
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

__all__ = ["PREDICATE_FAILED", "SYNTHETIC_RULES", "evaluate", "explain"]

#: The hit the engine records when a rule's ``when`` could not be evaluated and
#: the rule was skipped (ADR-0016). A constant because `qed/api/observe.py`
#: counts it: a rule id spelled out in two files is a metric that stops
#: counting the day the id changes.
PREDICATE_FAILED: Final = "AG-PRD-001"

#: How much of a skipped rule's error text reaches the evidence record. The
#: reason is kept -- it is what separates "this pattern is catastrophic" from
#: "the machine was busy" -- and bounded, because the text contains the rule's
#: own regex and a record is not the place for an unbounded one.
_MAX_REASON: Final = 120

_RANK: Final[dict[Decision, int]] = {
    Decision.ALLOW: 0,
    Decision.REQUIRE_APPROVAL: 1,
    Decision.BLOCK: 2,
}


class _Synthetic:
    """A hit the engine raises itself, not from the bundle."""

    __slots__ = ("compliance", "fix", "message", "mode", "rule_id", "severity", "verdict")

    def __init__(
        self,
        rule_id: str,
        verdict: Decision,
        severity: Severity,
        message: str,
        fix: str | None = None,
        compliance: tuple[tuple[str, str], ...] = (),
        mode: Mode = Mode.enforce,
    ) -> None:
        self.rule_id = rule_id
        self.mode = mode
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
            mode=self.mode,
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
        "Issue a mandate with `qed mandate sign` before running this agent.",
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
    # The one synthetic hit that is a report rather than a decision: `evaluate`
    # appends it *after* the decision is made, with `mode: shadow`, so that a
    # consumer recomputing the decision from the enforce-mode hits still gets
    # the decision the kernel gave. Its `message` is replaced per verdict with
    # the rule ids that were skipped (ADR-0016).
    PREDICATE_FAILED: _Synthetic(
        PREDICATE_FAILED,
        Decision.ALLOW,
        Severity.HIGH,
        "A rule could not be evaluated and was skipped, neither allowing nor blocking this action.",
        "Fix the rule's `when` -- a regex that spends its budget under machine load is the "
        "usual cause -- and check whether this action should have been governed.",
        (("nist_ai_rmf", "MEASURE-2.7"),),
        mode=Mode.shadow,
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


def _match(
    proposal: ActionProposal, bundle: PolicyBundle, derived: Derived
) -> tuple[list[Rule], list[tuple[str, str]]]:
    """The rules that fired, and the rules whose ``when`` could not be evaluated.

    Both lists are ordered by ``rule_id``, so neither can depend on which file a
    rule was read from or in what order the files were read.

    **A predicate that raises skips its rule** (ADR-0016). In practice that is a
    regex spending its budget, since `qed policy lint` refuses every structural
    error before a bundle ever loads. A rule that cannot be evaluated is not a
    hit and not an absence of one, and the two alternatives are both worse:
    counting the failure as a match turns machine load into a BLOCK, and
    refusing the whole proposal hands one bad pattern in one rule the power to
    stop every action the kernel governs. So the rule is left out of the
    decision and the skip is reported in the verdict as ``AG-PRD-001`` -- the
    one thing that must not happen is the decision coming out as if the bundle
    had one fewer rule in it and nobody being told.

    **Every regex here draws on one allowance** (ADR-0018), so a bundle cannot
    cost its rule count times the per-pattern worst case. The consequence to
    know about is that a rule can now be skipped because an *earlier* rule's
    pattern spent the allowance, which makes which rules are skipped depend on
    ``rule_id`` order. The decision itself does not depend on that order --
    :func:`_max_decision` takes a maximum over the hits -- and the skip message
    says which of the two happened, because they are different operator faults.
    In a bundle with one bad pattern the allowance is never reached by the
    rules behind it: they need microseconds each.
    """
    proposal_json = proposal.model_dump(mode="json")
    derived_json = derived.model_dump(mode="json")
    matched: list[Rule] = []
    skipped: list[tuple[str, str]] = []
    # One allowance of regex time for the whole bundle (ADR-0018). Without it
    # each rule starts a fresh one, so the cost of a decision is the rule count
    # times the per-pattern worst case -- 46 rules at three attempts of a
    # second is over two minutes in the request path.
    with pooled():
        for rule in sorted(bundle.active_rules(), key=lambda r: r.rule_id):
            if not _applies(rule, proposal):
                continue
            if rule.when is None:
                matched.append(rule)
                continue
            try:
                fired = evaluate_predicate(rule.when, proposal_json, derived_json)
            except PredicateError as exc:
                skipped.append((rule.rule_id, str(exc)))
                continue
            if fired:
                matched.append(rule)
    return matched, skipped


def matching_rules(proposal: ActionProposal, bundle: PolicyBundle, derived: Derived) -> list[Rule]:
    """Active rules whose ``applies_to`` and ``when`` both hold.

    A rule whose predicate could not be evaluated is not here and is not an
    error either; see :func:`_match`, which is what reports it.
    """
    return _match(proposal, bundle, derived)[0]


def _skipped_message(skipped: list[tuple[str, str]]) -> str:
    """One line naming every rule that was skipped, and why.

    One line because an SDK explanation and a hook's `reason` are single-line
    strings, and one hit rather than one per rule because `hits` is a list of
    rule ids and repeating the same id would make a verdict that reads as if
    ``AG-PRD-001`` had fired twice.
    """
    detail = "; ".join(f"{rule_id}: {_clip(reason)}" for rule_id, reason in skipped)
    if len(skipped) == 1:
        return (
            "A rule could not be evaluated and was skipped, neither allowing nor "
            f"blocking this action: {detail}"
        )
    return (
        f"{len(skipped)} rules could not be evaluated and were skipped, neither allowing "
        f"nor blocking this action: {detail}"
    )


def _clip(reason: str) -> str:
    flat = " ".join(reason.split())
    return flat if len(flat) <= _MAX_REASON else flat[:_MAX_REASON] + "..."


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

    matched, skipped = _match(proposal, bundle, derived)
    hits = [_rule_hit(rule) for rule in matched]
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

    if skipped:
        # Appended last, deliberately. This hit says a rule was *missing* from
        # the decision, so letting it take part in making one would be a
        # different claim -- and `default_applied` stays as computed, because
        # the default really was applied. `AG-PRD-001` beside `AG-DEF-001` is
        # the honest reading: no rule matched, and one rule never got to say.
        hits.append(
            SYNTHETIC_RULES[PREDICATE_FAILED]
            .hit()
            .model_copy(update={"message": _skipped_message(skipped)})
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
    from qed.core.policy import blast_radius

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
        # Each rule that `applies_to` selected and whose `when` then failed to
        # evaluate, with the reason unclipped: this view is read by an operator
        # on a terminal, not written to an evidence record.
        "rules_skipped": [
            {"rule_id": rule_id, "reason": reason}
            for rule_id, reason in _match(proposal, bundle, derived)[1]
        ],
        "policy_hash": bundle.hash,
        "rules_total": len(bundle.rules),
        "rules_active": len(bundle.active_rules()),
    }
