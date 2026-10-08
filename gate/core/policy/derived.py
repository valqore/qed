"""Derived context (SPEC §4.4, §5).

Everything a rule can read that is not literally in the proposal. Pure: the
history snapshot and the mandate arrive in :class:`EvalContext`, collected by
the caller before the engine runs, because the engine performs no I/O.
"""

from __future__ import annotations

from fnmatch import fnmatchcase

from gate.core.policy import blast_radius
from gate.core.schemas import (
    ActionProposal,
    Budget,
    BudgetDerived,
    BudgetState,
    Derived,
    EvalContext,
    Mandate,
    MandateDerived,
)

__all__ = ["compute_derived", "within_mandate"]


def _remaining(cap: int, used: int) -> int | None:
    """``None`` when the axis is uncapped (cap of 0)."""
    return None if cap == 0 else max(cap - used, 0)


def _pct_used(cap: int, used: int) -> int | None:
    return None if cap == 0 else min(int(used * 100 // cap), 100)


def _budget_derived(state: BudgetState, ctx: EvalContext, cost_money_cents: int) -> BudgetDerived:
    budget: Budget = state.budget
    seconds_remaining: int | None = None
    seconds_pct_used: int | None = None
    if budget.seconds:
        elapsed = 0.0 if state.first_seen is None else (ctx.now - state.first_seen).total_seconds()
        seconds_remaining = max(int(budget.seconds - elapsed), 0)
        seconds_pct_used = _pct_used(budget.seconds, int(elapsed))
    money_remaining = _remaining(budget.money_cents, state.money_used_cents)
    return BudgetDerived(
        steps_remaining=_remaining(budget.steps, state.steps_used),
        tokens_remaining=_remaining(budget.tokens, state.tokens_used),
        seconds_remaining=seconds_remaining,
        money_remaining_cents=money_remaining,
        steps_pct_used=_pct_used(budget.steps, state.steps_used),
        tokens_pct_used=_pct_used(budget.tokens, state.tokens_used),
        money_pct_used=_pct_used(budget.money_cents, state.money_used_cents),
        seconds_pct_used=seconds_pct_used,
        money_overrun=None if money_remaining is None else cost_money_cents > money_remaining,
    )


def within_mandate(proposal: ActionProposal, mandate: Mandate) -> bool:
    """Is the action inside the mandate's ``allowed`` envelope (SPEC §3.4)?

    Every present constraint must hold. An absent constraint means "any", which
    matches ``applies_to`` semantics so a reader does not have to hold two
    different rules in their head.
    """
    allowed = mandate.allowed
    action = proposal.action
    if allowed.kinds is not None and action.kind not in allowed.kinds:
        return False
    environments = allowed.environments
    if environments is not None and proposal.context.environment not in environments:
        return False
    if allowed.name_globs is not None and not any(
        fnmatchcase(action.name, g) for g in allowed.name_globs
    ):
        return False
    return allowed.target_globs is None or any(
        fnmatchcase(action.target, g) for g in allowed.target_globs
    )


def mandate_validity(mandate: Mandate, ctx: EvalContext) -> bool:
    """Time window and revocation. Signature verification is the token layer's job."""
    if mandate.revoked_at is not None and mandate.revoked_at <= ctx.now:
        return False
    return mandate.valid.from_ <= ctx.now <= mandate.valid.until


def compute_derived(proposal: ActionProposal, budget: BudgetState, ctx: EvalContext) -> Derived:
    mandate = ctx.mandate
    if mandate is None:
        mandate_state = MandateDerived(present=False, within=True)
    else:
        mandate_state = MandateDerived(
            present=True,
            within=mandate_validity(mandate, ctx) and within_mandate(proposal, mandate),
        )
    return Derived(
        blast_radius=blast_radius.score(proposal),
        budget=_budget_derived(budget, ctx, proposal.context.cost_estimate.money_cents),
        mandate=mandate_state,
        chain_depth=len(proposal.principal.agent_chain),
        history=ctx.history,
    )
