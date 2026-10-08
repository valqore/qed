"""Budget arithmetic (SPEC §8). Pure: no storage, no clock of its own.

The ledger itself lives in :mod:`gate.infra.storage.sqlite`, which owns the
atomic read-modify-write. This module owns the two questions that decide what
that write should be, so both the SQLite path and the Postgres path in week 6
answer them the same way:

* what does one action cost on each axis, and
* did paying that cost cross a cap.

``BudgetState.exhausted`` (``gate.core.schemas``) answers "is this token spent
*now*", which the engine short-circuits on before any rule runs. The functions
here answer "would this charge spend it", which is a different question: the
first gates the action, the second decides whether a ``budget_exhausted``
record is owed after the action was already allowed through.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from gate.core.schemas import ActionProposal, BudgetState

__all__ = ["Charge", "apply_charge", "charge_for", "newly_exhausted"]


@dataclass(frozen=True)
class Charge:
    """What one action consumes. ``steps`` is always 1 — an action is a step."""

    steps: int = 1
    tokens: int = 0
    money_cents: int = 0
    #: False when the adapter could not estimate cost. Carried through so the
    #: caller can record that the money and token figures are a floor, not a
    #: measurement. AG-BUD-004 raises the same gap as a shadow hit at decision
    #: time; this flag is what makes it visible in the ledger too.
    cost_known: bool = True


def charge_for(proposal: ActionProposal) -> Charge:
    """The cost of one proposal, taken from the adapter's estimate.

    An adapter that cannot estimate reports ``known=False`` and zeroes, and
    SPEC §8 is explicit that this charges 0 rather than guessing. A guessed
    number in a ledger an auditor reads is worse than a zero next to a flag
    that says the adapter could not see.
    """
    est = proposal.context.cost_estimate
    return Charge(
        steps=1,
        tokens=max(est.tokens, 0),
        money_cents=max(est.money_cents, 0),
        cost_known=est.known,
    )


def apply_charge(state: BudgetState, charge: Charge, *, now: datetime) -> BudgetState:
    """``state`` plus ``charge``. Does not clamp at the cap.

    Usage is allowed to exceed its cap. The alternative — clamping — would make
    the ledger disagree with what was actually spent, and the overshoot is
    exactly what an operator needs to see when deciding whether the cap was set
    too low. The cap governs the *next* action, through
    :meth:`BudgetState.exhausted`.
    """
    return state.model_copy(
        update={
            "steps_used": state.steps_used + charge.steps,
            "tokens_used": state.tokens_used + charge.tokens,
            "money_used_cents": state.money_used_cents + charge.money_cents,
            "first_seen": state.first_seen if state.first_seen is not None else now,
        }
    )


def newly_exhausted(before: BudgetState, after: BudgetState, *, now: datetime) -> bool:
    """Did this charge push the token over a cap it was under?

    Edge that matters: a token whose only cap is ``seconds`` can become
    exhausted with no charge at all, simply by time passing. That case is not
    "newly exhausted by this charge" and is reported by the engine's
    short-circuit on the next action instead, so comparing the two states at
    the same ``now`` keeps the ``budget_exhausted`` record tied to a cause.
    """
    return after.exhausted(now) and not before.exhausted(now)
