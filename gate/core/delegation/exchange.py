"""What a token exchange is allowed to grant (SPEC §6.2). Pure.

The endpoint in :mod:`gate.api.routers.token` does the HTTP and the signing;
this module answers the only question that matters for the audit: given who is
asking, what they asked for, and what their group may hold, what comes out.

Every answer here is a **minimum**, never a request granted as made. An
exchange that handed back what it was asked for would be an escalation path
that works by asking politely.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta

from gate.core.schemas import Budget

__all__ = ["Grant", "cap_budget", "grant_for", "scopes_for_groups"]

#: SPEC §6.2. Nothing the caller says can extend a token past this.
MAX_LIFETIME = timedelta(minutes=60)


@dataclass(frozen=True)
class Grant:
    """What the exchange decided to issue."""

    scope: list[str]
    budget: Budget
    lifetime: timedelta
    #: Scopes that were asked for and refused. Returned to the caller so a
    #: misconfigured agent fails loudly at the exchange rather than silently
    #: at the first action it cannot take.
    refused_scope: list[str]


def scopes_for_groups(groups: list[str], scopes_by_group: dict[str, list[str]]) -> frozenset[str]:
    """Union of what each group may hold. An unknown group contributes nothing."""
    allowed: set[str] = set()
    for group in groups:
        allowed.update(scopes_by_group.get(group, ()))
    return frozenset(allowed)


def cap_budget(requested: Budget, ceiling: Budget) -> Budget:
    """Per-axis minimum of ``requested`` and ``ceiling``.

    A cap of 0 means uncapped, which makes the arithmetic less obvious than it
    looks: an uncapped ceiling grants whatever was asked, an uncapped *request*
    under a capped ceiling takes the ceiling, and two caps take the smaller.
    """

    def axis(request: int, limit: int) -> int:
        if limit == 0:
            return request
        if request == 0:
            return limit
        return min(request, limit)

    return Budget(
        steps=axis(requested.steps, ceiling.steps),
        tokens=axis(requested.tokens, ceiling.tokens),
        seconds=axis(requested.seconds, ceiling.seconds),
        money_cents=axis(requested.money_cents, ceiling.money_cents),
        currency=ceiling.currency or requested.currency,
    )


def grant_for(
    *,
    requested_scope: list[str],
    groups: list[str],
    scopes_by_group: dict[str, list[str]],
    requested_budget: Budget,
    ceiling: Budget,
    requested_lifetime: timedelta,
    default_lifetime: timedelta,
    parent_expires_in: timedelta | None = None,
    mandate_expires_in: timedelta | None = None,
) -> Grant:
    """The whole of §6.2's granting logic.

    Lifetime is the smallest of: what was asked (or the default), the hour
    ceiling, what is left of the parent token, and what is left of the mandate.
    A token that outlived any of those would survive the thing that authorised
    it.
    """
    allowed = scopes_for_groups(groups, scopes_by_group)
    if scopes_by_group:
        granted = [s for s in requested_scope if s in allowed]
        refused = [s for s in requested_scope if s not in allowed]
    else:
        # No mapping configured means scope is not being used to restrict
        # anything yet. Refusing everything here would make the endpoint
        # unusable before an operator has written a mapping, and granting
        # everything is honest about what is actually enforced: nothing.
        granted, refused = list(requested_scope), []

    lifetime = requested_lifetime if requested_lifetime > timedelta(0) else default_lifetime
    bounds = [lifetime, MAX_LIFETIME]
    if parent_expires_in is not None:
        bounds.append(parent_expires_in)
    if mandate_expires_in is not None:
        bounds.append(mandate_expires_in)
    lifetime = min(bounds)

    return Grant(
        scope=granted,
        budget=cap_budget(requested_budget, ceiling),
        lifetime=max(lifetime, timedelta(0)),
        refused_scope=refused,
    )
