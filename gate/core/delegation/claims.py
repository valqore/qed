"""Token claims and the checks that run against them (SPEC §6.1).

Every function here is total and pure: given the same claims, the same parent
and the same ``now``, the answer is the same. That is what lets a token
decision be replayed from the chain months later, and it is why the clock
arrives as an argument rather than from :func:`utcnow`.

What this module does **not** do is verify a signature. Resolving ``kid`` to a
key needs either a JWKS fetch or the instance's own token key, and both are
I/O. :mod:`gate.infra.tokens` does that and then calls in here.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Literal

from pydantic import ConfigDict, Field

from gate.core.evidence.hashing import principal_hash
from gate.core.schemas import Budget, Environment, Frozen, Principal, Timestamp

__all__ = [
    "ChainTooDeep",
    "DelegationError",
    "NarrowingViolation",
    "TokenClaims",
    "TokenVerificationError",
    "flatten_actor_chain",
    "narrows_from",
    "principal_from",
    "require_mandate",
    "validate_claims",
    "verify",
]

#: SPEC §6.1 step 3. Four is deep enough for human -> agent -> sub-agent ->
#: tool and shallow enough that a runaway delegation loop is refused rather
#: than explored.
MAX_CHAIN_DEPTH = 4

#: SPEC §6.1 step 2. Applied in both directions: a token issued slightly in the
#: future by a clock that runs fast is accepted, a token that expired within the
#: window is not — expiry is the one bound that does not get the benefit of the
#: doubt.
DEFAULT_SKEW = timedelta(seconds=60)

#: SPEC §6.1 step 5. A subject with this prefix is a service identity, and a
#: service identity acting without a mandate is the unattended case the gate
#: exists to refuse.
SERVICE_PREFIX = "svc:"

AUDIENCE = "gate"


class DelegationError(Exception):
    """Base for every refusal in this module.

    Carries the rule id the refusal maps to so the caller can record it in the
    verdict without re-deriving which check failed.
    """

    rule_id = "AG-IDN-001"


class TokenVerificationError(DelegationError):
    """A claim is missing, malformed, or outside its window."""


class NarrowingViolation(DelegationError):
    """A child token asks for more than its parent holds (SPEC §6.1 step 4)."""

    rule_id = "AG-IDN-003"


class ChainTooDeep(DelegationError):
    rule_id = "AG-IDN-004"


class ActorClaim(Frozen):
    """One link of an RFC 8693 ``act`` chain."""

    sub: str
    act: ActorClaim | None = None


class TokenClaims(Frozen):
    """The claims the gate reads. Unknown claims are kept, not rejected.

    An IdP adds claims for its own reasons and a token that an IdP considers
    valid must not be refused because this software has not heard of a field.
    The claims that *are* read are all required, so a missing one is an error
    rather than a silent default.
    """

    iss: str
    sub: str
    aud: str | list[str]
    exp: Timestamp
    iat: Timestamp
    jti: str
    nbf: Timestamp | None = None
    act: ActorClaim | None = None
    scope: list[str] = Field(default_factory=list)
    budget: Budget = Budget()
    environments: list[Environment] = Field(default_factory=list)
    mandate_id: str | None = None
    parent_jti: str | None = None
    agent_id: str | None = None
    token_type: Literal["gate", "idp"] = "gate"

    model_config = ConfigDict(frozen=True, extra="allow")

    @property
    def is_service(self) -> bool:
        return self.sub.startswith(SERVICE_PREFIX)


def _audiences(aud: str | list[str]) -> list[str]:
    return [aud] if isinstance(aud, str) else list(aud)


def validate_claims(
    claims: TokenClaims,
    *,
    now: datetime,
    issuers: frozenset[str] | set[str] | list[str],
    skew: timedelta = DEFAULT_SKEW,
    audience: str = AUDIENCE,
) -> None:
    """SPEC §6.1 step 2. Raises on the first failure, returns None otherwise.

    The checks are ordered cheapest-and-most-damning first, so a token from an
    unknown issuer is refused before any effort goes into its time windows.
    """
    if claims.iss not in set(issuers):
        raise TokenVerificationError(
            f"issuer {claims.iss!r} is not configured; add it to `delegation.issuers`"
        )
    if audience not in _audiences(claims.aud):
        raise TokenVerificationError(
            f"token audience {claims.aud!r} does not include {audience!r}; "
            "a token minted for another service must not be usable here"
        )
    if claims.exp <= now - skew:
        raise TokenVerificationError(f"token expired at {claims.exp.isoformat()}")
    if claims.nbf is not None and claims.nbf > now + skew:
        raise TokenVerificationError(f"token is not valid before {claims.nbf.isoformat()}")
    if claims.iat > now + skew:
        raise TokenVerificationError(
            f"token was issued at {claims.iat.isoformat()}, which is further ahead "
            "than the allowed clock skew"
        )


def flatten_actor_chain(claims: TokenClaims, *, max_depth: int = MAX_CHAIN_DEPTH) -> list[str]:
    """``[subject, actor, actor-of-actor, ...]`` (SPEC §6.1 step 3).

    Outermost first: the subject is who the action is *for*, each ``act`` below
    it is who is acting on their behalf. A cycle presents as a chain that keeps
    going, so the depth bound catches it without a seen-set — at four links
    there is nothing a cycle can hide behind.
    """
    chain = [claims.sub]
    actor = claims.act
    while actor is not None:
        if len(chain) >= max_depth:
            raise ChainTooDeep(
                f"delegation chain is deeper than {max_depth} links; "
                "either the chain is looping or the delegation is too indirect to audit"
            )
        chain.append(actor.sub)
        actor = actor.act
    return chain


def _budget_within(child: Budget, parent: Budget) -> str | None:
    """The axis on which ``child`` exceeds ``parent``, or None.

    A cap of 0 means uncapped, so a parent of 0 permits anything and a child of
    0 under a capped parent is an *increase* — the one case where the obvious
    numeric comparison gives the wrong answer.
    """
    for axis in ("steps", "tokens", "seconds", "money_cents"):
        parent_cap = getattr(parent, axis)
        child_cap = getattr(child, axis)
        if parent_cap == 0:
            continue
        if child_cap == 0 or child_cap > parent_cap:
            return axis
    return None


def narrows_from(child: TokenClaims, parent: TokenClaims) -> None:
    """SPEC §6.1 step 4. A child may hold less than its parent, never more.

    Raises :class:`NarrowingViolation` naming the field that widened, because
    "the token was rejected" is not a message anyone can act on.
    """
    extra_scope = set(child.scope) - set(parent.scope)
    if parent.scope and extra_scope:
        raise NarrowingViolation(
            f"child token asks for scope {sorted(extra_scope)} that its parent does not hold"
        )
    axis = _budget_within(child.budget, parent.budget)
    if axis is not None:
        raise NarrowingViolation(
            f"child token asks for a larger {axis} budget than its parent holds"
        )
    if child.exp > parent.exp:
        raise NarrowingViolation(
            f"child token outlives its parent ({child.exp.isoformat()} > {parent.exp.isoformat()})"
        )
    extra_env = set(child.environments) - set(parent.environments)
    if parent.environments and extra_env:
        raise NarrowingViolation(
            f"child token asks for environments {sorted(extra_env)} that its parent does not hold"
        )


def principal_from(claims: TokenClaims, *, chain: list[str] | None = None) -> Principal:
    """Build the :class:`Principal` a proposal carries (SPEC §6.1 step 6).

    A human subject is hashed with the issuer so that two people with the same
    local username at different issuers are two principals. A service subject
    has no ``human_hash``: there is no person to attribute the action to, which
    is exactly why §6.1 step 5 insists on a mandate for that case, and why
    AG-IDN-007 blocks an unattended action that arrives without one.
    """
    links = chain if chain is not None else flatten_actor_chain(claims)
    return Principal(
        token_jti=claims.jti,
        human_hash=None if claims.is_service else principal_hash(claims.sub, issuer=claims.iss),
        agent_chain=links[1:],
        mandate_id=claims.mandate_id,
    )


def require_mandate(claims: TokenClaims) -> None:
    """SPEC §6.1 step 5. Unattended without a mandate is refused at the door.

    Leaving this to the policy engine would mean a service token with no
    mandate still minted a principal and still reached the rules. It is cheaper
    and clearer to refuse a token that cannot name who authorised it.
    """
    if claims.is_service and not claims.mandate_id:
        raise TokenVerificationError(
            f"subject {claims.sub!r} is a service identity and carries no mandate; "
            "an unattended agent must say who authorised it"
        )


def verify(
    claims: TokenClaims,
    *,
    now: datetime,
    issuers: frozenset[str] | set[str] | list[str],
    parent: TokenClaims | None = None,
    skew: timedelta = DEFAULT_SKEW,
    max_depth: int = MAX_CHAIN_DEPTH,
    audience: str = AUDIENCE,
) -> Principal:
    """All of §6.1 in the order the spec gives, returning the principal.

    Signature verification has already happened by the time this is called;
    what is left is everything that can be decided from the claims alone.
    """
    validate_claims(claims, now=now, issuers=issuers, skew=skew, audience=audience)
    chain = flatten_actor_chain(claims, max_depth=max_depth)
    if parent is not None:
        narrows_from(claims, parent)
    require_mandate(claims)
    return principal_from(claims, chain=chain)


ActorClaim.model_rebuild()
