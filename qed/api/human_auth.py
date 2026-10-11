"""Human authentication on ``/v1`` (SPEC §13 auth, SPEC §19 SSO).

An adapter signs every request with the shared secret it was registered with
(:mod:`qed.api.auth`). A person in a browser cannot do that: the secret would
have to be in the page, where anyone who can open dev tools becomes every
adapter at once. So a human arrives on an ``Authorization: Bearer <jwt>`` from
one of the ``delegation.issuers`` already configured for token exchange, and it
is verified by the same :meth:`~qed.api.app_state.QedState.verify_subject_token`
the exchange uses. One verification path, not two — a second JWT reader is a
second place for the `alg`/`kid` mistakes to live.

Why this matters more than the page it unlocks
----------------------------------------------

Until now the approver's identity travelled in ``X-QED-Approver``, a header the
*adapter* writes. The approvals router says so plainly and the header is honest
about being an assertion — but separation of duties checked against an
assertion is separation of duties the caller gets to choose. Declaring an SoD
control in an OSCAL export while enforcing nothing is the worst outcome
available here -- it hands an auditor a control that does not exist -- and an
adapter-asserted approver is a smaller version of the same problem: the chain
records who the adapter *said* approved.

With a verified bearer the subject comes from the identity provider, so
``AG-SOD-001`` (the approver is not the principal) and ``AG-SOD-002`` (a
person, in the group the rule named) are decided on evidence.

So for a bearer caller ``X-QED-Approver`` is **not read**, and a request that
sends one disagreeing with its token is refused rather than resolved. There is
no innocent reason to present two different approvers in one request.

What is deliberately not here
-----------------------------

**No session, no cookie, no redirect.** The browser gets its token from the
IdP and sends it; QED never holds one. A login endpoint would make this service
an OAuth client with a client secret to store and a callback to protect, which
is a bigger attack surface than the page is worth.

**No scope check.** Reading a pending approval and deciding it are both gated
on the group the *rule* named, which `check_separation_of_duties` already
enforces against the groups below. A second scope vocabulary would be a second
answer to "may this person approve this", and they would disagree eventually.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from qed.api.problems import Problem
from qed.config import QedConfig
from qed.core.delegation.claims import TokenClaims
from qed.core.evidence.hashing import principal_hash

__all__ = [
    "HEADER_AUTHORIZATION",
    "Human",
    "bearer_token",
    "human_from_claims",
]

HEADER_AUTHORIZATION: Final = "authorization"

#: Claims an IdP might put an address in, best first. Keycloak sends `email`
#: when the client has the `email` scope and `preferred_username` always;
#: Entra sends `preferred_username` and sometimes `upn`.
_EMAIL_CLAIMS: Final = ("email", "preferred_username", "upn")

#: Claims an IdP might put group membership in. Keycloak's group mapper writes
#: `groups`; Entra writes `groups` (object ids) and `roles`.
_GROUP_CLAIMS: Final = ("groups", "roles")


@dataclass(frozen=True)
class Human:
    """A person, as the identity provider describes them.

    ``principal_hash`` is built with the same function the chain uses for every
    other principal, so the hash that records an approval is comparable with
    the hash that recorded the proposal — which is the whole mechanism behind
    ``AG-SOD-001``.
    """

    subject: str
    issuer: str
    email: str
    groups: list[str]
    principal_hash: str


def bearer_token(headers: dict[str, str]) -> str | None:
    """The bearer token, or None when the caller is not presenting one.

    None means "not a human bearer request", not "refused": the caller may be
    an adapter with a signature, and deciding that is the caller's business
    rather than this function's.
    """
    raw = headers.get(HEADER_AUTHORIZATION, "").strip()
    if not raw:
        return None
    scheme, _, rest = raw.partition(" ")
    if scheme.lower() != "bearer":
        return None
    token = rest.strip()
    return token or None


def human_from_claims(claims: TokenClaims, config: QedConfig) -> Human:
    """Turn verified claims into the person the approval service will record.

    A service identity is refused here rather than at the SoD check. Both
    would refuse it — ``AG-SOD-002`` exists for exactly this — but a service
    account presenting a token to the approval UI is a misconfiguration, not a
    policy decision, and saying so in the right words saves somebody an hour.
    """
    if claims.is_service:
        raise Problem(
            status=403,
            code="service-identity",
            title="A service identity cannot approve",
            detail=(
                f"{claims.sub} is a service subject. An approval has to be an act of a "
                "person (SPEC §9.3, AG-SOD-002); give the approver their own login."
            ),
        )

    extra = claims.model_extra or {}
    email = ""
    for name in _EMAIL_CLAIMS:
        value = extra.get(name)
        if isinstance(value, str) and "@" in value:
            email = value
            break

    # Both sources are deliberate grants: the claim is what the IdP asserts,
    # the config map is what the operator wrote down. Union, so that an
    # installation whose IdP has no group mapper yet still works -- which is
    # the state every installation starts in. Requiring the claim alone would
    # be stricter and would lock out exactly those installations, so it stays a
    # union until somebody asks for the stricter mode and can switch it on.
    groups = {g for name in _GROUP_CLAIMS for g in _claim_list(extra.get(name))}
    groups.update(config.approvals.groups_for(email) if email else [])

    return Human(
        subject=claims.sub,
        issuer=claims.iss,
        email=email,
        groups=sorted(groups),
        principal_hash=principal_hash(claims.sub, issuer=claims.iss),
    )


def _claim_list(value: object) -> list[str]:
    """A group claim, which arrives as a list, a space-delimited string, or not.

    Keycloak writes a list. Some mappers write a single string. Neither is
    worth refusing a token over, and a type nobody expected is read as "no
    groups" rather than as an error -- the SoD check below will refuse the
    approval anyway, with a message about the group the rule wanted.
    """
    if isinstance(value, list):
        return [item for item in value if isinstance(item, str) and item.strip()]
    if isinstance(value, str):
        return [part for part in value.split() if part]
    return []
