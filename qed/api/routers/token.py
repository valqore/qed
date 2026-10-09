"""``POST /v1/token`` — RFC 8693 token exchange (SPEC §6.2).

An IdP token (or an existing qed token) goes in; a narrower, budgeted qed
token comes out. The exchange never grants what it was asked for: every field
is the minimum of the request and what the caller's group may hold, because an
endpoint that honoured requests would be an escalation path that works by
asking.

Why this endpoint is adapter-authenticated like every other ``/v1`` route: the
subject token proves who the *user* is, not which deployment is asking on their
behalf. Both matter. A stolen IdP token should not be exchangeable from
anywhere on the internet.
"""

from __future__ import annotations

import json
from datetime import timedelta
from typing import Any

from fastapi import APIRouter, Request
from starlette.responses import JSONResponse
from ulid import ULID

from qed.api.app_state import authenticate, qed_state
from qed.api.problems import Problem
from qed.core.delegation.claims import DelegationError, TokenClaims
from qed.core.delegation.exchange import grant_for
from qed.core.schemas import Assurance, Budget, EvidenceType, utcnow
from qed.infra.jwks import JwksError

router = APIRouter(prefix="/v1", tags=["token"])

#: The public-key endpoint lives outside `/v1` on purpose. Every `/v1` route
#: refuses an unsigned request and `tests/api/test_auth.py` asserts it with no
#: exemption list; a JWKS document is a public key that anyone holding a token
#: this qed issued must be able to fetch without first holding an adapter
#: credential. `/.well-known/jwks.json` is also where every other
#: implementation looks for it.
public_router = APIRouter(tags=["token"])

GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange"
JWT_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:jwt"

_MAX_BODY_BYTES = 16 * 1024


def _oauth_error(code: str, detail: str, *, status: int = 400) -> Problem:
    """RFC 6749 §5.2 shape, carried inside the problem document.

    Clients of a token endpoint look for `error`; everything else here speaks
    problem+json. Both are emitted rather than picking a side, because a
    generic OAuth client and our own CLI read different fields.
    """
    return Problem(
        status=status,
        code=code,
        title="The token exchange was refused",
        detail=detail,
        extra={"error": code, "error_description": detail},
    )


def _parse_body(raw: bytes) -> dict[str, Any]:
    """Accept JSON or form encoding; RFC 8693 is a form, our CLI sends JSON."""
    text = raw.decode("utf-8", errors="replace").strip()
    if text.startswith("{"):
        try:
            loaded = json.loads(text)
        except ValueError as exc:
            raise _oauth_error("invalid_request", f"body is not valid JSON: {exc}") from exc
        if not isinstance(loaded, dict):
            raise _oauth_error("invalid_request", "body must be a JSON object")
        return loaded
    from urllib.parse import parse_qsl

    return dict(parse_qsl(text))


def _as_budget(value: Any) -> Budget:
    if value is None:
        return Budget()
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError as exc:
            raise _oauth_error("invalid_request", "budget is not valid JSON") from exc
    try:
        return Budget.model_validate(value)
    except ValueError as exc:
        raise _oauth_error("invalid_request", f"budget is not well formed: {exc}") from exc


def _scope_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [s for s in value.split() if s]
    if isinstance(value, list):
        return [str(s) for s in value]
    raise _oauth_error("invalid_request", "scope must be a string or a list")


@router.post("/token")
async def exchange(request: Request) -> JSONResponse:
    raw = await request.body()
    if len(raw) > _MAX_BODY_BYTES:
        raise Problem(
            status=413,
            code="body-too-large",
            title="The request body is too large",
            detail=f"the token endpoint accepts at most {_MAX_BODY_BYTES} bytes",
        )
    authenticate(request, raw)

    state = qed_state(request)
    session = state.require()
    delegation = session.config.delegation
    if state.token_issuer is None:
        raise Problem(
            status=501,
            code="delegation-not-configured",
            title="Token exchange is not configured",
            detail=(
                "no identity providers are configured under `delegation.issuers`, "
                "so there is nothing to exchange a token from"
            ),
        )

    body = _parse_body(raw)
    if body.get("grant_type") != GRANT_TYPE:
        raise _oauth_error("unsupported_grant_type", f"grant_type must be {GRANT_TYPE}")
    requested_type = body.get("requested_token_type", JWT_TOKEN_TYPE)
    if requested_type != JWT_TOKEN_TYPE:
        raise _oauth_error("invalid_request", f"requested_token_type must be {JWT_TOKEN_TYPE}")
    subject_token = body.get("subject_token")
    if not isinstance(subject_token, str) or not subject_token:
        raise _oauth_error("invalid_request", "subject_token is required")

    now = utcnow()
    try:
        claims, principal, qed_issued = state.verify_subject_token(subject_token, now=now)
    except JwksError as exc:
        # The identity provider is unreachable and nothing is cached. That is
        # an upstream failure, not a bad request, and the distinction decides
        # whether a caller retries.
        raise Problem(
            status=503,
            code="issuer-unavailable",
            title="The identity provider could not be reached",
            detail=str(exc),
        ) from exc
    except DelegationError as exc:
        raise _oauth_error("invalid_grant", str(exc), status=401) from exc

    groups = _claim_list(claims, "groups")
    ceiling = _ceiling_for(delegation.budget_caps, groups)
    requested_seconds = _positive_int(body.get("expires_in"))
    granted = grant_for(
        requested_scope=_scope_list(body.get("scope")),
        groups=groups,
        scopes_by_group=_scopes_by_group(delegation),
        requested_budget=_as_budget(body.get("budget")),
        ceiling=ceiling,
        requested_lifetime=timedelta(seconds=requested_seconds),
        default_lifetime=timedelta(seconds=delegation.token_ttl_default_seconds),
        parent_expires_in=claims.exp - now if qed_issued else None,
    )
    if granted.lifetime <= timedelta(0):
        raise _oauth_error(
            "invalid_grant",
            "the subject token has too little life left to issue anything from",
            status=401,
        )

    jti = str(ULID())
    issuer = state.token_issuer
    try:
        token, minted = issuer.mint(
            subject=claims.sub,
            jti=jti,
            now=now,
            lifetime=granted.lifetime,
            scope=granted.scope,
            budget=granted.budget,
            environments=[str(e) for e in claims.environments] or None,
            agent_id=_string(body.get("agent_id")),
            mandate_id=_string(body.get("mandate_id")) or claims.mandate_id,
            parent=claims if qed_issued else None,
            actor=_string(body.get("agent_id")),
        )
    except DelegationError as exc:
        # Narrowing is enforced at mint time as well as here, and a violation
        # is the caller asking for more than the subject token holds -- a bad
        # request, not a server fault.
        raise _oauth_error("invalid_scope", str(exc)) from exc

    # The caps go into the ledger before the token is handed out: a token whose
    # budget was never recorded would be treated as uncapped by the first
    # action that used it (SPEC §8).
    session.store.upsert_budget_caps(jti, granted.budget)

    session.writer.append(
        type_=EvidenceType.budget_update,
        assurance=Assurance.kernel,
        payload={
            "type": "token_issued",
            "token_jti": jti,
            "subject_hash": principal.human_hash,
            "agent_chain": principal.agent_chain,
            "scope": granted.scope,
            "refused_scope": granted.refused_scope,
            "budget": granted.budget.model_dump(mode="json"),
            "expires_at": minted.exp.isoformat(),
            "parent_jti": claims.jti if qed_issued else None,
            "mandate_id": minted.mandate_id,
        },
        mode=session.config.mode,
        principal_hash=principal.human_hash,
        ts=now,
    )

    payload: dict[str, Any] = {
        "access_token": token,
        "issued_token_type": JWT_TOKEN_TYPE,
        "token_type": "Bearer",
        "expires_in": int((minted.exp - now).total_seconds()),
        "scope": " ".join(granted.scope),
    }
    if granted.refused_scope:
        payload["refused_scope"] = " ".join(granted.refused_scope)
    return JSONResponse(payload, status_code=200)


@public_router.get("/.well-known/jwks.json")
async def jwks(request: Request) -> JSONResponse:
    """This instance's token-verification key, for verifying tokens it issued."""
    state = qed_state(request)
    if state.token_issuer is None:
        return JSONResponse({"keys": []})
    return JSONResponse({"keys": [state.token_issuer.public_jwk()]})


def _claim_list(claims: TokenClaims, name: str) -> list[str]:
    value = getattr(claims, name, None)
    if isinstance(value, list):
        return [str(v) for v in value]
    if isinstance(value, str):
        return [value]
    return []


def _scopes_by_group(delegation: Any) -> dict[str, list[str]]:
    merged: dict[str, list[str]] = {}
    for configured in delegation.issuers:
        for group, scopes in configured.scopes_by_group.items():
            merged.setdefault(group, []).extend(scopes)
    return merged


def _ceiling_for(caps: dict[str, Budget], groups: list[str]) -> Budget:
    """The most generous cap among the caller's groups.

    Taking the maximum rather than the minimum is deliberate: belonging to an
    additional group is meant to grant more, and an operator who wants a hard
    limit sets it on every group rather than relying on membership arithmetic.
    """
    if not caps:
        return Budget()
    mine = [caps[g] for g in groups if g in caps]
    if not mine:
        return caps.get("*", Budget(steps=1))
    return Budget(
        steps=max(b.steps for b in mine),
        tokens=max(b.tokens for b in mine),
        seconds=max(b.seconds for b in mine),
        money_cents=max(b.money_cents for b in mine),
        currency=mine[0].currency,
    )


def _positive_int(value: Any) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return 0
    return max(number, 0)


def _string(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None
