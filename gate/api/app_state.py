"""Per-process API state and how a router reaches it.

In its own module so that routers can read the state without importing
``gate.api.app``, which imports them. The cycle is avoidable and a cycle broken
by a function-local import is a cycle waiting to come back.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from fastapi import Request

from gate.api.auth import AdapterAuth
from gate.api.problems import Problem
from gate.core.delegation.claims import TokenClaims, TokenVerificationError
from gate.core.schemas import Principal
from gate.infra.jwks import JwksCache, discover_jwks_uri
from gate.infra.tokens import GATE_ALG, TokenIssuer, decode_unverified_header, verify_token
from gate.runtime import Session

__all__ = ["GateState", "authenticate", "gate_state", "require_session"]


@dataclass
class GateState:
    """What the routers need. Set up once by the app's lifespan."""

    directory: Path
    dev: bool
    session: Session | None = None
    auth: AdapterAuth | None = None
    #: Present only when `delegation.issuers` is configured. `/v1/token`
    #: answers 501 without it rather than minting tokens nobody asked for.
    token_issuer: TokenIssuer | None = None
    jwks: JwksCache | None = None
    _jwks_uris: dict[str, str] = field(default_factory=dict, repr=False)
    #: Why the service is not ready, if it is not. Empty when it is.
    blockers: list[str] = field(default_factory=list)

    @property
    def ready(self) -> bool:
        return self.session is not None and not self.blockers

    def require(self) -> Session:
        """The session, or a 503 that names what is missing."""
        if self.session is None or self.blockers:
            raise Problem(
                status=503,
                code="not-ready",
                title="The service is not ready",
                detail="; ".join(self.blockers) or "the policy kernel is not initialised",
                extra={"blockers": list(self.blockers)},
            )
        return self.session

    def verify_subject_token(self, token: str, *, now: datetime) -> tuple[TokenClaims, Principal]:
        """Verify a subject token from any configured source (SPEC §6.1 step 1).

        The `kid` selects among the keys of a *configured* issuer; it never
        names a URL. A token able to point at its own key server would be a
        token that signs itself.
        """
        session = self.require()
        delegation = session.config.delegation
        header = decode_unverified_header(token)
        kid = header.get("kid")

        if self.token_issuer is not None and kid == self.token_issuer.kid:
            return verify_token(
                token,
                keys=self.token_issuer.key,
                now=now,
                issuers=frozenset({delegation.self_issuer}),
                algorithms=(GATE_ALG,),
            )

        if self.jwks is None or not delegation.issuers:
            raise TokenVerificationError(
                "no identity providers are configured, so only tokens this gate "
                "issued can be exchanged"
            )

        last: Exception | None = None
        for configured in delegation.issuers:
            uri = self._jwks_uri(configured)
            wanted = kid if isinstance(kid, str) else None
            keyset = self.jwks.get(configured.issuer, uri, kid=wanted)
            try:
                return verify_token(
                    token,
                    keys=keyset,
                    now=now,
                    issuers=frozenset({configured.issuer}),
                    algorithms=tuple(configured.algorithms),
                )
            except TokenVerificationError as exc:
                last = exc
        raise last or TokenVerificationError("no configured issuer accepted this token")

    def _jwks_uri(self, configured: object) -> str:
        issuer = str(configured.issuer)
        explicit = getattr(configured, "jwks_uri", None)
        if explicit:
            return str(explicit)
        if issuer not in self._jwks_uris:
            # Discovery is done once per process. An air-gapped install sets
            # `jwks_uri` explicitly and never reaches this branch.
            self._jwks_uris[issuer] = discover_jwks_uri(issuer)
        return self._jwks_uris[issuer]


def gate_state(request: Request) -> GateState:
    state = request.app.state.gate
    assert isinstance(state, GateState)  # set in create_app, before any request
    return state


def require_session(request: Request) -> Session:
    return gate_state(request).require()


def authenticate(request: Request, body: bytes) -> str:
    """Verify the adapter signature and return the adapter id.

    Shared by every ``/v1`` router so that there is one place where an endpoint
    could be left unauthenticated, and ``tests/api/test_auth.py`` asserts that
    every route under ``/v1`` rejects an unsigned request.
    """
    state = gate_state(request)
    if state.auth is None:
        raise Problem(
            status=503,
            code="not-ready",
            title="The service is not ready",
            detail="; ".join(state.blockers) or "adapter authentication is not initialised",
        )
    return state.auth.verify(
        method=request.method,
        path=request.url.path,
        headers={key.lower(): value for key, value in request.headers.items()},
        body=body,
    )
