"""Per-process API state and how a router reaches it.

In its own module so that routers can read the state without importing
``qed.api.app``, which imports them. The cycle is avoidable and a cycle broken
by a function-local import is a cycle waiting to come back.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from fastapi import Request

from qed.api.auth import AdapterAuth
from qed.api.human_auth import Human, bearer_token, human_from_claims
from qed.api.leader import LeaderLoop
from qed.api.problems import Problem
from qed.config import IssuerConfig
from qed.core.delegation.claims import AUDIENCE, TokenClaims, TokenVerificationError
from qed.core.ratelimit import Limiter
from qed.core.schemas import Principal
from qed.infra.channels.slack import SlackChannel
from qed.infra.jwks import JwksCache, discover_jwks_uri
from qed.infra.metrics import MetricsRegistry
from qed.infra.siem import SiemShipper
from qed.infra.tokens import QED_ALG, TokenIssuer, decode_unverified_header, verify_token
from qed.runtime import Session

__all__ = [
    "Caller",
    "QedState",
    "authenticate",
    "authenticate_caller",
    "qed_state",
    "require_session",
]


@dataclass
class QedState:
    """What the routers need. Set up once by the app's lifespan."""

    directory: Path
    dev: bool
    session: Session | None = None
    auth: AdapterAuth | None = None
    #: Present only when `delegation.issuers` is configured. `/v1/token`
    #: answers 501 without it rather than minting tokens nobody asked for.
    token_issuer: TokenIssuer | None = None
    jwks: JwksCache | None = None
    #: Present only when a bot token is configured. Without it a button click
    #: cannot be resolved to a person, so the endpoint refuses rather than
    #: recording a Slack user id as the approver.
    slack: SlackChannel | None = None
    _jwks_uris: dict[str, str] = field(default_factory=dict, repr=False)
    #: The chain leader loop, on the deferred path. None on SQLite, where the
    #: decider chains its own records and there is nothing to elect.
    leader: LeaderLoop | None = None
    #: SPEC §13's rate limits. On the state for the same reason as `metrics`:
    #: a module global would make two instances in one process share buckets,
    #: and a test could not start from an empty one. None until the lifespan
    #: builds it, which also means an unconfigured instance opens no buckets.
    limiter: Limiter | None = None
    #: SPEC §18's metrics. On the state and not a module global, so a test can
    #: make a fresh one and two instances in one process do not share numbers.
    metrics: MetricsRegistry = field(default_factory=MetricsRegistry)
    #: Present only when `observability.siem` is configured. None means the
    #: records go nowhere but the chain, which is the default and is fine --
    #: a SIEM event is a copy.
    siem: SiemShipper | None = None
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

    @property
    def owned_audiences(self) -> frozenset[str]:
        """Every ``aud`` value a token for *this instance* may carry.

        ``qed`` is the service. Each configured ``ui_client_id`` is added
        because an **id_token's ``aud`` is the client id by OIDC definition**:
        the browser pages log in as a public PKCE client, so their token can
        never carry the service name, and refusing it would mean the pages
        could not sign anybody in. Found by pointing the page at a real
        Keycloak, which answered `aud: qed-cli` and was refused.

        The set is closed and comes from configuration, so the control the
        audience check exists for is intact: a token minted for a service
        nobody here declared is still refused.
        """
        session = self.session
        if session is None:
            return frozenset({AUDIENCE})
        return frozenset({AUDIENCE}) | {
            configured.ui_client_id
            for configured in session.config.delegation.issuers
            if configured.ui_client_id
        }

    def verify_subject_token(
        self, token: str, *, now: datetime
    ) -> tuple[TokenClaims, Principal, bool]:
        """Verify a subject token from any configured source (SPEC §6.1 step 1).

        Returns ``(claims, principal, qed_issued)``. The third value says which
        key verified the token, not what the token claims about itself.

        The `kid` selects among the keys of a *configured* issuer; it never
        names a URL. A token able to point at its own key server would be a
        token that signs itself.
        """
        session = self.require()
        delegation = session.config.delegation
        header = decode_unverified_header(token)
        kid = header.get("kid")

        if self.token_issuer is not None and kid == self.token_issuer.kid:
            # QED-issued, because *our key* verified it -- not because the
            # token said so. A token able to declare its own kind could ask to
            # be treated as its own parent, which is the same class of mistake
            # as reading `alg` out of the token.
            claims, principal = verify_token(
                token,
                keys=self.token_issuer.key,
                now=now,
                issuers=frozenset({delegation.self_issuer}),
                algorithms=(QED_ALG,),
                audience=self.owned_audiences,
            )
            return claims, principal, True

        if self.jwks is None or not delegation.issuers:
            raise TokenVerificationError(
                "no identity providers are configured, so only tokens this qed "
                "issued can be exchanged"
            )

        last: Exception | None = None
        for configured in delegation.issuers:
            uri = self._jwks_uri(configured)
            wanted = kid if isinstance(kid, str) else None
            keyset = self.jwks.get(configured.issuer, uri, kid=wanted)
            try:
                claims, principal = verify_token(
                    token,
                    keys=keyset,
                    now=now,
                    issuers=frozenset({configured.issuer}),
                    algorithms=tuple(configured.algorithms),
                    audience=self.owned_audiences,
                )
            except TokenVerificationError as exc:
                last = exc
            else:
                return claims, principal, False
        raise last or TokenVerificationError("no configured issuer accepted this token")

    def _jwks_uri(self, configured: IssuerConfig) -> str:
        issuer = configured.issuer
        if configured.jwks_uri:
            return configured.jwks_uri
        if issuer not in self._jwks_uris:
            # Discovery is done once per process. An air-gapped install sets
            # `jwks_uri` explicitly and never reaches this branch.
            self._jwks_uris[issuer] = discover_jwks_uri(issuer)
        return self._jwks_uris[issuer]


def qed_state(request: Request) -> QedState:
    state = request.app.state.qed
    assert isinstance(state, QedState)  # set in create_app, before any request
    return state


def require_session(request: Request) -> Session:
    return qed_state(request).require()


@dataclass(frozen=True)
class Caller:
    """Who is making this request: an adapter, or a person.

    Exactly one of the two is set. Routes that only adapters use keep calling
    :func:`authenticate`; routes a browser reaches call
    :func:`authenticate_caller` and read this.
    """

    adapter_id: str | None = None
    human: Human | None = None

    @property
    def is_human(self) -> bool:
        return self.human is not None

    def describe(self) -> str:
        """For the `client_fingerprint` field and for log lines. Advisory."""
        if self.human is not None:
            return f"oidc:{self.human.issuer}:{self.human.subject}"
        return f"adapter:{self.adapter_id}"


def enforce_rate_limit(
    request: Request, *, adapter: str | None, principal: str | None, now: float | None = None
) -> None:
    """Spend a token, or raise a 429 with `Retry-After` (SPEC §13).

    Called from the route rather than from middleware, for one reason that
    matters: the **principal** is inside the request body, so a middleware
    would have to parse the proposal to find it -- and then the route would
    parse it again, or the middleware would have to hand the parse forward. The
    adapter is known at authentication and the principal one line after the
    parse, which is where this sits.

    A refusal writes nothing to the chain. The attack this exists to stop is a
    caller flooding the API, and recording every refusal would let that caller
    flood the evidence chain instead -- the one thing that has to stay
    readable.
    """
    state = qed_state(request)
    limiter = state.limiter
    if limiter is None or not limiter.enabled:
        return
    verdict = limiter.check(
        adapter=adapter,
        principal=principal,
        now=time.monotonic() if now is None else now,
    )
    if verdict.allowed:
        return
    raise Problem(
        status=429,
        code="rate-limited",
        title="Too many proposals",
        detail=(
            f"the per-{verdict.scope} limit of {verdict.limit_rps:g}/s is spent for "
            f"{verdict.key}. This is a per-process limit, so an operator raising it "
            "should divide the number they want by their replica count "
            "(`api.rate_limit`, SPEC 13)."
        ),
        headers={"Retry-After": f"{verdict.retry_after:g}"},
        extra={"scope": verdict.scope, "retry_after_seconds": verdict.retry_after},
    )


def authenticate_caller(request: Request, body: bytes, *, now: datetime) -> Caller:
    """An adapter signature or a verified human bearer. One or the other.

    A request carrying neither is refused exactly as before, so the sweep in
    ``tests/api/test_auth.py`` that walks every ``/v1`` route and asserts an
    unsigned request cannot get a 2xx still holds: a bearer is a credential,
    not the absence of one.

    The bearer is tried first, and only when one is actually present. An
    adapter that also happens to send an ``Authorization`` header for its own
    reasons is not quietly reinterpreted as a person.
    """
    state = qed_state(request)
    headers = {key.lower(): value for key, value in request.headers.items()}

    token = bearer_token(headers)
    if token is not None:
        if state.jwks is None and state.token_issuer is None:
            raise Problem(
                status=501,
                code="no-human-auth",
                title="Human authentication is not configured",
                detail=(
                    "a bearer token arrived but no identity provider is configured under "
                    "`delegation.issuers`, so there is nothing to verify it against. "
                    "Adapters authenticate with a signature instead (SPEC §13)."
                ),
            )
        try:
            claims, _, _ = state.verify_subject_token(token, now=now)
        except TokenVerificationError as exc:
            # Same shape as the adapter refusal: a caller who cannot
            # authenticate does not get to learn which issuers exist.
            raise Problem(
                status=401,
                code="bad-token",
                title="The bearer token was not accepted",
                detail=str(exc),
                extra={"rule_id": "AG-IDN-005"},
            ) from exc
        return Caller(human=human_from_claims(claims, state.require().config))

    return Caller(adapter_id=authenticate(request, body))


def authenticate(request: Request, body: bytes) -> str:
    """Verify the adapter signature and return the adapter id.

    Shared by every ``/v1`` router so that there is one place where an endpoint
    could be left unauthenticated, and ``tests/api/test_auth.py`` asserts that
    every route under ``/v1`` rejects an unsigned request.
    """
    state = qed_state(request)
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
