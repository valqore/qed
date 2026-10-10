"""The FastAPI application (SPEC §13).

The app starts even when it cannot work. A missing signing key makes ``/readyz``
answer 503 with the reason, which is what SPEC §17 asks for and what a
readiness probe needs; a process that exited instead would come back as a crash
loop with the reason only in the logs.

Everything stateful lives on one :class:`~qed.api.app_state.QedState` attached
to ``app.state``. There is no module-level session, so two apps in one test
process -- a ready one and a key-less one -- do not share a chain.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI

from qed.api.app_state import QedState
from qed.api.auth import AdapterAuth
from qed.api.leader import LeaderLoop
from qed.api.problems import install_handlers
from qed.api.routers import (
    approvals,
    events,
    evidence,
    health,
    metrics,
    proposals,
    slack,
    status,
    token,
)
from qed.config import DEFAULT_DIR
from qed.core.ratelimit import Limiter
from qed.infra.channels.slack import SlackChannel
from qed.infra.jwks import JwksCache
from qed.infra.keys.file import MissingSigningKey
from qed.infra.siem import SiemShipper
from qed.infra.tokens import TokenIssuer, load_or_create_token_key
from qed.runtime import PolicyErrors, open_session
from qed.version import VERSION

__all__ = ["API_VERSION", "create_app"]

API_TITLE = "qed"
#: The OpenAPI document's version, which is the product's. `/v1` is the API
#: *path* and is versioned separately, by being in the path.
API_VERSION = VERSION


def create_app(
    *,
    directory: Path = DEFAULT_DIR,
    config_path: Path | None = None,
    policy_paths: list[Path] | None = None,
    dev: bool = False,
) -> FastAPI:
    """Build the app. Opens nothing until the lifespan runs."""
    state = QedState(directory=directory, dev=dev)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        try:
            state.session = open_session(
                directory=directory,
                policy_paths=policy_paths,
                config_path=config_path,
                dev=dev,
            )
        except MissingSigningKey as exc:
            # SPEC §17: no evidence signing key means readyz is false. A
            # decision that cannot be signed is not evidence, so answering
            # /v1/proposals here would produce verdicts nobody can verify.
            state.blockers.append(f"no evidence signing key: {exc}")
        except PolicyErrors as exc:
            state.blockers.extend(finding.format() for finding in exc.findings)
            state.blockers.append(
                "the policy bundle has errors; refusing to decide against a broken bundle"
            )
        else:
            # SPEC 13's rate limits. Built here rather than at import so an
            # unconfigured instance opens no buckets, and so two apps in one
            # process cannot share an allowance.
            limits = state.session.config.api.rate_limit
            state.limiter = Limiter(
                per_adapter_rps=limits.per_adapter_rps,
                per_principal_rps=limits.per_principal_rps,
            )
            state.auth = AdapterAuth(state.session.config, dev=dev)
            mode = state.auth.mode
            if not mode.usable:
                state.blockers.append(f"adapter authentication is unusable: {mode.reason}")
            # Delegation is optional. A deployment that never exchanges tokens
            # should not be made to hold a token key, and `/v1/token` answers
            # 501 rather than pretending the feature is off for some other
            # reason.
            delegation = state.session.config.delegation
            if delegation.issuers:
                state.token_issuer = TokenIssuer(
                    load_or_create_token_key(directory),
                    issuer=delegation.self_issuer,
                )
                state.jwks = JwksCache(
                    directory=directory / delegation.jwks_cache,
                    offline=delegation.offline,
                )
            bot_token = state.session.config.approvals.slack_bot_token()
            channel_name = state.session.config.approvals.slack.channel
            if bot_token and channel_name:
                state.slack = SlackChannel(bot_token=bot_token, channel=channel_name)
            # The chain's background loop: drains the outbox on the HA path,
            # and checkpoints, publishes and purges on both. It runs on its
            # own thread with its own session, because a `sqlite3` connection
            # belongs to the thread that made it and this one was made here.
            state.leader = LeaderLoop(
                state.session,
                own_session=lambda: open_session(
                    directory=directory,
                    policy_paths=policy_paths,
                    config_path=config_path,
                    dev=dev,
                    strict_policy=False,
                ),
            )
            state.leader.start()

            # OCSF events to a SIEM, if one is configured. A background thread
            # with a bounded queue: the chain is the record and this is a
            # copy, so nothing on the decision path waits for it.
            siem_config = state.session.config.observability.siem
            if siem_config.active:
                state.siem = SiemShipper(
                    instance_id=state.session.config.instance_id,
                    webhook=siem_config.resolved_webhook(),
                    to_stdout=siem_config.stdout,
                )
                state.siem.start()
        try:
            yield
        finally:
            if state.siem is not None:
                # Before the session closes, so a last drain still has
                # something to describe.
                await asyncio.to_thread(state.siem.stop)
                state.siem = None
            if state.leader is not None:
                await state.leader.stop()
                state.leader = None
            if state.session is not None:
                # The loop owns the draining, so closing must not start
                # another one -- a per-request or per-shutdown drain would
                # undo the point of deferring.
                state.session.close(settle_chain=False)
                state.session = None

    app = FastAPI(
        title=API_TITLE,
        version=API_VERSION,
        summary="Policy and evidence kernel for AI-agent actions.",
        lifespan=lifespan,
    )
    app.state.qed = state
    install_handlers(app)
    app.include_router(health.router)
    # Open, like the probes. A scraper is not an adapter and has no signing
    # secret, and a bearer token in every Prometheus config is the arrangement
    # that ends with monitoring switched off.
    app.include_router(metrics.router)
    app.include_router(proposals.router)
    app.include_router(evidence.router)
    app.include_router(approvals.router)
    app.include_router(events.router)
    app.include_router(slack.router)
    app.include_router(status.router)
    app.include_router(token.router)
    app.include_router(token.public_router)
    return app
