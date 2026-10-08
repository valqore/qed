"""The FastAPI application (SPEC §13).

The app starts even when it cannot work. A missing signing key makes ``/readyz``
answer 503 with the reason, which is what SPEC §17 asks for and what a
readiness probe needs; a process that exited instead would come back as a crash
loop with the reason only in the logs.

Everything stateful lives on one :class:`~gate.api.app_state.GateState` attached
to ``app.state``. There is no module-level session, so two apps in one test
process -- a ready one and a key-less one -- do not share a chain.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI

from gate.api.app_state import GateState
from gate.api.auth import AdapterAuth
from gate.api.problems import install_handlers
from gate.api.routers import evidence, health, proposals
from gate.config import DEFAULT_DIR
from gate.infra.keys.file import MissingSigningKey
from gate.runtime import PolicyErrors, open_session

__all__ = ["API_VERSION", "create_app"]

API_TITLE = "gate"
API_VERSION = "0.1.0"


def create_app(
    *,
    directory: Path = DEFAULT_DIR,
    config_path: Path | None = None,
    policy_paths: list[Path] | None = None,
    dev: bool = False,
) -> FastAPI:
    """Build the app. Opens nothing until the lifespan runs."""
    state = GateState(directory=directory, dev=dev)

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
            state.auth = AdapterAuth(state.session.config, dev=dev)
            mode = state.auth.mode
            if not mode.usable:
                state.blockers.append(f"adapter authentication is unusable: {mode.reason}")
        try:
            yield
        finally:
            if state.session is not None:
                state.session.close()
                state.session = None

    app = FastAPI(
        title=API_TITLE,
        version=API_VERSION,
        summary="Policy and evidence kernel for AI-agent actions.",
        lifespan=lifespan,
    )
    app.state.gate = state
    install_handlers(app)
    app.include_router(health.router)
    app.include_router(proposals.router)
    app.include_router(evidence.router)
    return app
