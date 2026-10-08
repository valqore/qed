"""Per-process API state and how a router reaches it.

In its own module so that routers can read the state without importing
``gate.api.app``, which imports them. The cycle is avoidable and a cycle broken
by a function-local import is a cycle waiting to come back.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from fastapi import Request

from gate.api.auth import AdapterAuth
from gate.api.problems import Problem
from gate.runtime import Session

__all__ = ["GateState", "authenticate", "gate_state", "require_session"]


@dataclass
class GateState:
    """What the routers need. Set up once by the app's lifespan."""

    directory: Path
    dev: bool
    session: Session | None = None
    auth: AdapterAuth | None = None
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
