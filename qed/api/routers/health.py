"""``/healthz`` and ``/readyz`` (SPEC §13, SPEC §17).

The two answer different questions and must not be wired to the same check.

``/healthz`` -- is this process alive? Always 200 while it can serve. An
orchestrator restarts a container whose liveness probe fails, and restarting
will not conjure up a signing key, so a missing key must not fail here.

``/readyz`` -- can this process do its job? 503 with the reasons when it cannot.
SPEC §17 makes "no evidence signing key" one of those reasons: an unsigned
decision is not evidence. "No usable adapter authentication" is another, because
SPEC §17 also requires unknown adapters to be rejected and an instance that
cannot tell adapters apart cannot do that.
"""

from __future__ import annotations

from fastapi import APIRouter, Request
from starlette.responses import JSONResponse

from qed.api.app_state import qed_state
from qed.core.schemas import rfc3339_ms, utcnow

router = APIRouter(tags=["health"])


@router.get("/healthz", summary="Liveness. 200 while the process can serve.")
async def healthz() -> dict[str, object]:
    return {"status": "ok", "time": rfc3339_ms(utcnow())}


@router.get("/readyz", summary="Readiness. 503 with reasons when not ready.")
async def readyz(request: Request) -> JSONResponse:
    state = qed_state(request)
    body: dict[str, object] = {
        "ready": state.ready,
        "time": rfc3339_ms(utcnow()),
        "checks": {
            "signing_key": state.session is not None,
            "policy_bundle": state.session is not None,
            "adapter_auth": None if state.auth is None else state.auth.mode.kind,
        },
    }
    if state.session is not None:
        body["instance_id"] = state.session.config.instance_id
        body["key_id"] = state.session.signer.key_id
        body["policy_hash"] = state.session.bundle.hash
        body["mode"] = state.session.config.mode.value
        body["records"] = state.session.store.count_evidence()
    if state.dev:
        body["dev"] = True
    if not state.ready:
        body["blockers"] = list(state.blockers)
        return JSONResponse(body, status_code=503)
    return JSONResponse(body, status_code=200)
