"""``GET /v1/status`` — the chain badge (SPEC §19 page 1, ADR-0007).

SPEC §19 requires every UI page to carry a "chain status badge (``seq``, last
checkpoint age, verify ok)", and SPEC §13's route table has no endpoint that
answers it. ``/readyz`` is deliberately open and says only whether the service
can decide; ``/v1/evidence/verify`` re-reads the chain, which is the wrong cost
for something a page polls. So this is the one route added beyond the table,
and ADR-0007 records why.

It is the same :func:`~qed.runtime.chain_status` the CLI prints, plus the
checkpoint age the badge needs, so the page and ``qed status`` cannot come to
different conclusions about the same instance.

**No verification is performed here.** The badge wants to know whether the
chain is intact, and this endpoint reports the *shape* of the chain rather than
an answer to that question. Re-verifying on every poll would be expensive and,
more to the point, a verdict this instance delivers about its own chain is
worth very little: the whole design is that an auditor runs ``qed-verify``
against an export, with the public key, trusting nothing here. The response
says so in a field rather than leaving the page to imply otherwise.
"""

from __future__ import annotations

from fastapi import APIRouter, Request
from starlette.responses import JSONResponse

from qed.api.app_state import authenticate_caller, qed_state
from qed.core.schemas import utcnow
from qed.runtime import chain_status

router = APIRouter(prefix="/v1", tags=["status"])


@router.get("/status")
async def status(request: Request) -> JSONResponse:
    """Posture for the UI badge. Readable by an adapter or a person."""
    caller = authenticate_caller(request, b"", now=utcnow())
    state = qed_state(request)
    session = state.require()

    payload = chain_status(session)
    checkpoint = session.store.last_checkpoint()
    now = utcnow()

    age: float | None = None
    if checkpoint is not None and checkpoint.evidence_seq is not None:
        record = session.store.evidence_at(checkpoint.evidence_seq)
        if record is not None:
            age = round((now - record.ts).total_seconds(), 3)

    payload["last_checkpoint_age_seconds"] = age
    # Not a verification result. See the module docstring: an instance
    # vouching for its own chain is worth very little, and the badge should
    # not be able to imply it has been checked when it has not.
    payload["verified"] = None
    payload["verify_with"] = "qed export | qed-verify --keys <public dir>"
    payload["caller"] = caller.describe()
    # SPEC 13's limits, and the number of refusals. Here rather than only in
    # `/metrics` because the thing an operator wants when a client reports 429s
    # is "which limit, and is it mine or the replica count" -- and `describe`
    # says the scope is this process only.
    limiter = state.limiter
    payload["rate_limit"] = limiter.describe() if limiter is not None else {"enabled": False}
    return JSONResponse(payload)
