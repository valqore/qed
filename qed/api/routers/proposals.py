"""``/v1/proposals`` (SPEC §13).

This router is deliberately thin. It authenticates the adapter, checks the input
limits, validates the body against :class:`~qed.core.schemas.ActionProposal`,
and hands it to ``qed.runtime.check_proposal``. Nothing else. SPEC §22's week 2
exit criterion is that ``POST /v1/proposals`` and ``qed check`` return the same
verdict for the same input, and they do because they are the same call.

The body is read as raw bytes rather than through a FastAPI model parameter for
two reasons: the adapter's HMAC is computed over the exact bytes sent, and the
64 KB limit from SPEC §17 has to be enforced before a 10 MB body is parsed.

One thread, one connection
--------------------------

Every handler here is ``async def``, so it runs on the event loop thread. The
SQLite connection belongs to the thread that opened it, and ``check_proposal``
contains no ``await``, so two concurrent requests cannot interleave inside it
and ``seq`` stays contiguous. A ``def`` handler would be run in a threadpool by
Starlette and would hit that connection from the wrong thread. Postgres with a
pool and a chain leader is week 6; until then this constraint is load-bearing
and ``tests/api/test_proposals.py`` has a concurrency test that would catch its
removal.
"""

from __future__ import annotations

import json
import time
from typing import Final

from fastapi import APIRouter, Request, Response
from pydantic import ValidationError
from starlette.responses import JSONResponse

from qed.adapters.common import MAX_PROPOSAL_BYTES
from qed.api.app_state import authenticate, qed_state
from qed.api.observe import record_decision
from qed.api.problems import Problem
from qed.core.schemas import (
    ActionProposal,
    Assurance,
    BudgetState,
    Decision,
    Enforcement,
    EvidenceType,
    Frozen,
    Mandate,
    rfc3339_ms,
)
from qed.runtime import DuplicateProposal, Session, check_proposal

router = APIRouter(prefix="/v1", tags=["proposals"])

#: Execution statuses an adapter may report (SPEC §13, `/result`).
_RESULT_STATUSES: Final[frozenset[str]] = frozenset(
    {"ok", "error", "skipped", "timeout", "deferred"}
)

_MAX_RESULT_BYTES: Final = 16 * 1024


class ProposalEnvelope(Frozen):
    """Optional context an adapter may send alongside the proposal.

    SPEC §13 takes a bare ``ActionProposal``. A caller that already knows the
    token's budget or holds the signed mandate may send them in an envelope
    instead, which is the same shape ``qed check --budget --mandate`` accepts.
    Budgets become server-side state in week 3; until then, whoever holds the
    token is the only one who knows.
    """

    proposal: ActionProposal
    budget: BudgetState | None = None
    mandate: Mandate | None = None


@router.post(
    "/proposals",
    summary="Submit an ActionProposal and get a verdict.",
    status_code=200,
)
async def post_proposal(request: Request) -> Response:
    state = qed_state(request)
    body = await _body(request, limit=MAX_PROPOSAL_BYTES)
    authenticate(request, body)
    session = state.require()

    envelope = _parse(body)
    proposal = envelope.proposal

    started = time.perf_counter()
    try:
        outcome = check_proposal(
            session, proposal, budget=envelope.budget, mandate=envelope.mandate
        )
    except DuplicateProposal as exc:
        # SPEC §17: a replayed proposal id is a 409. No evidence is written: the
        # first submission is already in the chain and a second record would
        # claim the same id was decided twice.
        raise Problem(
            status=409,
            code="duplicate-proposal",
            title="That proposal id has already been decided",
            detail=str(exc),
            extra={"proposal_id": proposal.id},
        ) from None

    # Measured around the decision only, not the request: SPEC §18's p95 target
    # is about what qed does, and including transport would make the number
    # depend on the client's network.
    record_decision(
        state.metrics,
        proposal=proposal,
        outcome=outcome,
        seconds=time.perf_counter() - started,
    )

    payload: dict[str, object] = {
        "verdict": outcome.verdict.model_dump(mode="json"),
        "enforced": outcome.enforced,
        "effective_decision": outcome.effective_decision.value,
        # SPEC §13. In the Postgres/HA path the records are queued and the
        # leader has not chained them yet, so the reference is the outbox id
        # and `GET /v1/evidence/by-ref/{id}` resolves it once it has. Writing
        # a sequence number here that did not exist yet would be the sort of
        # plausible lie an integration builds on.
        "evidence_ref": outcome.records[-1].ref,
        "evidence_seq": [record.seq for record in outcome.records],
        "evidence_pending": any(record.deferred for record in outcome.records),
        # SPEC §13's optional `approval?`. `null` and not an empty object when
        # there is none: there is no approval, rather than an approval with
        # nothing in it. When there is one, the adapter gets what it needs to
        # wait for it and what to show the person who has to act -- without a
        # second round trip to `GET /v1/approvals/{id}`, which is the call an
        # adapter would otherwise have to make before it could say anything
        # useful at all.
        "approval": _approval_summary(session, outcome.verdict.approval_id),
    }
    # SPEC §13: 202 for REQUIRE_APPROVAL. Only when it is actually being
    # enforced -- in shadow mode nothing is pending and the adapter proceeds.
    status = 202 if outcome.effective_decision is Decision.REQUIRE_APPROVAL else 200
    return JSONResponse(payload, status_code=status)


def _approval_summary(session: Session, approval_id: str | None) -> dict[str, object] | None:
    """What an adapter needs about a pending approval, or None.

    Deliberately a subset of `GET /v1/approvals/{id}`: no stored proposal view,
    because the adapter already has the proposal it just submitted, and no
    approver identities beyond the groups the rule named.
    """
    if approval_id is None:
        return None
    request = session.store.load_approval(approval_id)
    if request is None:  # pragma: no cover - written in the same transaction
        return None
    return {
        "approval_id": request.id,
        "status": request.status.value,
        "approvers": list(request.approvers),
        "expires_at": rfc3339_ms(request.expires_at),
        "poll": f"/v1/approvals/{request.id}",
    }


@router.get("/proposals/{proposal_id}", summary="Fetch a proposal and its verdict.")
async def get_proposal(proposal_id: str, request: Request) -> Response:
    state = qed_state(request)
    authenticate(request, b"")
    session = state.require()

    stored = session.store.get_proposal(proposal_id)
    if stored is None:
        raise Problem(
            status=404,
            code="not-found",
            title="No such proposal",
            detail=f"no proposal with id {proposal_id} has been decided by this instance",
        )
    proposal_json, verdict_json = stored
    # Returned as parsed JSON of the canonical bytes that were hashed, so the
    # caller sees exactly what was signed.
    return JSONResponse(
        {
            "proposal": json.loads(proposal_json),
            "verdict": json.loads(verdict_json),
        }
    )


@router.post(
    "/proposals/{proposal_id}/result",
    summary="Report what happened when the action ran.",
    status_code=201,
)
async def post_result(proposal_id: str, request: Request) -> Response:
    state = qed_state(request)
    body = await _body(request, limit=_MAX_RESULT_BYTES)
    adapter_id = authenticate(request, body)
    session = state.require()

    stored = session.store.get_proposal(proposal_id)
    if stored is None:
        raise Problem(
            status=404,
            code="not-found",
            title="No such proposal",
            detail=(
                f"no proposal with id {proposal_id} has been decided by this instance, so "
                "there is nothing for this result to attach to"
            ),
        )

    report = _parse_result(body)
    proposal = ActionProposal.model_validate(json.loads(stored[0]))

    # SPEC §13: "assurance from adapter enforcement" (ADR-007.1). An enforcing
    # adapter could not be bypassed without leaving a gap in the chain, so its
    # report is `adapter`. An advisory one -- a coding-agent hook the user can
    # switch off -- is the agent's own testimony, and `self` says so.
    assurance = (
        Assurance.adapter
        if proposal.context.enforcement is Enforcement.enforcing
        else Assurance.self_
    )
    record = session.writer.append(
        type_=EvidenceType.execution_result,
        assurance=assurance,
        payload={"proposal_id": proposal_id, "reported_by": adapter_id, **report},
        mode=session.config.mode,
        enforcement=proposal.context.enforcement,
        proposal_id=proposal_id,
        principal_hash=proposal.principal.human_hash,
    )
    return JSONResponse(
        {
            "recorded": True,
            "assurance": assurance.value,
            "evidence_ref": record.ref,
            "evidence_seq": record.seq,
            "evidence_pending": record.deferred,
        },
        status_code=201,
    )


# --------------------------------------------------------------------------
# Request handling
# --------------------------------------------------------------------------


async def _body(request: Request, *, limit: int) -> bytes:
    """Read the body, refusing anything over the SPEC §17 limit.

    ``Content-Length`` is checked first so an oversized body is refused before
    it is read, and the body is measured again afterwards because a chunked
    request has no declared length to check.
    """
    declared = request.headers.get("content-length")
    if declared is not None and declared.isdigit() and int(declared) > limit:
        raise _too_large(int(declared), limit)
    body = await request.body()
    if len(body) > limit:
        raise _too_large(len(body), limit)
    return body


def _too_large(size: int, limit: int) -> Problem:
    return Problem(
        status=413,
        code="payload-too-large",
        title="The request body is too large",
        detail=(
            f"{size} bytes; the limit is {limit} (SPEC 17). Trim params_redacted: the "
            "engine matches on it and an approver reads it, so it is a summary, not a copy."
        ),
    )


def _parse(body: bytes) -> ProposalEnvelope:
    """Accept either a bare ActionProposal or the envelope around one."""
    try:
        raw = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise Problem(
            status=400,
            code="bad-request",
            title="The request body could not be parsed",
            detail=f"expected UTF-8 JSON: {exc}",
        ) from None
    if not isinstance(raw, dict):
        raise Problem(
            status=400,
            code="bad-request",
            title="The request body could not be parsed",
            detail="expected a JSON object",
        )

    wrapped = "proposal" in raw
    try:
        if wrapped:
            return ProposalEnvelope.model_validate(raw)
        return ProposalEnvelope(proposal=ActionProposal.model_validate(raw))
    except ValidationError as exc:
        raise Problem(
            status=422,
            code="invalid-proposal",
            title="The proposal does not match the schema",
            detail=(
                "ActionProposal per SPEC 3.1. Unknown fields are rejected on purpose: a "
                "field QED does not understand is a field no rule can match."
            ),
            extra={"errors": _field_errors(exc)},
        ) from None


def _parse_result(body: bytes) -> dict[str, object]:
    """Validate an execution report by hand; it has four optional fields."""
    try:
        raw = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise Problem(
            status=400,
            code="bad-request",
            title="The request body could not be parsed",
            detail=f"expected UTF-8 JSON: {exc}",
        ) from None
    if not isinstance(raw, dict):
        raise Problem(
            status=400,
            code="bad-request",
            title="The request body could not be parsed",
            detail="expected a JSON object",
        )

    status = raw.get("status")
    if not isinstance(status, str) or status not in _RESULT_STATUSES:
        raise Problem(
            status=422,
            code="invalid-result",
            title="The execution report does not match the schema",
            detail=f"`status` must be one of {sorted(_RESULT_STATUSES)}",
        )

    report: dict[str, object] = {"status": status}
    http_status = raw.get("http_status")
    if isinstance(http_status, int) and not isinstance(http_status, bool):
        report["http_status"] = http_status
    error = raw.get("error")
    if isinstance(error, str) and error:
        report["error"] = error[:2048]
    # Not in SPEC §13's list, which predates two of the three adapters. The MCP
    # proxy and the HTTP proxy both record `duration_ms` when they write to the
    # chain directly, so an adapter reporting through the API could not and an
    # auditor would see the field on some execution_result rows and not others
    # for no reason a reader could explain. Still an allowlist: an adapter does
    # not get to put arbitrary keys in the chain.
    duration = raw.get("duration_ms")
    if isinstance(duration, int | float) and not isinstance(duration, bool) and duration >= 0:
        report["duration_ms"] = round(float(duration), 3)
    cost = raw.get("cost_actual")
    if isinstance(cost, dict):
        report["cost_actual"] = {
            key: value
            for key, value in cost.items()
            if isinstance(key, str) and isinstance(value, int | float | str)
        }
    return report


def _field_errors(exc: ValidationError) -> list[dict[str, object]]:
    """Field paths and messages only -- never the rejected input.

    A proposal body can carry the very secret ``AG-DAT-001`` exists to stop, and
    an error response is not masked on the way out the way an evidence payload is.
    """
    return [
        {"loc": [str(part) for part in error.get("loc", ())], "msg": str(error.get("msg", ""))}
        for error in exc.errors()
    ]
