"""``/v1/approvals`` (SPEC §9, §13).

The decision path is the same one ``qed approve`` uses: both call
:func:`qed.core.approval.model.decide`, then persist. A channel that made its
own decision would be a channel where separation of duties worked differently,
which is the one place a second implementation must not exist.

Approver identity comes from the caller, not from the body. An endpoint that
let the request say who was approving would make the whole control decorative
-- which is why the approver fields are read from the adapter envelope and
documented as such rather than accepted as JSON.
"""

from __future__ import annotations

import json
from typing import Any, Final

from fastapi import APIRouter, Request
from starlette.responses import JSONResponse

from qed.api.app_state import authenticate, qed_state
from qed.api.problems import Problem
from qed.core.approval.model import (
    ApprovalStatus,
    DecisionKind,
    SoDViolation,
    decide,
    parse_duration,
)
from qed.core.evidence.hashing import principal_hash
from qed.core.schemas import Assurance, EvidenceType, utcnow

router = APIRouter(prefix="/v1", tags=["approvals"])

_MAX_BODY_BYTES: Final = 8 * 1024

#: The approver's identity travels in headers rather than the body, so a
#: compromised agent cannot name its own approver by writing JSON.
HEADER_APPROVER: Final = "x-qed-approver"
HEADER_APPROVER_GROUPS: Final = "x-qed-approver-groups"


@router.get("/approvals")
async def list_approvals(request: Request) -> JSONResponse:
    authenticate(request, b"")
    session = qed_state(request).require()
    wanted = request.query_params.get("status")
    if wanted is not None and wanted not in {s.value for s in ApprovalStatus}:
        raise Problem(
            status=400,
            code="bad-status",
            title="Unknown status",
            detail=f"status must be one of {sorted(s.value for s in ApprovalStatus)}",
        )
    found = session.store.list_approvals(status=wanted)
    return JSONResponse({"approvals": [json.loads(r.model_dump_json()) for r in found]})


@router.get("/approvals/{approval_id}")
async def get_approval(approval_id: str, request: Request) -> JSONResponse:
    authenticate(request, b"")
    session = qed_state(request).require()
    found = session.store.load_approval(approval_id)
    if found is None:
        raise Problem(
            status=404,
            code="no-such-approval",
            title="No such approval",
            detail=f"there is no approval {approval_id}",
        )
    payload = json.loads(found.model_dump_json())
    # The approver view is what a person needs to judge the action; it was
    # stored at request time so it reflects the proposal as it was decided,
    # not as the record looks now.
    stored = session.store.approval_request_json(approval_id)
    if stored is not None:
        payload["request"] = json.loads(stored)
    return JSONResponse(payload)


@router.post("/approvals/{approval_id}")
async def decide_approval(approval_id: str, request: Request) -> JSONResponse:
    raw = await request.body()
    if len(raw) > _MAX_BODY_BYTES:
        raise Problem(
            status=413,
            code="body-too-large",
            title="The request body is too large",
            detail=f"this endpoint accepts at most {_MAX_BODY_BYTES} bytes",
        )
    authenticate(request, raw)
    session = qed_state(request).require()

    approver = request.headers.get(HEADER_APPROVER, "").strip()
    if not approver:
        raise Problem(
            status=400,
            code="no-approver",
            title="The approver is not identified",
            detail=(
                f"send the approver's subject in {HEADER_APPROVER}. It is a header "
                "and not a body field on purpose: an endpoint that let the request "
                "name its own approver would make separation of duties decorative."
            ),
        )
    groups = [
        g.strip() for g in request.headers.get(HEADER_APPROVER_GROUPS, "").split(",") if g.strip()
    ]

    body: dict[str, Any] = {}
    if raw.strip():
        try:
            loaded = json.loads(raw)
        except ValueError as exc:
            raise Problem(
                status=400,
                code="bad-json",
                title="The body is not valid JSON",
                detail=str(exc),
            ) from exc
        if isinstance(loaded, dict):
            body = loaded

    wanted = str(body.get("decision", "approve_once"))
    try:
        kind = DecisionKind(wanted)
    except ValueError as exc:
        raise Problem(
            status=400,
            code="bad-decision",
            title="Unknown decision",
            detail=f"decision must be one of {sorted(k.value for k in DecisionKind)}",
        ) from exc

    found = session.store.load_approval(approval_id)
    if found is None:
        raise Problem(
            status=404,
            code="no-such-approval",
            title="No such approval",
            detail=f"there is no approval {approval_id}",
        )

    minutes = body.get("window_minutes")
    window = parse_duration(f"{int(minutes)}m") if isinstance(minutes, int | float) else None
    now = utcnow()
    try:
        decision = decide(
            found,
            kind=kind,
            approver_hash=principal_hash(approver),
            approver_subject=approver,
            approver_groups=groups,
            now=now,
            reason=str(body.get("reason", "")),
            requested_window=window,
        )
    except SoDViolation as violation:
        # Written to the chain before the refusal is returned. An attempt to
        # approve one's own action is exactly what an investigation looks for,
        # and a refusal nobody recorded is indistinguishable from an attempt
        # nobody made.
        session.writer.append(
            type_=EvidenceType.approval_decided,
            assurance=Assurance.kernel,
            payload={
                "approval_id": approval_id,
                "refused": violation.rule_id,
                "detail": str(violation),
                "attempted_by_hash": principal_hash(approver),
            },
            approval_id=approval_id,
            ts=now,
        )
        raise Problem(
            status=403,
            code="separation-of-duties",
            title="The approval was refused",
            detail=str(violation),
            extra={"rule_id": violation.rule_id},
        ) from violation
    except ValueError as exc:
        raise Problem(
            status=409,
            code="not-decidable",
            title="This approval cannot be decided",
            detail=str(exc),
        ) from exc

    if not session.store.apply_decision(decision):
        # Two approvers clicked at the same moment; the UPDATE carries the
        # status check, so exactly one of them won.
        raise Problem(
            status=409,
            code="already-decided",
            title="Somebody decided first",
            detail=f"approval {approval_id} was decided by another approver",
        )
    if decision.window_until is not None:
        session.store.open_window(found.dedupe_key, found.id, decision.window_until)

    record = session.writer.append(
        type_=EvidenceType.approval_decided,
        assurance=Assurance.kernel,
        payload={
            "approval_id": approval_id,
            "decision": decision.kind.value,
            "approver_hash": decision.approver_hash,
            "reason": decision.reason,
            "window_until": (
                None if decision.window_until is None else decision.window_until.isoformat()
            ),
        },
        approval_id=approval_id,
        principal_hash=decision.approver_hash,
        ts=now,
    )
    return JSONResponse(
        {
            "approval_id": approval_id,
            "decision": decision.kind.value,
            "status": decision.status.value,
            "window_until": (
                None if decision.window_until is None else decision.window_until.isoformat()
            ),
            "evidence_seq": record.seq,
        }
    )
