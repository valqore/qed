"""``POST /slack/interactivity`` — a button click becomes a decision (SPEC §9.5).

Outside `/v1` because Slack cannot sign an adapter envelope. It authenticates
instead with Slack's own `X-Slack-Signature` over the exact bytes sent, which
is why the body is read raw and parsed afterwards.

The click carries a Slack user id, and a Slack user id is not an identity the
gate can act on: it says somebody with access to a workspace pressed a button.
It is resolved to an email through `users.info`, and that email is what
becomes the principal hash in the chain. If the lookup fails the decision is
refused rather than recorded against an unknown person.
"""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import parse_qs

from fastapi import APIRouter, Request
from starlette.responses import JSONResponse

from gate.api.app_state import gate_state
from gate.api.problems import Problem
from gate.api.slack_auth import SlackSignatureError, verify_slack_signature
from gate.core.approval.model import (
    DecisionKind,
    SoDViolation,
    decide,
    parse_duration,
)
from gate.core.evidence.hashing import principal_hash
from gate.core.schemas import Assurance, EvidenceType, utcnow
from gate.infra.channels.slack import SlackError

router = APIRouter(tags=["slack"])

_MAX_BODY_BYTES = 64 * 1024

#: The button a reviewer pressed maps to one of these and nothing else.
_ACTIONS = {
    "approve_once": (DecisionKind.approve_once, None),
    "approve_window": (DecisionKind.approve_window, "15m"),
    "deny": (DecisionKind.deny, None),
}


@router.post("/slack/interactivity")
async def interactivity(request: Request) -> JSONResponse:
    raw = await request.body()
    if len(raw) > _MAX_BODY_BYTES:
        raise Problem(
            status=413,
            code="body-too-large",
            title="The request body is too large",
            detail=f"this endpoint accepts at most {_MAX_BODY_BYTES} bytes",
        )

    state = gate_state(request)
    session = state.require()
    secret = session.config.approvals.slack_signing_secret_value()
    if not secret:
        raise Problem(
            status=501,
            code="slack-not-configured",
            title="Slack is not configured",
            detail=(
                "set `approvals.slack.signing_secret_env` before pointing Slack "
                "interactivity here; an unauthenticated decision endpoint is worse "
                "than no Slack integration"
            ),
        )

    try:
        verify_slack_signature(
            signing_secret=secret,
            timestamp=request.headers.get("x-slack-request-timestamp", ""),
            body=raw,
            signature=request.headers.get("x-slack-signature", ""),
        )
    except SlackSignatureError as exc:
        raise Problem(
            status=401,
            code="bad-slack-signature",
            title="The Slack signature did not verify",
            detail=str(exc),
        ) from exc

    payload = _payload(raw)
    action = (payload.get("actions") or [{}])[0]
    action_id = str(action.get("action_id", ""))
    if action_id not in _ACTIONS:
        raise Problem(
            status=400,
            code="unknown-action",
            title="Unknown button",
            detail=f"action_id must be one of {sorted(_ACTIONS)}",
        )
    approval_id = str(action.get("value") or "")
    kind, window_text = _ACTIONS[action_id]

    found = session.store.load_approval(approval_id)
    if found is None:
        return JSONResponse(
            {"replace_original": False, "text": f"No approval {approval_id} any more."}
        )

    slack_user = str((payload.get("user") or {}).get("id", ""))
    channel = state.slack
    if channel is None:
        raise Problem(
            status=501,
            code="slack-not-configured",
            title="Slack is not configured",
            detail="no bot token, so the clicker cannot be resolved to a person",
        )
    try:
        email = channel.email_for_user(slack_user)
    except SlackError as exc:
        # Refused rather than recorded against the Slack id. "U01ABCDEF
        # approved it" is not an answer to "who approved it".
        return JSONResponse(
            {
                "replace_original": False,
                "text": f":x: Could not identify you to the gate: {exc}",
            }
        )

    groups = session.config.approvals.groups_for(email)
    now = utcnow()
    try:
        decision = decide(
            found,
            kind=kind,
            approver_hash=principal_hash(email),
            approver_subject=email,
            approver_groups=groups,
            now=now,
            reason=str(payload.get("reason", "") or ""),
            requested_window=parse_duration(window_text),
        )
    except SoDViolation as violation:
        session.writer.append(
            type_=EvidenceType.approval_decided,
            assurance=Assurance.kernel,
            payload={
                "approval_id": approval_id,
                "refused": violation.rule_id,
                "detail": str(violation),
                "attempted_by_hash": principal_hash(email),
                "channel": "slack",
            },
            approval_id=approval_id,
            ts=now,
        )
        return JSONResponse(
            {"replace_original": False, "text": f":no_entry: {violation.rule_id}: {violation}"}
        )
    except ValueError as exc:
        return JSONResponse({"replace_original": False, "text": f":warning: {exc}"})

    if not session.store.apply_decision(decision):
        return JSONResponse({"replace_original": False, "text": "Somebody decided this one first."})
    if decision.window_until is not None:
        session.store.open_window(found.dedupe_key, found.id, decision.window_until)

    session.writer.append(
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
            "channel": "slack",
        },
        approval_id=approval_id,
        principal_hash=decision.approver_hash,
        ts=now,
    )
    return JSONResponse(
        {"replace_original": False, "text": f":white_check_mark: {decision.kind.value} by {email}"}
    )


def _payload(raw: bytes) -> dict[str, Any]:
    """Slack posts `payload=<urlencoded json>` as a form."""
    form = parse_qs(raw.decode("utf-8", errors="replace"))
    values = form.get("payload")
    if not values:
        raise Problem(
            status=400,
            code="no-payload",
            title="No Slack payload",
            detail="expected a form body with a `payload` field",
        )
    try:
        loaded = json.loads(values[0])
    except ValueError as exc:
        raise Problem(
            status=400,
            code="bad-payload",
            title="The Slack payload is not JSON",
            detail=str(exc),
        ) from exc
    if not isinstance(loaded, dict):
        raise Problem(
            status=400,
            code="bad-payload",
            title="The Slack payload is not an object",
            detail="expected a JSON object",
        )
    return loaded
