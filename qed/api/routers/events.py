"""``GET /v1/events`` — server-sent events over the evidence chain (SPEC §13).

What this is for: a UI that shows decisions as they happen, and a SIEM that
wants them without polling. Both are readers of a record that already exists,
which is why this endpoint streams the chain rather than inventing a second
event bus. One chain, all event types, no exceptions (invariant §1.4.5) —
a feed assembled from somewhere else would be a feed that could disagree with
the evidence.

Polling the store rather than being pushed to. The writer is the decision
path, and making it notify subscribers would put a listener's slowness on the
hot path of a verdict. A reader that is half a second behind is fine; a
verdict that waits for a reader is not.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator

from fastapi import APIRouter, Request
from starlette.responses import StreamingResponse

from qed.api.app_state import authenticate, qed_state
from qed.api.problems import Problem
from qed.core.schemas import EvidenceRecord

router = APIRouter(prefix="/v1", tags=["events"])

#: How often the store is checked for new records. Fast enough that a UI feels
#: live, slow enough that an idle stream is not a busy loop.
POLL_SECONDS = 0.5

#: An idle stream still sends something, so a proxy in the middle does not
#: decide the connection is dead and close it.
HEARTBEAT_SECONDS = 15.0

#: Payload keys never sent to a stream. The chain holds what an approver saw,
#: already redacted, but a live feed goes to more screens than the queue does.
_DROP_KEYS = frozenset({"params_redacted", "proposal"})


def _event(record: EvidenceRecord) -> str:
    payload = dict(record.payload or {})
    for key in _DROP_KEYS:
        payload.pop(key, None)
    body = {
        "seq": record.seq,
        "ts": record.ts.isoformat(),
        "type": record.type.value,
        "assurance": record.assurance.value,
        "mode": None if record.mode is None else record.mode.value,
        "hash": record.hash,
        "payload": payload,
    }
    # `id:` lets a client reconnect with Last-Event-ID and resume from the
    # sequence number it already has, which is the whole reason the chain is
    # contiguous.
    return f"id: {record.seq}\nevent: {record.type.value}\ndata: {json.dumps(body)}\n\n"


@router.get("/events")
async def events(request: Request) -> StreamingResponse:
    authenticate(request, b"")
    state = qed_state(request)
    session = state.require()

    last = request.headers.get("last-event-id") or request.query_params.get("from")
    try:
        cursor = int(last) if last is not None else -1
    except ValueError as exc:
        raise Problem(
            status=400,
            code="bad-cursor",
            title="Bad resume point",
            detail="`from` and Last-Event-ID must be a sequence number",
        ) from exc

    async def stream() -> AsyncIterator[str]:
        nonlocal cursor
        idle = 0.0
        while True:
            if await request.is_disconnected():
                return
            records = list(session.store.iter_evidence(from_seq=cursor + 1))
            if records:
                idle = 0.0
                for record in records:
                    cursor = record.seq
                    yield _event(record)
            else:
                idle += POLL_SECONDS
                if idle >= HEARTBEAT_SECONDS:
                    idle = 0.0
                    yield ": keep-alive\n\n"
            await asyncio.sleep(POLL_SECONDS)

    return StreamingResponse(
        stream(),
        media_type="text/event-stream",
        headers={
            "cache-control": "no-store",
            # Nginx buffers event streams by default and the symptom is a feed
            # that arrives all at once, minutes late.
            "x-accel-buffering": "no",
        },
    )
