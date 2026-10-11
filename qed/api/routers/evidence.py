"""``/v1/evidence`` (SPEC §13, SPEC §10.8).

Three formats. ``jsonl`` is the one ``qed-verify`` reads and the one an auditor
archives; ``csv`` is for a spreadsheet; ``oscal`` is the OSCAL 1.1.2
``assessment-results`` document.

A filtered export is not a verifiable one, and the response says so out loud.
``qed-verify`` checks that sequence numbers are contiguous and that each record
links to the previous hash, which a ``?type=verdict`` export cannot satisfy.
Rather than silently handing back something that will fail verification, the
response carries ``X-QED-Verifiable: false`` and the reason, and the ``oscal``
format refuses the combination outright -- an OSCAL document is what goes to an
auditor, and one assembled from a filtered subset would misstate what was
observed in the period it claims to cover.
"""

from __future__ import annotations

from typing import Annotated, Final

from fastapi import APIRouter, Query, Request, Response
from starlette.responses import JSONResponse, PlainTextResponse

from qed.api.app_state import authenticate, qed_state
from qed.api.problems import Problem
from qed.core.evidence.export.jsonl import to_csv, to_jsonl
from qed.core.evidence.export.oscal import to_oscal
from qed.core.schemas import EvidenceRecord, EvidenceType, utcnow

router = APIRouter(prefix="/v1", tags=["evidence"])

_FORMATS: Final[frozenset[str]] = frozenset({"jsonl", "csv", "oscal"})

#: Records per request. An auditor exporting a year of chain pages through with
#: ``from``; an unbounded export would hold the whole chain in memory to build
#: one response body. Streaming is not implemented, on either store.
MAX_RECORDS: Final = 50_000


@router.get("/evidence", summary="Export evidence as JSONL, CSV or OSCAL.")
async def get_evidence(
    request: Request,
    from_seq: Annotated[int, Query(alias="from", ge=0)] = 0,
    to_seq: Annotated[int | None, Query(alias="to", ge=0)] = None,
    export_format: Annotated[str, Query(alias="format")] = "jsonl",
    types: Annotated[list[str] | None, Query(alias="type")] = None,
) -> Response:
    state = qed_state(request)
    authenticate(request, b"")
    session = state.require()

    if export_format not in _FORMATS:
        raise Problem(
            status=400,
            code="bad-request",
            title="Unknown export format",
            detail=f"`format` must be one of {sorted(_FORMATS)}",
        )
    wanted = _validate_types(types)
    if wanted and export_format == "oscal":
        raise Problem(
            status=400,
            code="filtered-oscal-export",
            title="An OSCAL export cannot be filtered by record type",
            detail=(
                "An assessment-results document states what was observed over a period. "
                "Built from a subset it would omit observations without saying so. Export "
                "a sequence range instead, with `from` and `to`."
            ),
        )

    records = list(session.store.iter_evidence(from_seq, to_seq, types=wanted))
    if len(records) > MAX_RECORDS:
        raise Problem(
            status=413,
            code="range-too-large",
            title="That range holds too many records",
            detail=(
                f"{len(records)} records; the limit per request is {MAX_RECORDS}. Page with "
                "`from` and `to`."
            ),
        )

    contiguous = _is_contiguous(records)
    headers = {
        "X-QED-Verifiable": "true" if contiguous else "false",
        "X-QED-Records": str(len(records)),
    }
    if not contiguous:
        headers["X-QED-Not-Verifiable-Reason"] = (
            "sequence numbers are not contiguous in this response; qed-verify needs an "
            "unfiltered range"
        )

    if export_format == "jsonl":
        return PlainTextResponse(
            to_jsonl(records), media_type="application/x-ndjson", headers=headers
        )
    if export_format == "csv":
        return PlainTextResponse(to_csv(records), media_type="text/csv", headers=headers)

    if not records:
        raise Problem(
            status=404,
            code="empty-range",
            title="There is nothing to export",
            detail=(
                "An OSCAL assessment-results document needs at least one observation, and "
                "this range holds no records."
            ),
        )
    document = to_oscal(
        records,
        instance_id=session.config.instance_id,
        generated_at=utcnow(),
        signing_keys=session.store.signing_keys(),
        policy_hash=session.bundle.hash,
    )
    return JSONResponse(document, media_type="application/json", headers=headers)


@router.get(
    "/evidence/by-ref/{ref}",
    summary="Resolve an evidence_ref returned by POST /v1/proposals.",
)
async def get_by_ref(ref: str, request: Request) -> Response:
    """Resolve a reference to the record it names.

    SPEC §10.3 defines ``evidence_ref`` as an outbox id for the Postgres path,
    where a decision is answered before the chain row exists. The SQLite path
    appends inside the decision, so there is no outbox and the ref *is* the
    sequence number. One endpoint covers both, so an adapter written against it
    needs no change when an installation moves to Postgres.
    """
    state = qed_state(request)
    authenticate(request, b"")
    session = state.require()

    # Two shapes of reference, because there are two write paths (SPEC §10.3).
    # Direct: the reference *is* the sequence number. Deferred: it is the
    # outbox id the API handed back before the leader had chained anything,
    # and resolving it is this endpoint's reason for existing.
    if ref.isdigit():
        record = session.store.evidence_at(int(ref))
        if record is None:
            raise Problem(
                status=404,
                code="not-found",
                title="No such evidence record",
                detail=f"this chain has no record at seq {ref}",
            )
        return JSONResponse(
            {"seq": record.seq, "pending": False, "record": record.model_dump(mode="json")}
        )

    seq = session.store.resolve_outbox_ref(ref)
    if seq is not None:
        record = session.store.evidence_at(seq)
        return JSONResponse(
            {
                "seq": seq,
                "pending": False,
                "record": None if record is None else record.model_dump(mode="json"),
            }
        )

    if session.store.outbox_pending(ref):
        # 200 and not 404: the record exists and is durable, the leader has
        # simply not chained it yet. A 404 here would tell a caller their
        # evidence was lost, which is the opposite of true, and an integration
        # that retried on 404 would give up on a record that was about to
        # arrive.
        return JSONResponse(
            {
                "seq": None,
                "pending": True,
                "record": None,
                "detail": (
                    "queued and durable; the chain leader has not assigned a sequence "
                    "number yet. Poll this reference, or watch "
                    "`chain_lag_records` in GET /v1/status."
                ),
            },
            status_code=200,
        )

    raise Problem(
        status=404,
        code="not-found",
        title="No such evidence reference",
        detail=(
            f"{ref!r} is neither a sequence number, nor a queued outbox id, nor one this "
            "instance has chained. A reference from a different instance will not resolve "
            "here."
        ),
    )


def _validate_types(types: list[str] | None) -> list[str] | None:
    if not types:
        return None
    known = {member.value for member in EvidenceType}
    unknown = sorted(set(types) - known)
    if unknown:
        raise Problem(
            status=400,
            code="bad-request",
            title="Unknown evidence type",
            detail=f"{unknown} is not an evidence type; see SPEC 3.5",
            extra={"known_types": sorted(known)},
        )
    return sorted(set(types))


def _is_contiguous(records: list[EvidenceRecord]) -> bool:
    seqs = [record.seq for record in records]
    return not seqs or seqs == list(range(seqs[0], seqs[0] + len(seqs)))
