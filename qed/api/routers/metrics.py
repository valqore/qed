"""``GET /metrics`` — Prometheus exposition (SPEC §18).

The nine metrics SPEC §18 names, and nothing else. Each is declared here, next
to the code that reads it, rather than registered at import time somewhere
else: a metric whose definition lives apart from its use is one that outlives
the thing it measured.

**Open, like ``/healthz`` and ``/readyz``.** A scraper is not an adapter and
has no signing secret, and the alternative — a bearer token in every Prometheus
config — is the arrangement that ends with monitoring switched off. What is
exposed is counts, latencies and queue depths: no principal, no target, no
payload. The labels are bounded by construction (``qed/infra/metrics.py``),
because a metric labelled with a proposal's own strings is a cardinality
explosion an agent can trigger on purpose.

The gauges are read at scrape time from the store, not pushed. Queue depth and
checkpoint age are questions with a current answer, and a copy of that answer
updated on some other schedule would be a number that is right most of the
time.
"""

from __future__ import annotations

from typing import Final

from fastapi import APIRouter, Request
from starlette.responses import PlainTextResponse

from qed.api.app_state import qed_state
from qed.core.schemas import utcnow

router = APIRouter(tags=["observability"])

#: ``name -> (prometheus type, help)``. The `_total` suffix on counters is a
#: convention scrapers and dashboards rely on, so it is part of the name.
METRICS: Final[dict[str, tuple[str, str]]] = {
    "qed_decisions_total": (
        "counter",
        "Decisions by outcome, mode, environment and adapter kind.",
    ),
    "qed_decision_latency_seconds": (
        "histogram",
        "Time to decide one proposal, excluding transport. SPEC 18 targets p95 < 0.05s.",
    ),
    "qed_approvals_total": ("counter", "Approval requests by what happened to them."),
    "qed_approval_wait_seconds": (
        "histogram",
        "How long an approval waited before a human decided it.",
    ),
    "qed_budget_exhausted_total": (
        "counter",
        "Times a budget ran out, by the axis that ran out.",
    ),
    "qed_chain_lag_records": (
        "gauge",
        "Records in the evidence outbox, not yet chained. Always 0 on the direct path.",
    ),
    "qed_chain_last_checkpoint_age_seconds": (
        "gauge",
        "Age of the newest checkpoint. Grows without bound when nothing is checkpointing.",
    ),
    "qed_ungated_windows_total": (
        "counter",
        "Intervals in which an adapter proceeded without a verdict (fail-open).",
    ),
    "qed_no_rule_matched_ratio": (
        "gauge",
        "Share of decisions that matched no rule and fell through to the default verdict.",
    ),
    "qed_records_total": ("gauge", "Records in the chain."),
    # The two the ratio above is derived from. Exposed rather than hidden,
    # because a dashboard wants the numerator and denominator anyway, and a
    # ratio nobody can take apart is a ratio nobody trusts.
    "qed_decisions_observed_total": ("counter", "Decisions this process has recorded."),
    "qed_decisions_no_rule_total": (
        "counter",
        "Decisions that matched no rule and fell through to the default verdict.",
    ),
}

#: Approval wait times are minutes-to-hours, not milliseconds, so the latency
#: buckets would put almost everything in `+Inf`.
WAIT_BUCKETS: Final[tuple[float, ...]] = (10.0, 30.0, 60.0, 300.0, 900.0, 3600.0, 14400.0, 86400.0)


@router.get("/metrics", include_in_schema=False)
async def metrics(request: Request) -> PlainTextResponse:
    state = qed_state(request)
    registry = state.metrics

    session = state.session
    if session is not None:
        # Read now, from whoever knows. An instance that is not ready still
        # answers: the counters are about what it did before it stopped being
        # ready, which is exactly what somebody debugging wants.
        registry.set_gauge("qed_records_total", float(session.store.count_evidence()))
        registry.set_gauge(
            "qed_chain_lag_records",
            float(session.store.outbox_depth()) if session.writer.deferred else 0.0,
        )
        registry.set_gauge("qed_chain_last_checkpoint_age_seconds", _checkpoint_age(session))
        registry.set_gauge("qed_no_rule_matched_ratio", _no_rule_ratio(registry))

    body = registry.render(descriptions=METRICS)
    # 0.0.4 is the text format every Prometheus understands; naming the version
    # is what stops a scraper guessing.
    return PlainTextResponse(body, media_type="text/plain; version=0.0.4; charset=utf-8")


def _checkpoint_age(session: object) -> float:
    """Seconds since the newest checkpoint, or -1 when there is none.

    -1 rather than 0: a chain with no checkpoint at all is a different state
    from one checkpointed a moment ago, and an alert on "age > 2h" must not be
    satisfied by the absence of the thing it is watching.
    """
    from qed.runtime import Session

    assert isinstance(session, Session)
    checkpoint = session.store.last_checkpoint()
    if checkpoint is None or checkpoint.evidence_seq is None:
        return -1.0
    record = session.store.evidence_at(checkpoint.evidence_seq)
    if record is None:  # pragma: no cover - the row names a real record
        return -1.0
    return round((utcnow() - record.ts).total_seconds(), 3)


def _no_rule_ratio(registry: object) -> float:
    """SPEC §18's `qed_no_rule_matched_ratio`.

    Derived from two counters rather than tracked as its own number, so it
    cannot drift from them. A ratio of a count that is zero is 0, not a
    division error -- and not 1, which would read as "everything fell through"
    on an instance that has decided nothing.
    """
    from qed.infra.metrics import MetricsRegistry

    assert isinstance(registry, MetricsRegistry)
    decided = registry.counter("qed_decisions_observed_total")
    fell_through = registry.counter("qed_decisions_no_rule_total")
    return round(fell_through / decided, 6) if decided else 0.0
