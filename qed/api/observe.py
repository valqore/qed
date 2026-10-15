"""Recording what happened, for SPEC §18's metrics.

One module so that every metric is incremented in one place rather than spread
through the routers, and so that the label sets are visible together — a
cardinality problem is only visible when you can see all the labels at once.

**Every label value here comes from an enum, a configured id, or a fixed set.**
Never from a proposal's own strings. A metric labelled with `action.target`
would be a cardinality explosion an agent could trigger on purpose, and the
first symptom would be the monitoring system falling over rather than anything
in `qed`.

**Nothing here can fail a request.** A metric is a report; a report that raises
turns an observability concern into an outage. The registry's operations are
dict updates under a lock, and the call sites are after the decision is already
made.
"""

from __future__ import annotations

from qed.core.policy.engine import PREDICATE_FAILED
from qed.core.schemas import ActionProposal
from qed.infra.metrics import MetricsRegistry
from qed.infra.siem import SiemShipper
from qed.runtime import CheckOutcome

__all__ = ["record_approval_decided", "record_decision", "record_ungated_window"]

#: What an unknown or absent adapter kind is called. A label that is sometimes
#: missing makes two time series out of one, so it is always present.
UNKNOWN = "unknown"


def record_decision(
    registry: MetricsRegistry,
    *,
    proposal: ActionProposal,
    outcome: CheckOutcome,
    seconds: float,
    siem: SiemShipper | None = None,
) -> None:
    """SPEC §18's `qed_decisions_total` and `qed_decision_latency_seconds`.

    The decision recorded is the **effective** one -- what the adapter was
    actually told -- because that is what a dashboard is being asked about. A
    shadow-mode BLOCK counts as the ALLOW it became, and `mode` is a label so
    the two can still be told apart.
    """
    registry.increment(
        "qed_decisions_total",
        labels={
            "decision": outcome.effective_decision.value,
            # The **service's** mode, not `context.mode`. The proposal carries
            # what the adapter believed (SPEC §3.1) and the two can disagree --
            # the baseline proposal says `enforce` against a shadow instance --
            # and the one that matters is whether the verdict was applied. It
            # is also the one an operator changes, so it is the one a dashboard
            # slices by when they are about to change it.
            "mode": "enforce" if outcome.enforced else "shadow",
            "environment": proposal.context.environment,
            "adapter_kind": _adapter_kind(proposal),
        },
    )
    registry.observe("qed_decision_latency_seconds", seconds)

    # The two the `qed_no_rule_matched_ratio` gauge is derived from. Unlabelled
    # on purpose: a ratio over four label dimensions is a ratio nobody reads,
    # and the labelled counter above already answers "which kind".
    registry.increment("qed_decisions_observed_total")
    if outcome.verdict.default_applied:
        registry.increment("qed_decisions_no_rule_total")

    # A rule that could not be evaluated was skipped (ADR-0016), so this
    # decision was taken with less policy than the bundle contains. It is in
    # the evidence record either way; the counter is here because a hole in the
    # policy is something an operator should be alerted to rather than find
    # later in a chain. One increment per decision, not per rule: how many
    # rules were skipped is in the hit's message.
    if any(hit.rule_id == PREDICATE_FAILED for hit in outcome.verdict.hits):
        registry.increment("qed_decisions_rule_skipped_total")

    if siem is not None:
        for appended in outcome.records:
            # Only what was chained. A queued record has no sequence number
            # yet, and an OCSF event whose `raw_data` pointed at nothing would
            # be a correlation key that resolves to nothing.
            if appended.record is not None:
                siem.send(
                    appended.record,
                    principal_hash=proposal.principal.human_hash,
                )

    for record in outcome.records:
        if record.type.value == "budget_exhausted":
            # No axis label: which axis ran out is in the record, and putting
            # it here would mean reading a payload the API has already masked.
            registry.increment("qed_budget_exhausted_total")
        elif record.type.value == "approval_requested":
            registry.increment("qed_approvals_total", labels={"decision": "requested"})
        elif record.type.value == "ungated_window":
            registry.increment("qed_ungated_windows_total")


def record_approval_decided(
    registry: MetricsRegistry, *, decision: str, waited_seconds: float | None
) -> None:
    """SPEC §18's `qed_approvals_total` and `qed_approval_wait_seconds`.

    The wait is how long a person took, which is the number an operator uses
    to argue for more approvers. `None` when the request's creation time is
    not available, in which case the wait is simply not observed -- a zero
    would drag the histogram towards a figure nobody waited.
    """
    from qed.api.routers.metrics import WAIT_BUCKETS

    registry.increment("qed_approvals_total", labels={"decision": decision})
    if waited_seconds is not None and waited_seconds >= 0:
        registry.observe("qed_approval_wait_seconds", waited_seconds, buckets=WAIT_BUCKETS)


def record_ungated_window(registry: MetricsRegistry) -> None:
    """For an adapter reporting a fail-open interval after the fact."""
    registry.increment("qed_ungated_windows_total")


def _adapter_kind(proposal: ActionProposal) -> str:
    """`mcp`, `http`, `hook`, `sdk`, ... from the adapter's own name.

    Taken from the adapter string the proposal carries, which is set by the
    adapter and not by the agent -- and reduced to its first token, so
    `qed-sdk/0.5.0` and `qed-sdk/0.6.0` are one series. Anything unrecognised
    becomes `unknown` rather than a new label value, because this is the one
    label whose input is a free-form string.
    """
    adapter = (proposal.context.adapter or "").lower()
    for known in ("mcp", "http", "hook", "sdk", "cli", "proxy"):
        if known in adapter:
            return known
    return UNKNOWN
