"""Approval state, dedupe and separation of duties (SPEC §9). Pure.

Nothing here reads a clock or a store: ``now`` arrives as an argument, so a
decision made six months ago can be replayed from the chain and reach the same
answer. That is the same rule the policy engine follows, for the same reason.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta
from enum import StrEnum

from pydantic import Field

from qed.core.evidence.format import CHAIN_FORMAT
from qed.core.schemas import ActionProposal, Frozen, Timestamp

__all__ = [
    "DEDUPE_DOMAIN",
    "DEFAULT_DEDUPE_WINDOW",
    "DEFAULT_WINDOW",
    "MAX_WINDOW",
    "ApprovalDecision",
    "ApprovalRequest",
    "ApprovalStatus",
    "DecisionKind",
    "SoDViolation",
    "check_separation_of_duties",
    "decide",
    "dedupe_key",
    "is_expired",
    "parse_duration",
    "window_until",
]

#: Domain separator, so a dedupe key cannot collide with some other sha256 of
#: the same four strings used for a different purpose.
DEDUPE_DOMAIN = f"{CHAIN_FORMAT}:approval-dedupe:"

#: SPEC §9.2. Long enough that a retrying agent joins the request a human is
#: already looking at; short enough that "the same action" still means the
#: same situation.
DEFAULT_DEDUPE_WINDOW = timedelta(minutes=10)

#: SPEC §9.3 service defaults.
DEFAULT_WINDOW = timedelta(minutes=15)
MAX_WINDOW = timedelta(minutes=60)

#: A service identity cannot approve anything (SPEC §9.3).
SERVICE_PREFIX = "svc:"

_UNITS = {"ms": 0.001, "s": 1.0, "m": 60.0, "h": 3600.0, "d": 86400.0}


def parse_duration(text: str | None) -> timedelta | None:
    """``"10m"`` -> ten minutes. ``None`` passes through.

    The policy schema validates the shape with a regex, so anything reaching
    here is well formed; an unparseable value is a loader bug rather than a
    user error, and raising says so.
    """
    if text is None:
        return None
    for suffix, seconds in sorted(_UNITS.items(), key=lambda kv: -len(kv[0])):
        if text.endswith(suffix):
            return timedelta(seconds=float(text[: -len(suffix)]) * seconds)
    raise ValueError(f"{text!r} is not a duration the policy schema allows")


class ApprovalStatus(StrEnum):
    """SPEC §9.1. ``escalated`` is a flag, not a state."""

    pending = "pending"
    approved = "approved"
    denied = "denied"
    expired = "expired"
    superseded = "superseded"


class DecisionKind(StrEnum):
    approve_once = "approve_once"
    approve_window = "approve_window"
    deny = "deny"


class SoDViolation(Exception):
    """Separation of duties was not satisfied (SPEC §9.3).

    Carries the rule id so the refusal lands in the chain as a finding rather
    than as an unexplained error.
    """

    def __init__(self, rule_id: str, detail: str) -> None:
        self.rule_id = rule_id
        super().__init__(detail)


class ApprovalRequest(Frozen):
    id: str
    proposal_id: str
    dedupe_key: str
    status: ApprovalStatus = ApprovalStatus.pending
    #: Groups or principals who may decide this, from the rule that fired.
    approvers: list[str] = Field(default_factory=list)
    #: Hash of the human the action is for. The one person who may not decide.
    principal_hash: str | None = None
    created_at: Timestamp
    expires_at: Timestamp
    escalate_at: Timestamp | None = None
    escalated: bool = False
    #: Largest window this request may grant, from the rule. None = service cap.
    window_max: timedelta | None = None


class ApprovalDecision(Frozen):
    approval_id: str
    kind: DecisionKind
    approver_hash: str
    decided_at: Timestamp
    reason: str = ""
    #: Set only for ``approve_window``.
    window_until: Timestamp | None = None

    @property
    def status(self) -> ApprovalStatus:
        return ApprovalStatus.denied if self.kind is DecisionKind.deny else ApprovalStatus.approved


def dedupe_key(proposal: ActionProposal) -> str:
    """SPEC §9.2: ``sha256(principal | name | target | params_hash)``.

    Deliberately **not** including the environment or the timestamp. Two
    identical actions a minute apart are the same request as far as a human is
    concerned, and an approver should see one of them, not forty.

    Deliberately **including** ``params_hash``: an approval for
    ``DROP TABLE orders_archive`` must not cover ``DROP TABLE orders``, and the
    parameters are the only thing that distinguishes them.
    """
    parts = [
        proposal.principal.human_hash or f"{SERVICE_PREFIX}{proposal.principal.token_jti}",
        proposal.action.name,
        proposal.action.target,
        proposal.action.params_hash,
    ]
    payload = DEDUPE_DOMAIN + "|".join(parts)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def is_expired(request: ApprovalRequest, *, now: datetime) -> bool:
    return request.status is ApprovalStatus.pending and request.expires_at <= now


def window_until(
    *,
    now: datetime,
    requested: timedelta | None,
    rule_max: timedelta | None,
    service_default: timedelta = DEFAULT_WINDOW,
    service_max: timedelta = MAX_WINDOW,
) -> datetime:
    """When a window granted now should end (SPEC §9.3).

    The smallest of what was asked for, what the rule allows, and what the
    service allows. An approver cannot widen a rule's own ceiling by asking,
    which is the whole reason the rule carries one.
    """
    wanted = requested if requested is not None else service_default
    bounds = [wanted, service_max]
    if rule_max is not None:
        bounds.append(rule_max)
    return now + max(min(bounds), timedelta(0))


def check_separation_of_duties(
    request: ApprovalRequest,
    *,
    approver_hash: str,
    approver_subject: str,
    approver_groups: list[str],
) -> None:
    """SPEC §9.3. Raises :class:`SoDViolation`, or returns None.

    Three conditions, and all three are refusals rather than warnings:

    * the approver is not the principal (AG-SOD-001),
    * the approver is a person, not a service identity (AG-SOD-002), and
    * the approver is in the group the rule named (AG-SOD-002).

    A compliance report listing a "separation of duties" control while
    nothing enforces it is worse than one that omits it, because the evidence
    says somebody checked. That is the failure this function exists to not be,
    which is why all three conditions refuse rather than warn.
    """
    if request.principal_hash is not None and approver_hash == request.principal_hash:
        raise SoDViolation(
            "AG-SOD-001",
            "the approver is the principal this action is for; somebody else has to agree",
        )
    if approver_subject.startswith(SERVICE_PREFIX):
        raise SoDViolation(
            "AG-SOD-002",
            f"{approver_subject} is a service identity, and an approval needs a person",
        )
    if request.approvers:
        allowed = set(request.approvers)
        if not (allowed & set(approver_groups)) and approver_subject not in allowed:
            raise SoDViolation(
                "AG-SOD-002",
                f"{approver_subject} is not in {sorted(allowed)}, which the rule named",
            )


def decide(
    request: ApprovalRequest,
    *,
    kind: DecisionKind,
    approver_hash: str,
    approver_subject: str,
    approver_groups: list[str],
    now: datetime,
    reason: str = "",
    requested_window: timedelta | None = None,
    service_default: timedelta = DEFAULT_WINDOW,
    service_max: timedelta = MAX_WINDOW,
    require_reason_for_deny: bool = False,
) -> ApprovalDecision:
    """Decide a pending request, or refuse to.

    An expired request is refused rather than silently decided: the agent has
    long since been told no, and an approval arriving afterwards would create
    a window nobody is waiting on.
    """
    if request.status is not ApprovalStatus.pending:
        raise ValueError(
            f"approval {request.id} is already {request.status.value}; decisions are made once"
        )
    if is_expired(request, now=now):
        raise ValueError(
            f"approval {request.id} expired at {request.expires_at.isoformat()}; "
            "the agent has already been told no, so approving it now would open "
            "a window nobody is waiting on"
        )
    if kind is DecisionKind.deny and require_reason_for_deny and not reason.strip():
        raise ValueError("this instance requires a reason when denying")

    check_separation_of_duties(
        request,
        approver_hash=approver_hash,
        approver_subject=approver_subject,
        approver_groups=approver_groups,
    )

    until: datetime | None = None
    if kind is DecisionKind.approve_window:
        until = window_until(
            now=now,
            requested=requested_window,
            rule_max=request.window_max,
            service_default=service_default,
            service_max=service_max,
        )

    return ApprovalDecision(
        approval_id=request.id,
        kind=kind,
        approver_hash=approver_hash,
        decided_at=now,
        reason=reason,
        window_until=until,
    )
