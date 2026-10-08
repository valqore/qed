"""Approval state, dedupe and separation of duties (SPEC §9). Pure."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from gate.core.approval.model import (
    DEFAULT_WINDOW,
    MAX_WINDOW,
    ApprovalRequest,
    ApprovalStatus,
    DecisionKind,
    SoDViolation,
    check_separation_of_duties,
    decide,
    dedupe_key,
    is_expired,
    window_until,
)
from tests.conftest import make_proposal

NOW = datetime(2026, 10, 8, 12, 0, tzinfo=UTC)
ALI = "a" * 64
PRIYA = "b" * 64


def request(**kwargs: object) -> ApprovalRequest:
    base: dict[str, object] = {
        "id": "apr_01",
        "proposal_id": "01JB0000000000000000000000",
        "dedupe_key": "k" * 64,
        "principal_hash": ALI,
        "approvers": ["sre-oncall"],
        "created_at": NOW,
        "expires_at": NOW + timedelta(minutes=15),
    }
    base.update(kwargs)
    return ApprovalRequest.model_validate(base)


def approve(req: ApprovalRequest, **kwargs: object):  # type: ignore[no-untyped-def]
    params: dict[str, object] = {
        "kind": DecisionKind.approve_once,
        "approver_hash": PRIYA,
        "approver_subject": "priya@example.com",
        "approver_groups": ["sre-oncall"],
        "now": NOW,
    }
    params.update(kwargs)
    return decide(req, **params)  # type: ignore[arg-type]


class TestDedupeKey:
    def test_the_same_action_twice_keys_the_same(self) -> None:
        assert dedupe_key(make_proposal()) == dedupe_key(make_proposal())

    def test_a_different_target_keys_differently(self) -> None:
        other = make_proposal({"action": {"target": "repo:acme/other"}})
        assert dedupe_key(make_proposal()) != dedupe_key(other)

    def test_different_parameters_key_differently(self) -> None:
        """An approval for `DROP TABLE orders_archive` must not cover
        `DROP TABLE orders`, and the parameters are the only difference."""
        other = make_proposal({"action": {"params_hash": "f" * 64}})
        assert dedupe_key(make_proposal()) != dedupe_key(other)

    def test_a_different_principal_keys_differently(self) -> None:
        other = make_proposal({"principal": {"human_hash": PRIYA}})
        assert dedupe_key(make_proposal()) != dedupe_key(other)

    def test_the_environment_is_not_part_of_the_key(self) -> None:
        """Two identical actions a minute apart are one request as far as a
        human is concerned; an approver should see one, not forty."""
        other = make_proposal({"context": {"environment": "staging"}})
        assert dedupe_key(make_proposal()) == dedupe_key(other)

    def test_an_unattended_principal_still_keys(self) -> None:
        other = make_proposal({"principal": {"human_hash": None, "mandate_id": "md_1"}})
        assert len(dedupe_key(other)) == 64

    def test_the_key_is_domain_separated(self) -> None:
        import hashlib

        proposal = make_proposal()
        naive = hashlib.sha256(
            "|".join(
                [
                    proposal.principal.human_hash or "",
                    proposal.action.name,
                    proposal.action.target,
                    proposal.action.params_hash,
                ]
            ).encode()
        ).hexdigest()
        assert dedupe_key(proposal) != naive


class TestSeparationOfDuties:
    def test_a_different_person_in_the_group_may_decide(self) -> None:
        check_separation_of_duties(
            request(),
            approver_hash=PRIYA,
            approver_subject="priya@example.com",
            approver_groups=["sre-oncall"],
        )

    def test_the_principal_cannot_approve_their_own_action(self) -> None:
        """A compliance report listing a "separation of duties" control while
        nothing enforces it is worse than one that omits it, because the
        evidence says somebody checked. So it is enforced here, and refused
        rather than warned about."""
        with pytest.raises(SoDViolation) as caught:
            check_separation_of_duties(
                request(),
                approver_hash=ALI,
                approver_subject="ali@example.com",
                approver_groups=["sre-oncall"],
            )
        assert caught.value.rule_id == "AG-SOD-001"

    def test_a_service_identity_cannot_approve(self) -> None:
        with pytest.raises(SoDViolation) as caught:
            check_separation_of_duties(
                request(),
                approver_hash=PRIYA,
                approver_subject="svc:auto-approver",
                approver_groups=["sre-oncall"],
            )
        assert caught.value.rule_id == "AG-SOD-002"

    def test_someone_outside_the_named_group_cannot_approve(self) -> None:
        with pytest.raises(SoDViolation, match="sre-oncall"):
            check_separation_of_duties(
                request(),
                approver_hash=PRIYA,
                approver_subject="priya@example.com",
                approver_groups=["interns"],
            )

    def test_a_named_individual_may_approve_without_the_group(self) -> None:
        check_separation_of_duties(
            request(approvers=["priya@example.com"]),
            approver_hash=PRIYA,
            approver_subject="priya@example.com",
            approver_groups=[],
        )

    def test_an_unattended_action_can_be_approved_by_anyone_in_the_group(self) -> None:
        """There is no principal to collide with, so only the other two
        conditions apply."""
        check_separation_of_duties(
            request(principal_hash=None),
            approver_hash=PRIYA,
            approver_subject="priya@example.com",
            approver_groups=["sre-oncall"],
        )


class TestWindow:
    def test_the_default_applies_when_nothing_is_asked_for(self) -> None:
        assert window_until(now=NOW, requested=None, rule_max=None) == NOW + DEFAULT_WINDOW

    def test_a_modest_request_is_honoured(self) -> None:
        got = window_until(now=NOW, requested=timedelta(minutes=5), rule_max=None)
        assert got == NOW + timedelta(minutes=5)

    def test_the_service_ceiling_applies(self) -> None:
        got = window_until(now=NOW, requested=timedelta(days=1), rule_max=None)
        assert got == NOW + MAX_WINDOW

    def test_a_rule_ceiling_is_tighter_than_the_service_one(self) -> None:
        """An approver cannot widen a rule's own ceiling by asking, which is
        the whole reason the rule carries one."""
        got = window_until(now=NOW, requested=timedelta(minutes=50), rule_max=timedelta(minutes=5))
        assert got == NOW + timedelta(minutes=5)


class TestDecide:
    def test_approving_once_grants_no_window(self) -> None:
        assert approve(request()).window_until is None

    def test_approving_a_window_sets_one(self) -> None:
        decision = approve(request(), kind=DecisionKind.approve_window)
        assert decision.window_until == NOW + DEFAULT_WINDOW

    def test_a_denial_is_a_denied_status(self) -> None:
        decision = approve(request(), kind=DecisionKind.deny, reason="no")
        assert decision.status is ApprovalStatus.denied

    def test_an_approval_is_an_approved_status(self) -> None:
        assert approve(request()).status is ApprovalStatus.approved

    def test_a_decided_request_cannot_be_decided_again(self) -> None:
        with pytest.raises(ValueError, match="already approved"):
            approve(request(status=ApprovalStatus.approved))

    def test_an_expired_request_is_refused(self) -> None:
        """The agent was told no fifteen minutes ago. Approving now would open
        a window nobody is waiting on."""
        with pytest.raises(ValueError, match="expired"):
            approve(request(), now=NOW + timedelta(hours=1))

    def test_separation_of_duties_is_enforced_at_decision_time(self) -> None:
        with pytest.raises(SoDViolation):
            approve(request(), approver_hash=ALI, approver_subject="ali@example.com")

    def test_a_reason_can_be_required_for_a_denial(self) -> None:
        with pytest.raises(ValueError, match="reason"):
            approve(
                request(),
                kind=DecisionKind.deny,
                reason="   ",
                require_reason_for_deny=True,
            )

    def test_a_reason_is_not_required_for_an_approval(self) -> None:
        approve(request(), require_reason_for_deny=True)


class TestExpiry:
    def test_a_pending_request_past_its_time_is_expired(self) -> None:
        assert is_expired(request(), now=NOW + timedelta(hours=1)) is True

    def test_a_pending_request_inside_its_time_is_not(self) -> None:
        assert is_expired(request(), now=NOW + timedelta(minutes=1)) is False

    def test_a_decided_request_is_never_expired(self) -> None:
        """Expiry is what happens to a request nobody answered."""
        decided = request(status=ApprovalStatus.approved)
        assert is_expired(decided, now=NOW + timedelta(days=7)) is False
