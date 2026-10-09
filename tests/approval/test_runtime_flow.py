"""The approval flow through `check_proposal` (SPEC §9.2, §9.3).

The question each test answers is the same one: given what a human has or has
not already said about this exact action, what should happen now.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from qed.core.approval.model import ApprovalStatus, DecisionKind, decide, dedupe_key
from qed.core.evidence.hashing import principal_hash
from qed.core.schemas import Decision, EvidenceType, Mode
from qed.runtime import Session, check_proposal, open_session
from tests.conftest import make_proposal

NOW = datetime(2026, 10, 8, 12, 0, tzinfo=UTC)
ALI = principal_hash("ali@example.com")

#: Trips AG-BLR-003 (destructive change in production), which asks for
#: approval rather than blocking -- the verdict this whole module is about.
NEEDS_APPROVAL: dict[str, object] = {
    "principal": {"human_hash": ALI},
    "action": {"name": "db.delete_rows", "target": "db:prod/orders"},
    "context": {
        "environment": "prod",
        "intent": "clear the failed import",
        "blast_radius_hints": {"writes": True, "deletes": True, "scope": "single_resource"},
    },
}


@pytest.fixture
def session(qed_dir: Path, tmp_path: Path) -> Iterator[Session]:
    config = tmp_path / "qed.yaml"
    config.write_text("mode: enforce\n", encoding="utf-8")
    opened = open_session(directory=qed_dir, config_path=config)
    try:
        yield opened
    finally:
        opened.close()


def propose(session: Session, n: int, **patch: object):  # type: ignore[no-untyped-def]
    merged = {**NEEDS_APPROVAL, **patch, "id": f"01JB0000000000000000000A{n:02d}"}
    return check_proposal(session, make_proposal(merged), now=NOW)


def types_of(outcome: object) -> list[EvidenceType]:
    return [record.type for record in outcome.records]  # type: ignore[attr-defined]


class TestRequestCreation:
    def test_enforce_mode_is_on_for_these_tests(self, session: Session) -> None:
        assert session.config.mode is Mode.enforce

    def test_require_approval_opens_a_request(self, session: Session) -> None:
        outcome = propose(session, 1)
        assert outcome.verdict.decision is Decision.REQUIRE_APPROVAL
        assert outcome.verdict.approval_id is not None
        assert EvidenceType.approval_requested in types_of(outcome)

    def test_the_request_comes_before_the_verdict_in_the_chain(self, session: Session) -> None:
        """The chain should read as what happened, in order: the request was
        opened, and then the verdict that refers to it was written."""
        order = types_of(propose(session, 2))
        assert order.index(EvidenceType.approval_requested) < order.index(EvidenceType.verdict)

    def test_the_request_names_the_approvers_the_rule_asked_for(self, session: Session) -> None:
        outcome = propose(session, 3)
        request = session.store.load_approval(outcome.verdict.approval_id or "")
        assert request is not None
        assert "sre-oncall" in request.approvers

    def test_the_request_carries_the_principal_so_sod_can_be_checked(
        self, session: Session
    ) -> None:
        """Without this on the row, "the approver is not the principal" cannot
        be checked at decision time -- only claimed."""
        outcome = propose(session, 4)
        request = session.store.load_approval(outcome.verdict.approval_id or "")
        assert request is not None
        assert request.principal_hash == ALI

    def test_an_allow_opens_nothing(self, session: Session) -> None:
        outcome = check_proposal(
            session, make_proposal({"id": "01JB0000000000000000000B01"}), now=NOW
        )
        assert outcome.verdict.decision is Decision.ALLOW
        assert outcome.verdict.approval_id is None
        assert EvidenceType.approval_requested not in types_of(outcome)


class TestDedupe:
    def test_the_same_action_twice_links_to_one_request(self, session: Session) -> None:
        """A retrying agent should land on the request a human is already
        looking at, not fill the queue with copies."""
        first = propose(session, 10)
        second = propose(session, 11)
        assert first.verdict.approval_id == second.verdict.approval_id
        assert EvidenceType.approval_requested not in types_of(second)
        assert len(session.store.list_approvals()) == 1

    def test_a_different_action_opens_its_own_request(self, session: Session) -> None:
        propose(session, 12)
        propose(session, 13, action={"name": "db.delete_rows", "target": "db:prod/items"})
        assert len(session.store.list_approvals()) == 2

    def test_a_stale_pending_request_is_not_joined(self, session: Session) -> None:
        """Ten minutes on, "the same action" no longer means the same
        situation, and the queue should say so."""
        first = propose(session, 14)
        later = check_proposal(
            session,
            make_proposal({**NEEDS_APPROVAL, "id": "01JB0000000000000000000A15"}),
            now=NOW + timedelta(minutes=30),
        )
        assert later.verdict.approval_id != first.verdict.approval_id


class TestAfterADecision:
    def _decide(self, session: Session, outcome: object, kind: DecisionKind, **kw: object):  # type: ignore[no-untyped-def]
        request = session.store.load_approval(outcome.verdict.approval_id)  # type: ignore[attr-defined]
        assert request is not None
        decision = decide(
            request,
            kind=kind,
            approver_hash=principal_hash("priya@example.com"),
            approver_subject="priya@example.com",
            approver_groups=["sre-oncall"],
            now=NOW,
            **kw,  # type: ignore[arg-type]
        )
        assert session.store.apply_decision(decision)
        if decision.window_until is not None:
            session.store.open_window(request.dedupe_key, request.id, decision.window_until)
        return decision

    def test_a_denial_blocks_the_next_identical_attempt(self, session: Session) -> None:
        """Otherwise an agent told no simply asks again, and the second
        request looks exactly like the first to whoever sees it."""
        first = propose(session, 20)
        self._decide(session, first, DecisionKind.deny, reason="not during business hours")
        again = propose(session, 21)
        assert again.verdict.decision is Decision.BLOCK
        assert again.verdict.would_decision is Decision.REQUIRE_APPROVAL

    def test_approving_once_does_not_cover_the_next_attempt(self, session: Session) -> None:
        """`approve_once` means once. The next identical action is a new
        question, and the queue should ask it."""
        first = propose(session, 22)
        self._decide(session, first, DecisionKind.approve_once)
        again = propose(session, 23)
        assert again.verdict.decision is Decision.REQUIRE_APPROVAL
        assert again.verdict.approval_id != first.verdict.approval_id

    def test_a_window_allows_the_next_identical_action(self, session: Session) -> None:
        first = propose(session, 24)
        self._decide(
            session, first, DecisionKind.approve_window, requested_window=timedelta(minutes=15)
        )
        again = propose(session, 25)
        assert again.verdict.decision is Decision.ALLOW
        assert again.verdict.via_approval == first.verdict.approval_id

    def test_a_window_does_not_cover_a_different_action(self, session: Session) -> None:
        """ "Priya approved restarting nginx on web-01" is a sentence an
        auditor can check. "Priya is approved" is not."""
        first = propose(session, 26)
        self._decide(
            session, first, DecisionKind.approve_window, requested_window=timedelta(minutes=15)
        )
        other = propose(
            session, 27, action={"name": "db.delete_rows", "target": "db:prod/payments"}
        )
        assert other.verdict.decision is Decision.REQUIRE_APPROVAL

    def test_an_expired_window_stops_covering(self, session: Session) -> None:
        first = propose(session, 28)
        self._decide(
            session, first, DecisionKind.approve_window, requested_window=timedelta(minutes=5)
        )
        later = check_proposal(
            session,
            make_proposal({**NEEDS_APPROVAL, "id": "01JB0000000000000000000A29"}),
            now=NOW + timedelta(hours=1),
        )
        assert later.verdict.decision is Decision.REQUIRE_APPROVAL


class TestExpirySweep:
    def test_overdue_requests_become_expired(self, session: Session) -> None:
        propose(session, 30)
        expired = session.store.expire_approvals(now=NOW + timedelta(hours=2))
        assert len(expired) == 1
        reloaded = session.store.load_approval(expired[0].id)
        assert reloaded is not None
        assert reloaded.status is ApprovalStatus.expired

    def test_a_request_inside_its_window_is_left_alone(self, session: Session) -> None:
        propose(session, 31)
        assert session.store.expire_approvals(now=NOW + timedelta(minutes=1)) == []

    def test_sweeping_twice_reports_nothing_the_second_time(self, session: Session) -> None:
        """Each expiry is written to the chain once. A sweep that kept
        returning the same request would write the record on every tick."""
        propose(session, 32)
        session.store.expire_approvals(now=NOW + timedelta(hours=2))
        assert session.store.expire_approvals(now=NOW + timedelta(hours=3)) == []


class TestDedupeKeyAtRuntime:
    def test_the_key_the_runtime_uses_matches_the_pure_function(self, session: Session) -> None:
        proposal = make_proposal({**NEEDS_APPROVAL, "id": "01JB0000000000000000000A40"})
        outcome = check_proposal(session, proposal, now=NOW)
        request = session.store.load_approval(outcome.verdict.approval_id or "")
        assert request is not None
        assert request.dedupe_key == dedupe_key(proposal)
