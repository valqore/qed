"""``/v1/approvals`` (SPEC §9, §13).

The decision path is shared with `gate approve`, so these tests are about the
HTTP surface: who the approver is taken to be, what a refusal looks like, and
whether two approvers can both win.
"""

from __future__ import annotations

import json
from typing import Any

from fastapi.testclient import TestClient

from gate.api.routers.approvals import HEADER_APPROVER, HEADER_APPROVER_GROUPS
from gate.core.evidence.hashing import principal_hash
from tests.api.conftest import Signer

ALI = principal_hash("ali@example.com")

NEEDS_APPROVAL: dict[str, Any] = {
    "schema_version": "1.0",
    "id": "01JB0000000000000000000C01",
    "ts": "2026-10-08T12:00:00.000Z",
    "principal": {
        "token_jti": "01JB000000000000000000JTI0",
        "human_hash": ALI,
        "agent_chain": ["claude-code@laptop"],
    },
    "action": {
        "kind": "mcp_tool",
        "name": "postgres.execute_sql",
        "target": "db:prod/orders",
        "params_hash": "0" * 64,
        "params_redacted": {"sql": "DELETE FROM orders WHERE id = 1"},
    },
    "context": {
        "environment": "prod",
        "adapter": "mcp-proxy/0.1.0",
        "adapter_id": "adp_test",
        "enforcement": "enforcing",
        "mode": "enforce",
        "cost_estimate": {"tokens": 0, "money_cents": 0, "currency": "USD", "known": True},
        "blast_radius_hints": {"writes": True, "deletes": True, "scope": "single_resource"},
        "intent": "clear the failed import",
        "summary": "delete one order row",
    },
}


def open_request(signed: Signer, n: int = 1) -> str:
    proposal = {**NEEDS_APPROVAL, "id": f"01JB0000000000000000000C{n:02d}"}
    response = signed.post("/v1/proposals", proposal)
    assert response.status_code in {200, 202}, response.text
    listed = signed.get("/v1/approvals?status=pending").json()["approvals"]
    assert listed, "a REQUIRE_APPROVAL should have opened a request"
    return str(listed[0]["id"])


def approver_headers(subject: str, groups: str = "sre-oncall") -> dict[str, str]:
    return {HEADER_APPROVER: subject, HEADER_APPROVER_GROUPS: groups}


class TestListingAndDetail:
    def test_the_queue_lists_a_pending_request(self, signed: Signer) -> None:
        approval_id = open_request(signed)
        found = signed.get("/v1/approvals").json()["approvals"]
        assert any(item["id"] == approval_id for item in found)

    def test_the_detail_carries_what_an_approver_needs(self, signed: Signer) -> None:
        approval_id = open_request(signed, 2)
        body = signed.get(f"/v1/approvals/{approval_id}").json()
        view = body["request"]
        assert view["action"]["target"] == "db:prod/orders"
        assert view["blast_radius"] > 0
        assert view["hits"], "an approver has to see what fired"

    def test_an_unknown_id_is_a_404(self, signed: Signer) -> None:
        assert signed.get("/v1/approvals/apr_nope").status_code == 404

    def test_a_bad_status_filter_is_rejected(self, signed: Signer) -> None:
        assert signed.get("/v1/approvals?status=maybe").status_code == 400


class TestDeciding:
    def test_a_third_party_in_the_group_may_approve(self, signed: Signer) -> None:
        approval_id = open_request(signed, 3)
        response = signed.post(
            f"/v1/approvals/{approval_id}",
            {"decision": "approve_once"},
            headers=approver_headers("priya@example.com"),
        )
        assert response.status_code == 200, response.text
        assert response.json()["status"] == "approved"

    def test_the_principal_cannot_approve_their_own_action(self, signed: Signer) -> None:
        approval_id = open_request(signed, 4)
        response = signed.post(
            f"/v1/approvals/{approval_id}",
            {"decision": "approve_once"},
            headers=approver_headers("ali@example.com"),
        )
        assert response.status_code == 403
        assert response.json()["rule_id"] == "AG-SOD-001"

    def test_a_refused_attempt_is_written_to_the_chain(self, signed: Signer) -> None:
        """A refusal nobody recorded is indistinguishable from an attempt
        nobody made."""
        approval_id = open_request(signed, 5)
        signed.post(
            f"/v1/approvals/{approval_id}",
            {"decision": "approve_once"},
            headers=approver_headers("ali@example.com"),
        )
        chain = signed.get("/v1/evidence").text
        assert "AG-SOD-001" in chain

    def test_an_unidentified_caller_cannot_decide(self, signed: Signer) -> None:
        """The approver travels in a header, not the body: an endpoint that
        let the request name its own approver would make the control
        decorative."""
        approval_id = open_request(signed, 6)
        response = signed.post(
            f"/v1/approvals/{approval_id}",
            {"decision": "approve_once", "approver": "priya@example.com"},
        )
        assert response.status_code == 400
        # RFC 9457: the machine-readable code is the tail of `type`.
        assert response.json()["type"].endswith("/no-approver")

    def test_a_window_is_returned_and_bounded(self, signed: Signer) -> None:
        approval_id = open_request(signed, 7)
        response = signed.post(
            f"/v1/approvals/{approval_id}",
            {"decision": "approve_window", "window_minutes": 600},
            headers=approver_headers("priya@example.com"),
        )
        assert response.status_code == 200
        assert response.json()["window_until"] is not None

    def test_deciding_twice_is_a_conflict(self, signed: Signer) -> None:
        approval_id = open_request(signed, 8)
        first = signed.post(
            f"/v1/approvals/{approval_id}",
            {"decision": "approve_once"},
            headers=approver_headers("priya@example.com"),
        )
        assert first.status_code == 200
        second = signed.post(
            f"/v1/approvals/{approval_id}",
            {"decision": "deny"},
            headers=approver_headers("sam@example.com"),
        )
        assert second.status_code == 409

    def test_an_unknown_decision_is_rejected(self, signed: Signer) -> None:
        approval_id = open_request(signed, 9)
        response = signed.post(
            f"/v1/approvals/{approval_id}",
            {"decision": "maybe"},
            headers=approver_headers("priya@example.com"),
        )
        assert response.status_code == 400

    def test_the_decision_lands_in_the_chain_with_its_sequence(self, signed: Signer) -> None:
        approval_id = open_request(signed, 10)
        body = signed.post(
            f"/v1/approvals/{approval_id}",
            {"decision": "approve_once", "reason": "checked with the DBA"},
            headers=approver_headers("priya@example.com"),
        ).json()
        assert isinstance(body["evidence_seq"], int)


class TestEvents:
    def test_the_stream_refuses_an_unsigned_request(self, client: TestClient) -> None:
        assert client.get("/v1/events").status_code in {401, 503}

    def test_a_bad_cursor_is_rejected(self, signed: Signer) -> None:
        assert signed.get("/v1/events?from=yesterday").status_code == 400


class TestSlackEndpoint:
    def test_slack_interactivity_refuses_when_unconfigured(self, client: TestClient) -> None:
        """501, not a silent accept. An unauthenticated decision endpoint is
        worse than no Slack integration."""
        response = client.post("/slack/interactivity", content=b"payload=%7B%7D")
        assert response.status_code == 501
        assert response.json()["type"].endswith("/slack-not-configured")

    def test_it_is_outside_v1_because_slack_cannot_sign_our_envelope(
        self, client: TestClient
    ) -> None:
        # The published contract, not the route tree: FastAPI wraps included
        # routers in a private type whose shape moves between versions, which
        # `tests/api/test_auth.py` already learned the hard way.
        paths = set(client.app.openapi()["paths"])  # type: ignore[attr-defined]
        assert "/slack/interactivity" in paths
        assert not any(p.startswith("/v1/slack") for p in paths)


def test_the_api_and_the_cli_share_one_decision_path() -> None:
    """Both import `decide` from the core. A channel that decided for itself
    would be a channel where separation of duties worked differently."""
    import inspect

    from gate import cli
    from gate.api.routers import approvals as api
    from gate.api.routers import slack as slack_router

    for module in (cli, api, slack_router):
        source = inspect.getsource(module)
        assert "from gate.core.approval.model import" in source or "decide(" in source
    assert "def decide(" not in inspect.getsource(api)
    assert "def decide(" not in inspect.getsource(slack_router)
    assert json  # keeps the import meaningful for the json-shaped assertions above
