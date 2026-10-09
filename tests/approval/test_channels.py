"""Approval channels (SPEC §9.5): Slack signatures, rendering, webhooks.

The signature verifier lives in `qed.api.slack_auth`, not with the Slack
client: it authenticates an inbound request, and the no-HMAC invariant scans
`qed/core` and `qed/infra` with no exemption list.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from typing import Any

import httpx
import pytest

from qed.api.slack_auth import (
    MAX_SIGNATURE_AGE,
    SlackSignatureError,
    verify_slack_signature,
)
from qed.infra.channels.slack import SlackChannel, SlackError, render_blocks
from qed.infra.channels.webhook import WebhookChannel, webhook_payload

SECRET = "s" * 32

VIEW: dict[str, Any] = {
    "approval_id": "apr_01",
    "summary": "claude-code wants to DROP TABLE orders_archive",
    "intent": "clean up the September migration",
    "environment": "prod",
    "agent_chain": ["claude-code@laptop", "sub:planner"],
    "action": {"kind": "mcp_tool", "name": "postgres.execute_sql", "target": "db:prod/orders"},
    "params_redacted": {"sql": "DROP TABLE orders_archive;"},
    "blast_radius": 75,
    "hits": [
        {
            "rule_id": "AG-BLR-003",
            "message": "Destructive change to production.",
            "severity": "HIGH",
        },
    ],
    "expires_at": "2026-10-08T12:15:00Z",
}


def sign_slack(body: bytes, timestamp: str, secret: str = SECRET) -> str:
    base = b"v0:" + timestamp.encode() + b":" + body
    return "v0=" + hmac.new(secret.encode(), base, hashlib.sha256).hexdigest()


class TestSlackSignature:
    def test_a_correctly_signed_request_verifies(self) -> None:
        now = time.time()
        body, ts = b"payload=%7B%7D", str(int(now))
        verify_slack_signature(
            signing_secret=SECRET,
            timestamp=ts,
            body=body,
            signature=sign_slack(body, ts),
            now=now,
        )

    def test_a_tampered_body_does_not_verify(self) -> None:
        now = time.time()
        ts = str(int(now))
        signature = sign_slack(b"payload=original", ts)
        with pytest.raises(SlackSignatureError, match="does not match"):
            verify_slack_signature(
                signing_secret=SECRET,
                timestamp=ts,
                body=b"payload=swapped",
                signature=signature,
                now=now,
            )

    def test_another_secret_does_not_verify(self) -> None:
        now = time.time()
        ts = str(int(now))
        body = b"payload=%7B%7D"
        with pytest.raises(SlackSignatureError):
            verify_slack_signature(
                signing_secret="different" * 4,
                timestamp=ts,
                body=body,
                signature=sign_slack(body, ts),
                now=now,
            )

    def test_an_old_request_is_a_replay_even_with_a_valid_signature(self) -> None:
        """The signature stays valid forever. The timestamp is the only thing
        that makes a captured request stop working."""
        now = time.time()
        old = str(int(now - MAX_SIGNATURE_AGE - 60))
        body = b"payload=%7B%7D"
        with pytest.raises(SlackSignatureError, match="replay"):
            verify_slack_signature(
                signing_secret=SECRET,
                timestamp=old,
                body=body,
                signature=sign_slack(body, old),
                now=now,
            )

    def test_a_timestamp_from_the_future_is_also_refused(self) -> None:
        now = time.time()
        ahead = str(int(now + MAX_SIGNATURE_AGE + 60))
        body = b"payload=%7B%7D"
        with pytest.raises(SlackSignatureError, match="replay"):
            verify_slack_signature(
                signing_secret=SECRET,
                timestamp=ahead,
                body=body,
                signature=sign_slack(body, ahead),
                now=now,
            )

    def test_a_non_numeric_timestamp_is_refused(self) -> None:
        with pytest.raises(SlackSignatureError, match="not a number"):
            verify_slack_signature(
                signing_secret=SECRET, timestamp="yesterday", body=b"", signature="v0=x"
            )


class TestRendering:
    def test_the_buttons_carry_the_approval_id(self) -> None:
        blocks = render_blocks(VIEW, approval_id="apr_01")
        actions = next(b for b in blocks if b["type"] == "actions")
        assert actions["block_id"] == "apr_01"
        assert {e["action_id"] for e in actions["elements"]} == {
            "approve_once",
            "approve_window",
            "deny",
        }

    def test_the_action_and_target_are_above_the_buttons(self) -> None:
        """What is being asked has to be readable before the thing that
        commits you to an answer."""
        blocks = render_blocks(VIEW, approval_id="apr_01")
        kinds = [b["type"] for b in blocks]
        assert kinds.index("section") < kinds.index("actions")
        rendered = json.dumps(blocks)
        assert "postgres.execute_sql" in rendered
        assert "db:prod/orders" in rendered

    def test_the_rules_that_fired_are_shown(self) -> None:
        assert "AG-BLR-003" in json.dumps(render_blocks(VIEW, approval_id="apr_01"))

    def test_the_agent_chain_is_shown(self) -> None:
        assert "sub:planner" in json.dumps(render_blocks(VIEW, approval_id="apr_01"))

    def test_a_view_with_nothing_optional_still_renders(self) -> None:
        bare = {"action": {"name": "x", "target": "y"}, "environment": "dev"}
        blocks = render_blocks(bare, approval_id="apr_02")
        assert any(b["type"] == "actions" for b in blocks)


class TestSlackIdentity:
    def _channel(self, handler: Any) -> SlackChannel:
        return SlackChannel(
            bot_token="xoxb-test",
            channel="#approvals",
            client=httpx.Client(transport=httpx.MockTransport(handler)),
        )

    def test_a_slack_user_is_resolved_to_an_email(self) -> None:
        """A Slack user id says somebody with workspace access pressed a
        button. The email is what the identity provider also knows."""

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200, json={"ok": True, "user": {"profile": {"email": "priya@example.com"}}}
            )

        assert self._channel(handler).email_for_user("U01") == "priya@example.com"

    def test_a_user_with_no_email_is_an_error_not_a_fallback(self) -> None:
        """Falling back to the Slack id would put `U01ABCDEF approved it` in
        the chain, which is not an answer to "who approved it"."""

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"ok": True, "user": {"profile": {}}})

        with pytest.raises(SlackError, match="no email"):
            self._channel(handler).email_for_user("U01")

    def test_a_slack_error_is_surfaced(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"ok": False, "error": "user_not_found"})

        with pytest.raises(SlackError, match="user_not_found"):
            self._channel(handler).email_for_user("U01")

    def test_posting_a_request_returns_the_message_ts(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"ok": True, "ts": "1712345.6789"})

        assert self._channel(handler).post_request(VIEW, approval_id="apr_01") == "1712345.6789"


class TestWebhook:
    def test_parameters_never_leave_in_a_webhook(self) -> None:
        """A webhook goes somewhere QED does not control. The request
        detail stays behind the API, where it can be authenticated."""
        body = webhook_payload("approval_requested", VIEW)
        assert "params_redacted" not in body
        assert body["event"] == "approval_requested"
        assert body["blast_radius"] == 75

    def test_delivery_reports_success(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(204)

        channel = WebhookChannel(
            url="https://hooks.example/x",
            client=httpx.Client(transport=httpx.MockTransport(handler)),
        )
        assert channel.send("approval_requested", VIEW) is True

    def test_a_failed_webhook_never_raises(self) -> None:
        """The caller is in the middle of deciding an action. A notification
        channel that is down must not be able to hold up a verdict."""

        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("down", request=request)

        channel = WebhookChannel(
            url="https://hooks.example/x",
            client=httpx.Client(transport=httpx.MockTransport(handler)),
        )
        assert channel.send("approval_decided", VIEW) is False

    def test_an_unknown_event_is_a_programming_error(self) -> None:
        channel = WebhookChannel(url="https://hooks.example/x")
        with pytest.raises(ValueError, match="not one of"):
            channel.send("something_else", VIEW)
