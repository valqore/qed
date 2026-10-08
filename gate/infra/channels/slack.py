"""Slack as an approval channel (SPEC §9.5).

Rendering a request and resolving a clicker to a person. Verifying Slack's
own signature on the way in lives in :mod:`gate.api.slack_auth`, with the
other request authentication -- the no-HMAC invariant scans this package and
that boundary is worth keeping absolute.

Two directions, and the second is the one that matters:

* **out** — a Block Kit message somebody can judge without leaving Slack, and
* **in** — a button click turned into an *identified human*, which is the only
  thing that makes the decision worth anything.

A Slack user id is not an identity the gate can use. It is mapped to an email
through ``users.info`` and then to a principal hash, so the approver in the
chain is the same person the identity provider knows. Recording `U01ABCDEF`
would be recording that somebody with access to a Slack workspace clicked a
button.

No `slack-sdk` dependency: the two calls needed are `chat.postMessage` and
`users.info`, both plain POSTs, and SPEC §20.3 lists `slack-sdk` only as an
optional extra. `httpx` is already here.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

import httpx

__all__ = ["SlackChannel", "SlackError", "render_blocks"]

SLACK_API = "https://slack.com/api"
HTTP_TIMEOUT = 10.0

_SEVERITY_ICON = {
    "CRITICAL": ":rotating_light:",
    "HIGH": ":warning:",
    "MEDIUM": ":large_orange_diamond:",
    "LOW": ":information_source:",
}


class SlackError(RuntimeError):
    """Slack refused, or answered something unusable."""


def render_blocks(view: dict[str, Any], *, approval_id: str) -> list[dict[str, Any]]:
    """The approver view as Block Kit.

    Laid out so the three things a person needs are above the buttons: what
    is being asked, what fired, and how bad it would be. The parameters go in
    last and collapsed, because they are the detail you read if the summary
    did not settle it.
    """
    hits = view.get("hits") or []
    worst = max(
        (str(h.get("severity", "MEDIUM")) for h in hits),
        key=lambda s: (
            ["LOW", "MEDIUM", "HIGH", "CRITICAL"].index(s)
            if s in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
            else 1
        ),
        default="MEDIUM",
    )
    action = view.get("action") or {}
    chain = view.get("agent_chain") or []

    blocks: list[dict[str, Any]] = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"{_SEVERITY_ICON.get(worst, ':grey_question:')} Approval needed",
            },
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Action*\n`{action.get('name', '?')}`"},
                {"type": "mrkdwn", "text": f"*Target*\n`{action.get('target', '?')}`"},
                {"type": "mrkdwn", "text": f"*Environment*\n{view.get('environment', '?')}"},
                {"type": "mrkdwn", "text": f"*Blast radius*\n{view.get('blast_radius', '?')}/100"},
            ],
        },
    ]

    intent = view.get("intent")
    if intent:
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": f"*Why*\n{intent}"}})
    if chain:
        blocks.append(
            {
                "type": "context",
                "elements": [
                    {"type": "mrkdwn", "text": "via " + " -> ".join(f"`{a}`" for a in chain)}
                ],
            }
        )
    if hits:
        lines = "\n".join(f"• *{h.get('rule_id')}* {h.get('message', '')}" for h in hits)
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": f"*Rules*\n{lines}"}})

    blocks.append(
        {
            "type": "actions",
            "block_id": approval_id,
            "elements": [
                {
                    "type": "button",
                    "style": "primary",
                    "text": {"type": "plain_text", "text": "Approve once"},
                    "action_id": "approve_once",
                    "value": approval_id,
                },
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "Approve 15m"},
                    "action_id": "approve_window",
                    "value": approval_id,
                },
                {
                    "type": "button",
                    "style": "danger",
                    "text": {"type": "plain_text", "text": "Deny"},
                    "action_id": "deny",
                    "value": approval_id,
                },
            ],
        }
    )
    expires = view.get("expires_at")
    if expires:
        blocks.append(
            {
                "type": "context",
                "elements": [{"type": "mrkdwn", "text": f"Expires {expires}"}],
            }
        )
    return blocks


@dataclass
class SlackChannel:
    """Posts requests and resolves clickers to people."""

    bot_token: str
    channel: str
    client: httpx.Client | None = None

    def _post(self, method: str, payload: dict[str, Any]) -> dict[str, Any]:
        owned = self.client is None
        http = self.client or httpx.Client(timeout=HTTP_TIMEOUT)
        try:
            response = http.post(
                f"{SLACK_API}/{method}",
                headers={
                    "authorization": f"Bearer {self.bot_token}",
                    "content-type": "application/json; charset=utf-8",
                },
                content=json.dumps(payload).encode(),
            )
            body = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise SlackError(f"could not reach Slack {method}: {exc}") from exc
        finally:
            if owned:
                http.close()
        if not body.get("ok"):
            raise SlackError(f"Slack {method} refused: {body.get('error', 'no reason given')}")
        return dict(body)

    def post_request(self, view: dict[str, Any], *, approval_id: str) -> str:
        """Post the request. Returns the message ts, for updating it later."""
        body = self._post(
            "chat.postMessage",
            {
                "channel": self.channel,
                "text": f"Approval needed: {view.get('summary', approval_id)}",
                "blocks": render_blocks(view, approval_id=approval_id),
            },
        )
        return str(body.get("ts", ""))

    def email_for_user(self, user_id: str) -> str:
        """Slack user id -> email, which is the identity the IdP shares.

        Without this step the chain would record that somebody with access to
        a Slack workspace pressed a button, which is not who approved.
        """
        body = self._post("users.info", {"user": user_id})
        user = body.get("user") or {}
        email = (user.get("profile") or {}).get("email")
        if not email:
            raise SlackError(
                f"Slack user {user_id} has no email on their profile, so there is no "
                "way to say which person this is. Grant users:read.email, or use the "
                "web approval page for this one."
            )
        return str(email)

    def update_decided(
        self, *, ts: str, view: dict[str, Any], decision: str, approver: str
    ) -> None:
        """Replace the buttons with the outcome, so nobody clicks a stale one."""
        self._post(
            "chat.update",
            {
                "channel": self.channel,
                "ts": ts,
                "text": f"{decision} by {approver}",
                "blocks": [
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": (
                                f"*{decision}* by {approver}\n"
                                f"`{(view.get('action') or {}).get('name', '?')}` on "
                                f"`{(view.get('action') or {}).get('target', '?')}`"
                            ),
                        },
                    }
                ],
            },
        )
