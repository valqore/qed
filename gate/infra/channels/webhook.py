"""Generic outbound webhook (SPEC §9.5).

For Teams, PagerDuty, or anything else somebody already runs. Deliberately
one-way: it announces, it does not accept decisions. A channel that could
decide needs an identity story, and "whoever can POST to this URL" is not one.

Fire and forget, with a short timeout. A notification channel that is down
must not be able to hold up a verdict — the request is already recorded in
the chain, and the queue is still there when the webhook comes back.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any

import httpx

logger = logging.getLogger(__name__)

__all__ = ["WebhookChannel", "webhook_payload"]

HTTP_TIMEOUT = 5.0

EVENTS = ("approval_requested", "approval_decided", "approval_expired")


def webhook_payload(event: str, view: dict[str, Any], **extra: Any) -> dict[str, Any]:
    """The body posted for one event.

    Carries the same fields the approver view holds minus the parameters: a
    webhook goes somewhere the gate does not control, and the request detail
    stays behind the API where it can be authenticated.
    """
    body = {k: v for k, v in view.items() if k != "params_redacted"}
    body["event"] = event
    body.update(extra)
    return body


@dataclass
class WebhookChannel:
    url: str
    client: httpx.Client | None = None

    def send(self, event: str, view: dict[str, Any], **extra: Any) -> bool:
        """Returns whether it was delivered. Never raises.

        The caller is in the middle of deciding an action. A failed
        notification is worth a log line and nothing more.
        """
        if event not in EVENTS:
            raise ValueError(f"{event!r} is not one of {EVENTS}")
        owned = self.client is None
        http = self.client or httpx.Client(timeout=HTTP_TIMEOUT)
        try:
            response = http.post(
                self.url,
                headers={"content-type": "application/json"},
                content=json.dumps(webhook_payload(event, view, **extra)).encode(),
            )
            response.raise_for_status()
            return True
        except httpx.HTTPError as exc:
            logger.warning("approval webhook to %s failed: %s", self.url, exc)
            return False
        finally:
            if owned:
                http.close()
