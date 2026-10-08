"""Where an approval request goes to find a person (SPEC §9.5).

A channel does two things and nothing else: it renders a request so somebody
can judge it, and it turns a click back into an identified approver. The
decision itself is always
:func:`gate.core.approval.model.decide` — a channel that decided for itself
would be a channel where separation of duties worked differently, and that is
the one place a second implementation must not exist.
"""

from __future__ import annotations

from gate.infra.channels.slack import SlackChannel, SlackError, render_blocks
from gate.infra.channels.webhook import WebhookChannel, webhook_payload

__all__ = [
    "SlackChannel",
    "SlackError",
    "WebhookChannel",
    "render_blocks",
    "webhook_payload",
]
