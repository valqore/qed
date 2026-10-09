"""Verifying an inbound Slack request (SPEC §9.5).

Lives beside :mod:`qed.api.auth` rather than with the Slack client in
``qed/infra/channels`` because it is the same kind of thing: authenticating a
request that arrived from outside. ``tests/evidence/test_no_hmac.py`` scans
the kernel and the verifier for any trace of HMAC, and that boundary is worth
keeping absolute — an invariant with an exemption list is a weaker invariant.

Slack's v0 scheme *is* an HMAC, and that is Slack's choice, not ours. It
authenticates a caller; it signs no evidence. The distinction is exactly the
one the no-HMAC test's docstring already draws for adapter authentication.
"""

from __future__ import annotations

import hashlib
import hmac
import time

__all__ = ["MAX_SIGNATURE_AGE", "SlackSignatureError", "verify_slack_signature"]

#: Slack's own bound. A request older than this is a replay, whatever its
#: signature says -- the signature stays valid forever, so the timestamp is
#: the only thing that makes a captured request stop working.
MAX_SIGNATURE_AGE = 60 * 5


class SlackSignatureError(RuntimeError):
    """The request did not come from Slack, or came from Slack too long ago."""


def verify_slack_signature(
    *,
    signing_secret: str,
    timestamp: str,
    body: bytes,
    signature: str,
    now: float | None = None,
) -> None:
    """Verify ``X-Slack-Signature`` over the exact bytes received.

    The age is checked **before** the MAC: a valid signature on a replayed
    request is still a replay, and rejecting early costs nothing. The MAC
    comparison is constant time, because a fast reject leaks which prefix was
    right.
    """
    current = time.time() if now is None else now
    try:
        age = abs(current - float(timestamp))
    except (TypeError, ValueError) as exc:
        raise SlackSignatureError("the Slack timestamp header is not a number") from exc
    if age > MAX_SIGNATURE_AGE:
        raise SlackSignatureError(
            f"the Slack request is {int(age)}s old, beyond the {MAX_SIGNATURE_AGE}s "
            "window; this is a replay even if the signature is valid"
        )
    base = b"v0:" + timestamp.encode("ascii") + b":" + body
    expected = "v0=" + hmac.new(signing_secret.encode(), base, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        raise SlackSignatureError("the Slack signature does not match this body")
