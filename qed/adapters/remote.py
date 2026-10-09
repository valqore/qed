"""Submitting an already-built proposal to a QED instance (SPEC §12.5).

Every other adapter in this package builds a proposal from something it
observed -- a tool call, an HTTP request, a function invocation -- and decides
locally against a session. This module is the other shape: the proposal already
exists as a document, and the decision belongs to somebody else's instance.

That is what `qed check --server` needs, and it is the mode that makes sense in
CI. The alternative -- a local chain in the runner's workspace -- means a
signing key in CI and a chain that is deleted with the workspace, so the
evidence for a decision that gated a deployment lives for the length of one
build.

It is deliberately not :class:`qed.sdk.Qed`. The SDK's job is to *build* a
proposal from arguments, so it insists on a principal or a mandate up front; a
document that already carries its own identity has nothing to tell it. What is
left when that is stripped away is one signed POST, which is this file.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Final

import httpx

from qed.adapters.signing import (
    HEADER_ADAPTER,
    HEADER_NONCE,
    HEADER_SIGNATURE,
    HEADER_TIMESTAMP,
    canonical_string,
    sign,
)
from qed.core.schemas import ActionProposal, Decision, rfc3339_ms, utcnow

__all__ = ["DEFAULT_TIMEOUT", "RemoteError", "RemoteVerdict", "submit"]

#: Seconds. A CI step can afford to wait longer than an inline SDK call, but
#: not indefinitely: a pipeline hanging on an unreachable QED is worse than one
#: that fails and says why.
DEFAULT_TIMEOUT: Final = 15.0

PROPOSALS: Final = "/v1/proposals"


class RemoteError(RuntimeError):
    """The instance could not be reached, or refused the request itself.

    Distinct from a BLOCK, which is the instance working correctly. A caller
    that treated them alike would let an unreachable QED read as a refusal --
    or, worse, a refusal read as a network blip worth retrying past.
    """


@dataclass(frozen=True)
class RemoteVerdict:
    decision: Decision
    #: What the API returned for this proposal. A sequence number on the direct
    #: path, an outbox id while a chain leader has yet to pick it up (ADR-0009)
    #: -- either way it is what resolves through `GET /v1/evidence/by-ref/`.
    evidence_ref: str
    #: True when the instance is in shadow mode, so the decision was recorded
    #: and not applied. A pipeline that failed on a shadow BLOCK would make
    #: shadow mode useless for finding out what a policy would do.
    enforced: bool
    approval_id: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def effective_decision(self) -> Decision:
        return self.decision if self.enforced else Decision.ALLOW


def submit(
    proposal: ActionProposal,
    *,
    url: str,
    adapter_id: str,
    adapter_secret: str,
    timeout: float = DEFAULT_TIMEOUT,
    client: httpx.Client | None = None,
) -> RemoteVerdict:
    """POST the proposal and return what the instance decided.

    Raises :class:`RemoteError` for anything that is not a verdict, including
    an HTTP error status: there is no "probably allowed" to fall back on, and a
    caller silently treating a 500 as an ALLOW is the failure this whole
    project exists to prevent.
    """
    base = url.rstrip("/")
    raw = proposal.model_dump_json().encode("utf-8")
    timestamp = rfc3339_ms(utcnow())
    headers = {
        "content-type": "application/json",
        HEADER_ADAPTER: adapter_id,
        HEADER_TIMESTAMP: timestamp,
        HEADER_NONCE: "",
        HEADER_SIGNATURE: sign(
            adapter_secret,
            canonical_string(
                method="POST", path=PROPOSALS, timestamp=timestamp, nonce="", body=raw
            ),
        ),
    }

    http = client or httpx.Client(timeout=timeout)
    try:
        response = http.post(f"{base}{PROPOSALS}", content=raw, headers=headers)
    except httpx.HTTPError as exc:
        raise RemoteError(f"could not reach QED at {base}: {exc}") from exc
    finally:
        if client is None:
            http.close()

    try:
        document = response.json()
    except ValueError:
        document = {}
    if not isinstance(document, dict):
        document = {}

    if response.status_code >= 400:
        # RFC 9457 problem+json. `detail` is the field written for a person, so
        # it is what the error carries rather than a status code the operator
        # would have to look up.
        detail = document.get("detail") or document.get("title") or response.text[:200]
        raise RemoteError(f"QED answered {response.status_code}: {detail}")

    verdict = document.get("verdict")
    if not isinstance(verdict, dict) or "decision" not in verdict:
        raise RemoteError(
            f"QED answered {response.status_code} with no verdict. Body: "
            f"{json.dumps(document)[:200]}"
        )

    try:
        decision = Decision(str(verdict["decision"]))
    except ValueError as exc:
        raise RemoteError(f"unknown decision {verdict['decision']!r} from {base}") from exc

    approval = document.get("approval")
    return RemoteVerdict(
        decision=decision,
        evidence_ref=str(document.get("evidence_ref", "")),
        # Absent means enforcing: an older instance that does not report the
        # field is not a reason to assume its decisions are advisory.
        enforced=bool(document.get("enforced", True)),
        approval_id=(
            str(approval.get("approval_id")) if isinstance(approval, dict) and approval else None
        ),
        raw=document,
    )
