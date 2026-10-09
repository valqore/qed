"""`qed.sdk` — govern an action from inside your own code (SPEC §12.4).

The other three adapters sit in front of something: an MCP server, an HTTP
egress, a coding agent's tool call. This one is for the action that has no
front — a function in your own application that charges a card, deletes a
tenant, or calls a partner API.

```python
from qed.sdk import Qed, guard

qed = Qed.from_env()


@guard(qed, kind="custom", target="crm:accounts", summary=lambda a, kw: f"update {a[0]}")
def update_account(account_id: str, fields: dict) -> None:
    ...
```

The decorator proposes before the call, raises :class:`QedBlocked` or
:class:`QedApprovalPending` if the answer was no, runs the function, and
reports what happened. A refused action never runs.

Three things worth knowing before you use it.

**It is a client, not a kernel.** It talks to a running ``qed serve``; it does
not carry the policy engine, the signing key or the chain. An SDK that decided
locally would need the signing key in every application process, and a signing
key in an application process is a signing key in a container image.

**It is enforcing only if it is the only path.** The SDK is ADR-001's class A:
whoever can edit the code can delete the decorator. ``enforcement`` is
therefore ``advisory`` by default and the chain says so. Pass
``enforcement="enforcing"`` only when the credential the function needs comes
from the broker, so that going around QED leaves the function with nothing to
authenticate with.

**A failure is not an allow.** ``fail_mode="closed"`` is the default here,
unlike the coding-agent hook: an application calling its own payment code has
no human watching, so a QED that cannot be reached must stop the action rather
than wave it through. Set ``fail_mode="open"`` deliberately, and know that the
gap is recorded as an ``ungated_window`` when it can be, and lost when the
server is the thing that is down.
"""

from __future__ import annotations

from qed.sdk.client import (
    DEFAULT_TIMEOUT,
    Qed,
    QedApprovalPending,
    QedBlocked,
    QedError,
    QedUnavailable,
    Verdict,
    guard,
)

__all__ = [
    "DEFAULT_TIMEOUT",
    "Qed",
    "QedApprovalPending",
    "QedBlocked",
    "QedError",
    "QedUnavailable",
    "Verdict",
    "guard",
]
