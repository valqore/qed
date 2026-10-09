"""How an adapter signs a request to the API (SPEC §13 auth).

The canonical string is a **wire format**: the signer and the verifier have to
agree on it byte for byte, so it gets exactly one definition, like the evidence
format in :mod:`qed.core.evidence.format`.

It lives here rather than in ``qed/api/auth.py``, where it started, for one
practical reason. The SDK is an adapter and has to sign; importing
``qed.api.auth`` to do it pulls FastAPI, Starlette, Click and Pydantic into
whatever application embedded the SDK. An SDK that drags a web framework into a
LangGraph worker is an SDK people route around, and routing around it means
their actions stop being recorded.

It cannot live in ``qed/core`` or ``qed/infra``: ``tests/evidence/test_no_hmac.py``
scans both for any mention of HMAC, because the evidence chain is Ed25519-only
and a shared-secret MAC anywhere near it would be a second, weaker path to a
signature. Adapter authentication is a different problem — a process on a
laptop proving which adapter it is, with no browser to redirect and no key to
distribute — and a MAC is the right tool for it. Keeping it out of those two
trees is what lets the invariant stay absolute.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
from typing import Final

__all__ = [
    "HEADER_ADAPTER",
    "HEADER_NONCE",
    "HEADER_SIGNATURE",
    "HEADER_TIMESTAMP",
    "canonical_string",
    "sign",
]

HEADER_ADAPTER: Final = "x-qed-adapter-id"
HEADER_TIMESTAMP: Final = "x-qed-timestamp"
HEADER_NONCE: Final = "x-qed-nonce"
HEADER_SIGNATURE: Final = "x-qed-signature"


def canonical_string(*, method: str, path: str, timestamp: str, nonce: str, body: bytes) -> bytes:
    """The exact bytes both sides MAC. Documented in ``docs/api.md``.

    Covering the method, the path and a hash of the body means a captured
    signature cannot be replayed against a different endpoint or with different
    content; covering the timestamp bounds how long a captured request stays
    usable.
    """
    digest = hashlib.sha256(body).hexdigest()
    return "\n".join([method.upper(), path, timestamp, nonce, digest]).encode("utf-8")


def sign(secret: str, canonical: bytes) -> str:
    """base64url, no padding -- safe in a header without quoting."""
    mac = hmac.new(secret.encode("utf-8"), canonical, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(mac).decode("ascii").rstrip("=")
