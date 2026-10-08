"""Adapter authentication (SPEC §13 auth, SPEC §17 "unknown adapters rejected").

An adapter signs each request with the shared secret it was registered with:

    X-Gate-Adapter-Id : adp_laptop_ali
    X-Gate-Timestamp  : 2026-10-07T12:00:00.000Z
    X-Gate-Nonce      : 01JB...                (optional, echoed into the MAC)
    X-Gate-Signature  : base64url(HMAC-SHA256(secret, canonical))

where ``canonical`` is, with ``\\n`` separators and nothing else:

    METHOD \\n path \\n timestamp \\n nonce \\n sha256-hex(body)

Covering the method, the path and the body means a captured signature cannot be
replayed against a different endpoint or with different content; covering the
timestamp bounds how long a captured request stays usable (``max_clock_skew_seconds``).

Why a shared-secret MAC and not OIDC: this is adapter identity, not human
identity. An adapter is a process on a laptop or in a CI job and has no browser
to redirect. Humans and admins arrive on an OIDC bearer in week 3, which is a
separate dependency on the same routes.

Two deliberate limits in week 2
-------------------------------

**No nonce replay cache.** Within the skew window the same signed request can be
sent twice. It does not get two decisions: ``proposal.id`` is single-use, so the
second attempt is a 409 (SPEC §17, replay). The nonce is in the MAC so that the
store arriving in week 3 needs no protocol change.

**No per-adapter rate limits.** SPEC §13's 100/s is week 10 hardening.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Final

from gate.api.problems import Problem
from gate.config import AdapterCredential, GateConfig
from gate.core.schemas import utcnow

__all__ = [
    "HEADER_ADAPTER",
    "HEADER_NONCE",
    "HEADER_SIGNATURE",
    "HEADER_TIMESTAMP",
    "AdapterAuth",
    "AuthMode",
    "canonical_string",
    "sign",
]

HEADER_ADAPTER: Final = "x-gate-adapter-id"
HEADER_TIMESTAMP: Final = "x-gate-timestamp"
HEADER_NONCE: Final = "x-gate-nonce"
HEADER_SIGNATURE: Final = "x-gate-signature"

#: Environment variable prefix used when an adapter is not in ``gate.yaml``.
#: ``GATE_ADAPTER_SECRET_ADP_LAPTOP_ALI`` for adapter id ``adp_laptop_ali``.
ENV_PREFIX: Final = "GATE_ADAPTER_SECRET_"

#: Shortest secret accepted. 32 bytes of entropy, hex or base64, is 43+ chars;
#: anything shorter is a password someone typed and is not worth guarding.
MIN_SECRET_LENGTH: Final = 32


def canonical_string(*, method: str, path: str, timestamp: str, nonce: str, body: bytes) -> bytes:
    """The exact bytes both sides MAC. Documented in ``docs/api.md``."""
    digest = hashlib.sha256(body).hexdigest()
    return "\n".join([method.upper(), path, timestamp, nonce, digest]).encode("utf-8")


def sign(secret: str, canonical: bytes) -> str:
    """base64url, no padding -- safe in a header without quoting."""
    mac = hmac.new(secret.encode("utf-8"), canonical, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(mac).decode("ascii").rstrip("=")


@dataclass(frozen=True)
class AuthMode:
    """How this process is authenticating adapters, and why."""

    #: ``signed`` | ``dev`` | ``unconfigured``
    kind: str
    adapters: tuple[str, ...] = ()
    reason: str = ""

    @property
    def usable(self) -> bool:
        return self.kind in {"signed", "dev"}


class AdapterAuth:
    """Resolves adapter secrets once at startup, then verifies each request."""

    def __init__(self, config: GateConfig, *, dev: bool = False) -> None:
        self.dev = dev
        self.max_skew = timedelta(seconds=config.api.max_clock_skew_seconds)
        self._secrets: dict[str, str] = {}
        self._problems: list[str] = []
        for entry in config.registered_adapters:
            self._load(entry)

    def _load(self, entry: AdapterCredential) -> None:
        secret = os.environ.get(entry.secret_env)
        if not secret:
            self._problems.append(
                f"adapter {entry.adapter_id} names {entry.secret_env}, which is not set"
            )
            return
        if len(secret) < MIN_SECRET_LENGTH:
            self._problems.append(
                f"adapter {entry.adapter_id}: {entry.secret_env} is shorter than "
                f"{MIN_SECRET_LENGTH} characters"
            )
            return
        self._secrets[entry.adapter_id] = secret

    @property
    def mode(self) -> AuthMode:
        if self.dev:
            return AuthMode(
                kind="dev",
                adapters=tuple(sorted(self._secrets)),
                reason=(
                    "--dev: adapter signatures are not checked. Bind to loopback only and "
                    "never run this against a real agent fleet."
                ),
            )
        if self._secrets:
            return AuthMode(kind="signed", adapters=tuple(sorted(self._secrets)))
        detail = "; ".join(self._problems) if self._problems else "no adapters are registered"
        return AuthMode(
            kind="unconfigured",
            reason=(
                f"{detail}. Register one under `adapters:` in gate.yaml with a `secret_env`, "
                "or start with --dev for local work."
            ),
        )

    # -------------------------------------------------------------- verifying

    def verify(
        self,
        *,
        method: str,
        path: str,
        headers: dict[str, str],
        body: bytes,
        now: datetime | None = None,
    ) -> str:
        """Return the authenticated ``adapter_id``, or raise :class:`Problem`.

        In ``--dev`` the adapter id is taken from the header if present and
        recorded as ``dev-unauthenticated`` if not, so a dev chain is honest
        about never having checked who was calling.
        """
        claimed = headers.get(HEADER_ADAPTER, "").strip()
        if self.dev:
            return claimed or "dev-unauthenticated"

        mode = self.mode
        if mode.kind == "unconfigured":
            raise Problem(
                status=503,
                code="adapter-auth-unconfigured",
                title="No adapter is registered",
                detail=(
                    "This instance cannot authenticate adapters, and SPEC 17 requires it to "
                    f"reject unknown ones. {mode.reason}"
                ),
            )
        if not claimed:
            raise self._unauthenticated(f"the {HEADER_ADAPTER} header is missing")
        secret = self._secrets.get(claimed)
        if secret is None:
            # Same message either way: which adapter ids exist is not something
            # an unauthenticated caller gets to enumerate (AG-IDN-005).
            raise self._unauthenticated("unknown adapter or bad signature")

        timestamp = headers.get(HEADER_TIMESTAMP, "").strip()
        signature = headers.get(HEADER_SIGNATURE, "").strip()
        nonce = headers.get(HEADER_NONCE, "").strip()
        if not timestamp or not signature:
            raise self._unauthenticated(
                f"both {HEADER_TIMESTAMP} and {HEADER_SIGNATURE} are required"
            )

        self._check_skew(timestamp, now)
        expected = sign(
            secret,
            canonical_string(method=method, path=path, timestamp=timestamp, nonce=nonce, body=body),
        )
        if not hmac.compare_digest(expected, signature):
            raise self._unauthenticated("unknown adapter or bad signature")
        return claimed

    def _check_skew(self, timestamp: str, now: datetime | None) -> None:
        try:
            sent = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        except ValueError:
            raise self._unauthenticated(
                f"{HEADER_TIMESTAMP} is not an RFC 3339 timestamp"
            ) from None
        if sent.tzinfo is None:
            raise self._unauthenticated(f"{HEADER_TIMESTAMP} has no timezone")
        reference = now if now is not None else utcnow()
        if abs(reference - sent) > self.max_skew:
            raise self._unauthenticated(
                f"{HEADER_TIMESTAMP} is more than "
                f"{int(self.max_skew.total_seconds())}s away from this server's clock"
            )

    def _unauthenticated(self, detail: str) -> Problem:
        return Problem(
            status=401,
            code="unauthenticated",
            title="The request is not authenticated",
            detail=detail,
            extra={"rule_id": "AG-IDN-005"},
        )
