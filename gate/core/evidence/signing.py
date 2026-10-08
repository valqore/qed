"""Signing and verification (SPEC §10.2, invariant §1.4.4).

Ed25519 only. There is no HMAC code path in this package and
``tests/evidence/test_no_hmac.py`` fails the build if one appears. The service
refuses to start without a signing key; there is no development fallback key.

Signatures cover the 32 raw bytes of the record hash, encoded base64url without
padding. ``key_id`` is derived from the public key so that it is stable across
copies of the same key and cannot be set to something misleading.
"""

from __future__ import annotations

import base64
import hashlib
from typing import Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

__all__ = [
    "Signer",
    "b64u_decode",
    "b64u_encode",
    "key_id_for",
    "verify_signature",
]

ALG = "Ed25519"


def b64u_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def b64u_decode(text: str) -> bytes:
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


def key_id_for(public_key: Ed25519PublicKey) -> str:
    """Stable identifier: ``ed25519:<first 16 hex of sha256(raw public key)>``."""
    raw = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return f"ed25519:{hashlib.sha256(raw).hexdigest()[:16]}"


class Signer(Protocol):
    """What the evidence ledger needs from a key source.

    Implemented by ``gate.infra.keys.file.FileSigner`` today and by Vault
    Transit / KMS backends later. The protocol deliberately does not expose the
    private key bytes.
    """

    @property
    def key_id(self) -> str: ...

    @property
    def public_pem(self) -> str: ...

    def sign(self, message: bytes) -> str:
        """Return a base64url (unpadded) signature over ``message``."""
        ...


def verify_signature(public_key: Ed25519PublicKey, message: bytes, sig_b64u: str) -> bool:
    try:
        public_key.verify(b64u_decode(sig_b64u), message)
    except (InvalidSignature, ValueError):
        return False
    return True


def sign_with(private_key: Ed25519PrivateKey, message: bytes) -> str:
    return b64u_encode(private_key.sign(message))
