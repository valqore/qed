"""Record hashing (SPEC §10.1–10.2).

The hash is taken over six fields joined by the ASCII unit separator (0x1F),
never over the payload itself — only over ``payload_hash``. That is what lets a
purged record (payload set to NULL after retention) still verify forever
(ADR-005, SPEC §10.6).
"""

from __future__ import annotations

import hashlib
from datetime import datetime

from qed.core import jcs
from qed.core.evidence.format import GENESIS_DOMAIN, PRINCIPAL_DOMAIN
from qed.core.schemas import rfc3339_ms

__all__ = [
    "PRINCIPAL_DOMAIN",
    "SEPARATOR",
    "genesis_prev_hash",
    "payload_hash",
    "principal_hash",
    "record_hash",
    "record_hash_bytes",
]

SEPARATOR = b"\x1f"


def payload_hash(payload: dict[str, object]) -> str:
    """``sha256(JCS(payload))`` as lowercase hex."""
    return jcs.sha256_hex(payload)


def record_hash_bytes(
    *,
    schema_version: str,
    seq: int,
    ts: datetime | str,
    type_: str,
    payload_hash_hex: str,
    prev_hash: str,
) -> bytes:
    """Return the 32 raw digest bytes that are hashed and then signed."""
    ts_text = ts if isinstance(ts, str) else rfc3339_ms(ts)
    parts = [
        schema_version.encode(),
        str(seq).encode(),
        ts_text.encode(),
        type_.encode(),
        payload_hash_hex.encode(),
        prev_hash.encode(),
    ]
    return hashlib.sha256(SEPARATOR.join(parts)).digest()


def record_hash(
    *,
    schema_version: str,
    seq: int,
    ts: datetime | str,
    type_: str,
    payload_hash_hex: str,
    prev_hash: str,
) -> str:
    """Hex form of :func:`record_hash_bytes`."""
    return record_hash_bytes(
        schema_version=schema_version,
        seq=seq,
        ts=ts,
        type_=type_,
        payload_hash_hex=payload_hash_hex,
        prev_hash=prev_hash,
    ).hex()


def genesis_prev_hash(instance_id: str) -> str:
    """``prev_hash`` of record 0. Ties a chain to one instance identity."""
    return hashlib.sha256(f"{GENESIS_DOMAIN}{instance_id}".encode()).hexdigest()


def principal_hash(subject: str, *, issuer: str = "") -> str:
    """``principal_hash`` for a human subject (SPEC §10.6).

    Principals appear in the chain only as a hash, so the same person must hash
    the same way whichever component wrote the record. This is the one place it
    is computed: the MCP proxy uses it for ``--human`` and the token and bearer
    paths use it for the ``sub`` claim, so a chain written across all of them
    attributes to one principal rather than several.

    ``issuer`` is the identity provider. It is part of the input because ``sub``
    is only unique within an issuer: ``ali@acme.com`` at one IdP and the same
    string at another are different people, and the hash has to say so.
    """
    return hashlib.sha256(f"{PRINCIPAL_DOMAIN}{issuer}:{subject}".encode()).hexdigest()
