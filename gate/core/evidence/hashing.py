"""Record hashing (SPEC §10.1–10.2).

The hash is taken over six fields joined by the ASCII unit separator (0x1F),
never over the payload itself — only over ``payload_hash``. That is what lets a
purged record (payload set to NULL after retention) still verify forever
(ADR-005, SPEC §10.6).
"""

from __future__ import annotations

import hashlib
from datetime import datetime

from gate.core import jcs
from gate.core.schemas import rfc3339_ms

__all__ = [
    "SEPARATOR",
    "genesis_prev_hash",
    "payload_hash",
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
    return hashlib.sha256(f"gate-genesis:{instance_id}".encode()).hexdigest()
