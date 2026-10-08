"""Building evidence records (SPEC §3.5, §10.2).

SPEC §10.2 requires ``assurance``, ``mode``, ``enforcement``, ``dev`` and
``key_id`` to live *inside* the payload as well as in their own columns, so that
``payload_hash`` covers them. They are written as reserved top-level keys with a
leading underscore; a caller payload that uses one of those names is rejected
rather than silently overwritten.

Masking runs before hashing, so a secret never reaches ``payload_hash`` in the
clear and no purge is needed to remove it.
"""

from __future__ import annotations

from datetime import datetime

from gate.core.evidence import hashing
from gate.core.evidence.masking import MaskingProfile, mask_payload
from gate.core.evidence.signing import Signer
from gate.core.schemas import (
    SCHEMA_VERSION,
    Assurance,
    Enforcement,
    EvidenceRecord,
    EvidenceType,
    Mode,
    rfc3339_ms,
    utcnow,
)

__all__ = ["RESERVED_KEYS", "build_record", "recompute_hash"]

RESERVED_KEYS = frozenset({"_assurance", "_mode", "_enforcement", "_dev", "_key_id"})


def build_record(
    *,
    seq: int,
    prev_hash: str,
    type_: EvidenceType,
    assurance: Assurance,
    payload: dict[str, object],
    signer: Signer,
    mode: Mode | None = None,
    enforcement: Enforcement | None = None,
    dev: bool = False,
    ts: datetime | None = None,
    masking: MaskingProfile = "default",
) -> EvidenceRecord:
    """Mask, hash, sign and return one record. Pure apart from the clock."""
    collisions = RESERVED_KEYS & set(payload)
    if collisions:
        raise ValueError(f"payload may not use reserved keys: {sorted(collisions)}")

    masked = mask_payload(payload, masking)
    if not isinstance(masked, dict):  # pragma: no cover - mask_payload preserves dicts
        raise TypeError("masked payload is not a mapping")

    full: dict[str, object] = dict(masked)
    full["_assurance"] = assurance.value
    full["_mode"] = mode.value if mode is not None else None
    full["_enforcement"] = enforcement.value if enforcement is not None else None
    full["_dev"] = dev
    full["_key_id"] = signer.key_id

    stamp = ts if ts is not None else utcnow()
    ts_text = rfc3339_ms(stamp)
    ph = hashing.payload_hash(full)
    digest = hashing.record_hash_bytes(
        schema_version=SCHEMA_VERSION,
        seq=seq,
        ts=ts_text,
        type_=type_.value,
        payload_hash_hex=ph,
        prev_hash=prev_hash,
    )
    return EvidenceRecord(
        seq=seq,
        ts=stamp,
        type=type_,
        assurance=assurance,
        mode=mode,
        enforcement=enforcement,
        dev=dev,
        payload_hash=ph,
        payload=full,
        prev_hash=prev_hash,
        hash=digest.hex(),
        key_id=signer.key_id,
        sig=signer.sign(digest),
    )


def recompute_hash(record: EvidenceRecord) -> str:
    """Recompute a record's hash from its own fields. Works on purged records."""
    return hashing.record_hash(
        schema_version=record.schema_version,
        seq=record.seq,
        ts=record.ts,
        type_=record.type.value,
        payload_hash_hex=record.payload_hash,
        prev_hash=record.prev_hash,
    )
