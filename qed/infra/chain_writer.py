"""Appending to the evidence chain (ADR-004, SPEC §10.3–10.4).

Week 1 is the single-process SQLite writer: the decider appends directly inside
one transaction. The Postgres leader/outbox path (week 6) replaces this class's
``append`` and nothing else — which is why the sequence number and the previous
hash are read from the store under the same write lock that inserts the record,
rather than cached on the instance.

One chain, all event types (invariant §1.4.5). There is no second journal for
anything, including shadow-mode decisions.
"""

from __future__ import annotations

from datetime import datetime

from qed.core.evidence import hashing
from qed.core.evidence.format import CHAIN_FORMAT
from qed.core.evidence.masking import MaskingProfile
from qed.core.evidence.merkle import merkle_root
from qed.core.evidence.record import build_record
from qed.core.evidence.signing import Signer
from qed.core.schemas import (
    Assurance,
    Enforcement,
    EvidenceRecord,
    EvidenceType,
    Mode,
    SigningKeyInfo,
    utcnow,
)
from qed.infra.storage.sqlite import SqliteStore

__all__ = ["ChainWriter", "InstanceMismatch", "signer_info"]

CHECKPOINT_EVERY_RECORDS = 1000
CHECKPOINT_EVERY_SECONDS = 3600


class InstanceMismatch(RuntimeError):
    """The store belongs to a different instance id than the one configured."""


class ChainWriter:
    def __init__(
        self,
        store: SqliteStore,
        signer: Signer,
        *,
        instance_id: str,
        dev: bool = False,
        masking: MaskingProfile = "default",
    ) -> None:
        self.store = store
        self.signer = signer
        self.instance_id = instance_id
        self.dev = dev
        self.masking = masking
        recorded = store.get_meta("instance_id")
        if recorded is None:
            store.set_meta("instance_id", instance_id)
        elif recorded != instance_id:
            raise InstanceMismatch(
                f"this chain was started as {recorded!r}; the genesis hash is bound to that "
                f"identity and cannot be reused as {instance_id!r}"
            )
        store.upsert_signing_key(signer_info(signer))

    # ------------------------------------------------------------------ append

    def ensure_genesis(self) -> EvidenceRecord | None:
        """Write record 0 if the chain is empty. Returns it, or None."""
        if self.store.last_seq() is not None:
            return None
        return self._append(
            type_=EvidenceType.genesis,
            assurance=Assurance.kernel,
            payload={
                "instance_id": self.instance_id,
                "chain_format": CHAIN_FORMAT,
            },
        )

    def append(
        self,
        *,
        type_: EvidenceType,
        assurance: Assurance,
        payload: dict[str, object],
        mode: Mode | None = None,
        enforcement: Enforcement | None = None,
        proposal_id: str | None = None,
        approval_id: str | None = None,
        principal_hash: str | None = None,
        ts: datetime | None = None,
    ) -> EvidenceRecord:
        self.ensure_genesis()
        return self._append(
            type_=type_,
            assurance=assurance,
            payload=payload,
            mode=mode,
            enforcement=enforcement,
            proposal_id=proposal_id,
            approval_id=approval_id,
            principal_hash=principal_hash,
            ts=ts,
        )

    def _append(
        self,
        *,
        type_: EvidenceType,
        assurance: Assurance,
        payload: dict[str, object],
        mode: Mode | None = None,
        enforcement: Enforcement | None = None,
        proposal_id: str | None = None,
        approval_id: str | None = None,
        principal_hash: str | None = None,
        ts: datetime | None = None,
    ) -> EvidenceRecord:
        last_seq = self.store.last_seq()
        if last_seq is None:
            seq, prev_hash = 0, hashing.genesis_prev_hash(self.instance_id)
        else:
            previous = self.store.last_hash()
            if previous is None:  # pragma: no cover - last_seq implies a row
                raise RuntimeError("chain has a sequence number but no last hash")
            seq, prev_hash = last_seq + 1, previous
        record = build_record(
            seq=seq,
            prev_hash=prev_hash,
            type_=type_,
            assurance=assurance,
            payload=payload,
            signer=self.signer,
            mode=mode,
            enforcement=enforcement,
            dev=self.dev,
            ts=ts,
            masking=self.masking,
        )
        self.store.append_evidence(
            record,
            proposal_id=proposal_id,
            approval_id=approval_id,
            principal_hash=principal_hash,
        )
        return record

    # -------------------------------------------------------------- checkpoint

    def checkpoint(
        self, *, force: bool = False, now: datetime | None = None
    ) -> EvidenceRecord | None:
        """Append a checkpoint over everything since the last one (SPEC §10.4).

        The receipts of the *previous* checkpoint go into this one's payload.
        Publication results are not written back into the record they describe —
        that would be a hash cycle — so they land one checkpoint later.

        A checkpoint cannot cover itself: its own hash depends on the root it
        carries. So each range begins at the *previous checkpoint record*, which
        means every record in the chain, checkpoints included, ends up covered
        by exactly one Merkle root.
        """
        last_seq = self.store.last_seq()
        if last_seq is None:
            return None
        previous = self.store.last_checkpoint()
        start = 0 if previous is None else previous.seq_to + 1
        pending = list(self.store.iter_evidence(start, last_seq))
        if not pending:
            return None
        stamp = now if now is not None else utcnow()
        if not force and len(pending) < CHECKPOINT_EVERY_RECORDS:
            oldest = pending[0].ts
            if (stamp - oldest).total_seconds() < CHECKPOINT_EVERY_SECONDS:
                return None
        root = merkle_root([r.hash for r in pending])
        record = self.append(
            type_=EvidenceType.checkpoint,
            assurance=Assurance.kernel,
            payload={
                "from_seq": start,
                "to_seq": last_seq,
                "merkle_root": root,
                "records": len(pending),
                "previous_receipts": [],
            },
            ts=stamp,
        )
        self.store.record_checkpoint(
            seq_from=start, seq_to=last_seq, merkle_root=root, evidence_seq=record.seq
        )
        return record


def signer_info(signer: Signer) -> SigningKeyInfo:
    """What the store needs to record about an active signing key."""
    return SigningKeyInfo(key_id=signer.key_id, public_pem=signer.public_pem, created_at=utcnow())
