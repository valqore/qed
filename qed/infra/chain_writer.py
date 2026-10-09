"""Appending to the evidence chain (ADR-004, SPEC §10.3–10.4).

Two ways in, one chain.

**Direct** (the default, and what SQLite always uses): the decider computes the
sequence number and the previous hash under the store's write lock, signs, and
inserts. One process, one writer, nothing to coordinate.

**Deferred** (the Postgres/HA path, SPEC §10.3): the decider writes a *pending*
record into ``evidence_outbox`` and returns. Whichever replica holds the chain
lock drains the queue in ``created_at, id`` order, assigns the sequence number
and the previous hash, signs, and inserts. Every replica can decide; exactly
one appends, so the chain cannot fork.

What makes deferring safe is that the enqueue is durable. "No decision without
a record" is satisfied the moment the outbox row commits; only the *chaining*
happens later. So the API can answer before the chain has caught up, which is
what SPEC §10.3 means by "decision latency is independent of chain latency".

What the decider cannot do is sign. The record hash covers the sequence number
and the previous hash, and both depend on where the record lands in an order no
single decider controls. So the **leader signs**, and in a multi-replica
deployment the key is used by whichever replica is currently leading.

**Masking happens at enqueue, not at drain.** The outbox is durable storage
like any other, and a payload that sat there unmasked would defeat the whole
point of masking before the hash (``qed/core/evidence/masking.py``): the raw
value would be in the database, waiting for a purge that the design exists to
avoid needing. Masking is idempotent -- there is a test -- so the drain's
second pass is harmless.

One chain, all event types (invariant §1.4.5). There is no second journal for
anything, including shadow-mode decisions.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Literal

from ulid import ULID

from qed.core.evidence import hashing
from qed.core.evidence.format import CHAIN_FORMAT
from qed.core.evidence.masking import MaskingProfile, mask_payload
from qed.core.evidence.merkle import merkle_root
from qed.core.evidence.record import build_record
from qed.core.evidence.signing import Signer
from qed.core.schemas import (
    Assurance,
    Enforcement,
    EvidenceRecord,
    EvidenceType,
    Frozen,
    Mode,
    SigningKeyInfo,
    Timestamp,
    utcnow,
)
from qed.infra.storage.store import SqlStore

__all__ = [
    "Appended",
    "ChainWriter",
    "InstanceMismatch",
    "PendingRecord",
    "WriteMode",
    "signer_info",
]

WriteMode = Literal["direct", "deferred"]

CHECKPOINT_EVERY_RECORDS = 1000
CHECKPOINT_EVERY_SECONDS = 3600


class PendingRecord(Frozen):
    """A record that is durable but not yet chained.

    Everything :func:`build_record` needs except the two fields only the
    leader can supply. Persisted as the outbox row's ``record_json``, so it is
    a format -- but an internal one: it never leaves the instance and no
    verifier reads it, which is why it lives here rather than beside the
    evidence format in ``qed/core/evidence/``.

    ``payload`` is already masked. See the module docstring.
    """

    type: EvidenceType
    assurance: Assurance
    payload: dict[str, object]
    ts: Timestamp
    dev: bool = False
    mode: Mode | None = None
    enforcement: Enforcement | None = None
    proposal_id: str | None = None
    approval_id: str | None = None
    principal_hash: str | None = None


@dataclass(frozen=True)
class Appended:
    """The result of an append, chained or not.

    ``seq`` is None exactly when the record is still in the outbox. A caller
    that needs the number either waits for the drain or hands the client the
    ``ref``, which ``GET /v1/evidence/by-ref/{id}`` resolves once the leader
    has committed it (SPEC §13).

    The alternative was to return an ``EvidenceRecord`` with a placeholder
    sequence number. A record carrying a sequence it does not have is a lie in
    the one data structure this product exists to keep honest, and it would
    have been one assignment away from reaching the chain.
    """

    #: ``str(seq)`` once chained, the outbox id while deferred.
    ref: str
    #: What was written. Known in both modes -- only the chaining is deferred,
    #: not the decision about what the record *is* -- so a caller asking
    #: "which records did this write" does not have to handle the None case
    #: for something that was never in doubt.
    type: EvidenceType
    #: The chained record. None while deferred.
    record: EvidenceRecord | None = None

    @property
    def seq(self) -> int | None:
        return None if self.record is None else self.record.seq

    @property
    def deferred(self) -> bool:
        return self.record is None


class InstanceMismatch(RuntimeError):
    """The store belongs to a different instance id than the one configured."""


class ChainWriter:
    def __init__(
        self,
        store: SqlStore,
        signer: Signer,
        *,
        instance_id: str,
        dev: bool = False,
        masking: MaskingProfile = "default",
        write_mode: WriteMode = "direct",
    ) -> None:
        self.store = store
        self.signer = signer
        self.instance_id = instance_id
        self.dev = dev
        self.masking = masking
        #: `deferred` is the Postgres/HA path: enqueue, and let the leader
        #: chain it. `direct` is one process writing for itself, which is what
        #: SQLite always is.
        self.write_mode: WriteMode = write_mode
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

    @property
    def deferred(self) -> bool:
        return self.write_mode == "deferred"

    def ensure_genesis(self, *, ts: datetime | None = None) -> EvidenceRecord | None:
        """Write record 0 if the chain is empty. Returns it, or None.

        ``ts`` for the same reason every other write path takes one: so a
        caller can be deterministic. Without it genesis was the one record
        whose timestamp nothing could pin, which made a whole chain
        irreproducible from its inputs -- every later ``prev_hash`` descends
        from it. `tests/evidence/test_cross_backend.py` is what noticed:
        the two backends produced identical records and different chains,
        because genesis had taken its own clock eight milliseconds apart.
        """
        if self.store.last_seq() is not None:
            return None
        # Written directly even in deferred mode. Genesis is record 0 and
        # every `prev_hash` descends from it, so there is nothing for a leader
        # to order it against -- and a chain whose first record was queued
        # behind other records would be a chain with no beginning.
        return self._append(
            type_=EvidenceType.genesis,
            assurance=Assurance.kernel,
            payload={
                "instance_id": self.instance_id,
                "chain_format": CHAIN_FORMAT,
            },
            ts=ts,
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
    ) -> Appended:
        """Record one event. Chained now, or queued for the leader.

        Returns :class:`Appended`, whose ``seq`` is None exactly when the
        record is still in the outbox.
        """
        # The same `ts`, so a caller who pins the first record's clock pins the
        # genesis before it too. They are two records written in one call and
        # it would be odd for one to be reproducible and the other not.
        self.ensure_genesis(ts=ts)
        if self.deferred:
            return self._enqueue(
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
        record = self._append(
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
        return Appended(ref=str(record.seq), type=record.type, record=record)

    def _enqueue(
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
    ) -> Appended:
        """Durably queue a record for the leader to chain (SPEC §10.3).

        The payload is masked here. The outbox is a table like any other, and
        a raw secret sitting in it would defeat masking's whole purpose --
        which is that the raw value never lands in the database at all, so no
        later purge is needed to remove it.
        """
        stamp = ts if ts is not None else utcnow()
        masked = mask_payload(payload, self.masking)
        pending = PendingRecord(
            type=type_,
            assurance=assurance,
            payload=masked if isinstance(masked, dict) else {"value": masked},
            ts=stamp,
            dev=self.dev,
            mode=mode,
            enforcement=enforcement,
            proposal_id=proposal_id,
            approval_id=approval_id,
            principal_hash=principal_hash,
        )
        outbox_id = str(ULID())
        self.store.enqueue_outbox(outbox_id, pending.model_dump_json(), created_at=stamp)
        return Appended(ref=outbox_id, type=type_, record=None)

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
        # Direct, even in deferred mode. A checkpoint covers a contiguous
        # range that ends at `last_seq`, and a queued checkpoint would be
        # chained after records that arrived while it waited -- so it would
        # claim a range it no longer ended, which is the one thing a
        # checkpoint must not do. The leader is the only caller.
        record = self._append(
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
