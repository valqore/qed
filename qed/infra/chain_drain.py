"""Draining the outbox into the chain (SPEC §10.3, §15, ADR-004).

Every replica decides and enqueues. Exactly one chains. That is the whole
design, and the two halves of it are:

* **The lock.** ``pg_try_advisory_lock`` is session-scoped, so it is released
  the moment the holder's connection dies — which is the liveness signal a
  leader election needs, without a heartbeat, a clock, or a decision about what
  to do when the clock is wrong.
* **The batch transaction.** Each batch reads the oldest entries, assigns
  sequence numbers and previous hashes in order, signs, inserts, and deletes
  the queue rows, all in one transaction. A crash halfway rolls back and leaves
  the rows where they were, so the work is retried rather than lost or
  half-applied.

Why ≤100 per batch (SPEC §10.3): a batch is one transaction holding one write
lock, and an unbounded one would hold it for as long as the queue happened to
be. The bound turns a backlog into many short transactions instead of one long
one, so a leader that loses its lock mid-backlog loses at most one batch's
worth of progress.

**Order is `created_at, id`**, which is what SPEC §10.3 specifies, and the tie
break is not decoration: two replicas enqueueing in the same millisecond would
otherwise be chained in whatever order the database felt like, and two replays
of the same inputs would produce two different chains. The ids are ULIDs, so
they sort by time within a millisecond and the order is stable.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Final

from qed.core.evidence.record import build_record
from qed.core.schemas import EvidenceRecord
from qed.infra.chain_writer import ChainWriter, PendingRecord

__all__ = ["BATCH_LIMIT", "DrainResult", "drain_once", "drain_until_empty"]

logger = logging.getLogger("qed.infra.chain_drain")

#: SPEC §10.3. One transaction per batch.
BATCH_LIMIT: Final = 100


@dataclass(frozen=True)
class DrainResult:
    """What one pass did. Returned rather than logged so a caller can decide."""

    chained: int
    #: Entries still queued after this pass. SPEC §18's `qed_chain_lag_records`.
    remaining: int
    #: Set when the drain could not run at all, with the reason.
    skipped: str = ""

    @property
    def did_work(self) -> bool:
        return self.chained > 0


def drain_once(writer: ChainWriter, *, limit: int = BATCH_LIMIT) -> DrainResult:
    """Chain up to ``limit`` queued records, in one transaction.

    The caller must already hold the chain lock. This function does not take
    it: a drain that acquired its own lock would be a drain that could be
    started by anything, and "exactly one writer" would depend on every caller
    remembering. The leader loop owns the lock and this owns the batch.
    """
    store = writer.store
    batch = store.outbox_batch(limit)
    if not batch:
        return DrainResult(chained=0, remaining=0)

    store._conn.begin_write()
    try:
        chained = 0
        drained: list[str] = []
        for outbox_id, raw in batch:
            try:
                pending = PendingRecord.model_validate_json(raw)
            except ValueError as exc:
                # A row we cannot read is not a row to drop. Rolling back and
                # reporting it leaves the evidence where it is; deleting it
                # would turn a parsing bug into a missing record, which is the
                # one outcome the chain must never produce quietly.
                store._conn.rollback()
                logger.error("outbox entry %s is unreadable: %s", outbox_id, exc)
                return DrainResult(
                    chained=0,
                    remaining=store.outbox_depth(),
                    skipped=f"outbox entry {outbox_id} could not be parsed: {exc}",
                )

            record = _chain(writer, pending)
            store.append_evidence(
                record,
                proposal_id=pending.proposal_id,
                approval_id=pending.approval_id,
                principal_hash=pending.principal_hash,
            )
            store.record_outbox_ref(outbox_id, record.seq)
            drained.append(outbox_id)
            chained += 1

        store.delete_outbox(drained)
        store._conn.commit()
    except Exception:
        store._conn.rollback()
        raise

    remaining = store.outbox_depth()
    logger.info("chained %d record(s); %d still queued", chained, remaining)
    return DrainResult(chained=chained, remaining=remaining)


def _chain(writer: ChainWriter, pending: PendingRecord) -> EvidenceRecord:
    """Assign the sequence number and previous hash, then sign.

    Read from the store inside the batch transaction rather than carried in a
    Python variable across the loop, for the same reason week 1 gave: the
    sequence number and the previous hash belong to the database's state, and a
    cached one is a cached one that was right when it was read.
    """
    last_seq = writer.store.last_seq()
    if last_seq is None:  # pragma: no cover - genesis is written directly
        from qed.core.evidence import hashing

        seq, prev_hash = 0, hashing.genesis_prev_hash(writer.instance_id)
    else:
        previous = writer.store.last_hash()
        if previous is None:  # pragma: no cover - last_seq implies a row
            raise RuntimeError("chain has a sequence number but no last hash")
        seq, prev_hash = last_seq + 1, previous

    return build_record(
        seq=seq,
        prev_hash=prev_hash,
        type_=pending.type,
        assurance=pending.assurance,
        payload=dict(pending.payload),
        signer=writer.signer,
        mode=pending.mode,
        enforcement=pending.enforcement,
        dev=pending.dev,
        ts=pending.ts,
        # Masked at enqueue (see `ChainWriter._enqueue`). Passing the profile
        # again is harmless because masking is idempotent, and leaving it out
        # would mean a record written through the outbox was masked under a
        # different rule set from one written directly.
        masking=writer.masking,
    )


def drain_until_empty(
    writer: ChainWriter, *, limit: int = BATCH_LIMIT, max_batches: int = 1000
) -> DrainResult:
    """Keep draining until the queue is empty or ``max_batches`` is reached.

    Bounded, because an unbounded loop against a queue that something is still
    filling never returns, and a leader that never returns from a drain is a
    leader that never notices it has lost the lock.
    """
    total = 0
    for _ in range(max_batches):
        result = drain_once(writer, limit=limit)
        if result.skipped:
            return DrainResult(chained=total, remaining=result.remaining, skipped=result.skipped)
        total += result.chained
        if not result.did_work:
            return DrainResult(chained=total, remaining=result.remaining)
    return DrainResult(
        chained=total,
        remaining=writer.store.outbox_depth(),
        skipped=f"stopped after {max_batches} batches; the queue is still being filled",
    )
