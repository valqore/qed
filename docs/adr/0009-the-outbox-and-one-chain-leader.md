# ADR-0009 — Deciding is durable, chaining is deferred to one leader

**Status:** accepted · week 6 (2026-10-09)
**Implements:** SPEC §10.3 (write path), §15 (PostgreSQL backend), §104 (HA exit criterion)
**Relates to:** ADR-0005 (record encoding), ADR-0006 (format constants carry no product name)

## Context

SPEC §15 adds PostgreSQL as an evidence backend, and SPEC §104 says what that
is for: more than one replica, with "leader loss → lock released → another
replica acquires within seconds". The chain itself is the obstacle. Every
record carries `seq` and `prev_hash`, so appending means reading the tip,
computing the next link, and writing — and two replicas doing that
concurrently read the same tip.

The two outcomes are both bad and only one is loud. Either the primary key on
`hash` refuses the loser, and a decision that was already delivered has no
evidence; or, on any schema without that constraint, both commit and the chain
forks. **A forked chain still verifies record by record.** `qed-verify` walks
linkage from genesis, so it would report a break — but only on the branch it
happened to follow, and only when somebody ran it. The failure is silent at
write time, which is the worst place for it.

Serialising the append across replicas with a lock held for the duration of
each decision would fix correctness and lose the reason for having replicas:
decision latency would become chain latency plus contention, against SPEC
§18's p95 < 50 ms.

## Decision

**Split the two guarantees.** "No decision without a record" is satisfied by
durability, not by chaining. So on the PostgreSQL path a decider writes the
record into an `evidence_outbox` table in the same transaction that produced
it, and answers. Exactly one replica — whoever holds the advisory lock — later
assigns `seq`, `prev_hash`, `hash` and the signature, in batches of at most
100.

Four consequences, each chosen rather than inherited:

**The backend decides the write mode, not a flag.** `write_mode="deferred" if
config.evidence.is_postgres else "direct"`. Postgres exists in this design for
more than one replica, and more than one direct writer forks the chain; SQLite
is one process writing for itself and has nothing to coordinate. A flag would
be a way to configure the forked chain back into existence.

**The reference the caller gets is a reference, not a sequence number.**
`Appended.ref` is `str(seq)` when chained and the outbox id while queued, and
`GET /v1/evidence/by-ref/{ref}` resolves both. A queued reference answers
`200 {"seq": null, "pending": true}` and not 404: the record exists and is
durable, and a 404 would tell a caller their evidence was lost — the opposite
of true, and an integration that retried on 404 would give up on a record that
was about to arrive.

**Leadership is asked every tick, never remembered.**
`pg_try_advisory_lock`, session-scoped, re-acquired on each 2-second tick. A
remembered "I am the leader" survives a connection reset, a failover, or an
administrator running `pg_advisory_unlock_all` — and a replica appending on a
stale belief is precisely the fork the lock exists to prevent. Nor does the
loop ever *block* on the lock: a follower that blocked would hold a connection
waiting for a leader to die and then wake up holding the lock with no idea how
long it had waited.

**A one-shot command drains its own work.** `qed check`, `qed approve` and
`qed mandate sign` enqueue and exit. Without `runtime.settle()` a CLI-only
PostgreSQL deployment would have a chain that never advanced, which is not a
trade worth making for a latency benefit only a server needs. If the lock is
held, a server is running and will drain it within its tick.

## Consequences

- **Genesis and checkpoints stay direct**, even in deferred mode. Record 0 has
  nothing to be ordered against, and a chain whose first record was queued
  behind others would be a chain with no beginning.
- **Masking happens at enqueue time**, not at chaining time. The outbox is
  durable storage like any other, so an unmasked payload sitting in it would
  be exactly the leak the masking profile exists to prevent.
- **An unparseable queue row stops the drain and is reported; it is never
  deleted.** Dropping it would turn a parsing bug into a missing record, which
  is the one outcome the chain must never produce quietly.
- **Queue depth is observable**: `chain_lag_records` in `qed status` and
  `GET /v1/status` (SPEC §18's `qed_chain_lag_records`, until there is a
  `/metrics` endpoint to carry it). A depth that keeps growing means the leader
  is gone, or is losing the lock faster than it can drain.
- **Verification is unchanged.** `qed-verify` has never heard of replicas,
  outboxes or leaders, and `tests/evidence/test_ha_outbox.py` asserts that a
  chain written by two leaders in turn — with a leader killed mid-stream —
  verifies as contiguous, unmodified and signed.

## Alternatives rejected

**A lock held across the decision.** Correct, and it makes chain latency a
component of decision latency for every replica. Rejected against SPEC §18.

**`seq` from a database sequence.** Removes the collision on the number and
not the one that matters: `prev_hash` still needs the previous record's hash,
so two writers would still have to agree on an order.

**Advisory-only evidence while queued** (answer first, record later). This is
the one thing the design must not do. Durability at enqueue is what makes
deferring the *chaining* legitimate; deferring the *record* would make "no
decision without a record" false.
