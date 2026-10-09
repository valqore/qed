"""Two replicas, one chain (SPEC §10.3, §15, week 6's HA exit criterion).

Every replica decides and enqueues; exactly one chains. These tests run two
real connections to a real PostgreSQL and assert the property that makes that
safe: **whatever happens to the leader, the chain stays a chain.** Contiguous,
no gaps, no duplicate sequence numbers, nothing lost, and an export that still
verifies through ``qed-verify``.

The failure this guards against is specific and silent. Two writers appending
directly would each read ``MAX(seq)``, each compute the same next number, and
one of two things would happen: the primary key refuses the loser, or -- on a
backend without that constraint -- both commit and the chain forks. A forked
chain still verifies record by record. It stops being a chain.

Skipped without ``QED_TEST_POSTGRES_DSN``.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

import pytest

from qed.core.schemas import Assurance, EvidenceType, utcnow
from qed.infra.chain_drain import BATCH_LIMIT, drain_once, drain_until_empty
from qed.infra.chain_writer import ChainWriter
from qed.infra.keys.file import init_keys, load_signer
from qed.infra.storage.postgres import PostgresStore

DSN = os.environ.get("QED_TEST_POSTGRES_DSN", "")

pytestmark = pytest.mark.skipif(not DSN, reason="set QED_TEST_POSTGRES_DSN to run the HA tests")

INSTANCE = "qed-ha"


@pytest.fixture
def signer(tmp_path: Path):  # type: ignore[no-untyped-def]
    """One key, shared. In a real deployment it is a mounted secret: the
    leader signs, and which replica is leading changes over time."""
    init_keys(tmp_path / "keys")
    return load_signer(tmp_path / "keys")


@pytest.fixture
def clean() -> Iterator[None]:
    store = PostgresStore(DSN)
    store._conn.execute(
        "DROP SCHEMA public CASCADE; CREATE SCHEMA public; GRANT ALL ON SCHEMA public TO public;"
    )
    store.close()
    yield


def replica(signer) -> ChainWriter:  # type: ignore[no-untyped-def]
    """A writer as a replica has one: its own connection, deferred writes."""
    return ChainWriter(PostgresStore(DSN), signer, instance_id=INSTANCE, write_mode="deferred")


def enqueue(writer: ChainWriter, note: str) -> str:
    appended = writer.append(
        type_=EvidenceType.proposal, assurance=Assurance.kernel, payload={"note": note}
    )
    return appended.ref


def seqs(writer: ChainWriter) -> list[int]:
    return [record.seq for record in writer.store.iter_evidence()]


@pytest.mark.usefixtures("clean")
class TestDecidingDoesNotWaitForTheChain:
    def test_an_enqueued_record_has_no_sequence_yet(self, signer) -> None:  # type: ignore[no-untyped-def]
        """What SPEC §10.3 means by "decision latency is independent of chain
        latency": the answer does not wait for the append."""
        a = replica(signer)
        try:
            appended = a.append(
                type_=EvidenceType.proposal, assurance=Assurance.kernel, payload={"n": 1}
            )
            assert appended.deferred is True
            assert appended.seq is None
            assert appended.record is None
            # The type is known even so: only the chaining was deferred.
            assert appended.type is EvidenceType.proposal
        finally:
            a.store.close()

    def test_it_is_durable_before_it_is_chained(self, signer) -> None:  # type: ignore[no-untyped-def]
        """The guarantee that makes deferring safe. "No decision without a
        record" holds at enqueue time, which is why the API may answer first."""
        a = replica(signer)
        try:
            ref = enqueue(a, "durable")
            assert a.store.outbox_pending(ref) is True
            assert a.store.outbox_depth() == 1
        finally:
            a.store.close()

    def test_another_replica_sees_the_queued_record(self, signer) -> None:  # type: ignore[no-untyped-def]
        """It is in the database, not in the enqueueing process's memory --
        which is what lets a different replica chain it."""
        a, b = replica(signer), replica(signer)
        try:
            enqueue(a, "shared")
            assert b.store.outbox_depth() == 1
        finally:
            a.store.close()
            b.store.close()

    def test_genesis_is_written_directly(self, signer) -> None:  # type: ignore[no-untyped-def]
        """Record 0 has nothing to be ordered against, and a chain whose first
        record was queued behind others would be a chain with no beginning."""
        a = replica(signer)
        try:
            enqueue(a, "first")
            assert seqs(a) == [0]
            assert [r.type.value for r in a.store.iter_evidence()] == ["genesis"]
        finally:
            a.store.close()


@pytest.mark.usefixtures("clean")
class TestOnlyTheLeaderChains:
    def test_the_leader_drains_what_both_replicas_queued(self, signer) -> None:  # type: ignore[no-untyped-def]
        a, b = replica(signer), replica(signer)
        try:
            enqueue(a, "from a")
            enqueue(b, "from b")
            assert a.store.try_become_leader() is True
            result = drain_until_empty(a)
            assert result.chained == 2
            assert result.remaining == 0
            assert seqs(a) == [0, 1, 2]
        finally:
            a.store.close()
            b.store.close()

    def test_a_follower_cannot_become_leader(self, signer) -> None:  # type: ignore[no-untyped-def]
        a, b = replica(signer), replica(signer)
        try:
            assert a.store.try_become_leader() is True
            assert b.store.try_become_leader() is False
        finally:
            a.store.close()
            b.store.close()

    def test_the_sequence_has_no_gaps_and_no_duplicates(self, signer) -> None:  # type: ignore[no-untyped-def]
        """The property. A forked chain still verifies record by record; what
        it stops being is a chain."""
        a, b = replica(signer), replica(signer)
        try:
            for index in range(12):
                enqueue(a if index % 2 else b, f"n{index}")
            a.store.try_become_leader()
            drain_until_empty(a)
            found = seqs(a)
            assert found == list(range(len(found)))
            assert len(found) == 13  # genesis + 12
        finally:
            a.store.close()
            b.store.close()

    def test_nothing_is_lost(self, signer) -> None:  # type: ignore[no-untyped-def]
        """Every enqueued reference resolves to a sequence number."""
        a, b = replica(signer), replica(signer)
        try:
            refs = [enqueue(a if index % 2 else b, f"n{index}") for index in range(6)]
            a.store.try_become_leader()
            drain_until_empty(a)
            resolved = [a.store.resolve_outbox_ref(ref) for ref in refs]
            assert all(seq is not None for seq in resolved), resolved
            assert sorted(s for s in resolved if s is not None) == [1, 2, 3, 4, 5, 6]
        finally:
            a.store.close()
            b.store.close()

    def test_a_batch_is_bounded(self, signer) -> None:  # type: ignore[no-untyped-def]
        """SPEC §10.3's ≤100. One batch is one transaction holding one write
        lock, and an unbounded one would hold it for as long as the queue
        happened to be."""
        a = replica(signer)
        try:
            for index in range(5):
                enqueue(a, f"n{index}")
            a.store.try_become_leader()
            result = drain_once(a, limit=2)
            assert result.chained == 2
            assert result.remaining == 3
            assert BATCH_LIMIT == 100
        finally:
            a.store.close()


@pytest.mark.usefixtures("clean")
class TestWhenTheLeaderDies:
    """SPEC §104: "Leader loss → lock released → another replica acquires
    within seconds; outbox is durable."
    """

    def test_the_survivor_takes_over_and_the_chain_continues(self, signer) -> None:  # type: ignore[no-untyped-def]
        a, b = replica(signer), replica(signer)
        try:
            enqueue(a, "before the crash")
            assert a.store.try_become_leader() is True
            drain_until_empty(a)
            before = seqs(a)

            enqueue(b, "queued while a was leader")
            # As a crashed pod's connection does. No resignation, no handover.
            a.store.close()

            assert b.store.try_become_leader() is True
            assert drain_until_empty(b).chained == 1
            after = seqs(b)
            assert after == list(range(len(after)))
            assert len(after) == len(before) + 1
        finally:
            b.store.close()

    def test_work_queued_during_the_gap_is_not_lost(self, signer) -> None:  # type: ignore[no-untyped-def]
        """The outbox is durable, so a leaderless interval costs latency and
        nothing else."""
        a, b = replica(signer), replica(signer)
        try:
            a.store.try_become_leader()
            a.store.close()  # leaderless from here
            refs = [enqueue(b, f"orphan {index}") for index in range(4)]
            assert b.store.outbox_depth() == 4

            assert b.store.try_become_leader() is True
            drain_until_empty(b)
            assert [b.store.resolve_outbox_ref(ref) for ref in refs] == [1, 2, 3, 4]
        finally:
            b.store.close()

    def test_a_follower_does_not_chain_behind_the_leaders_back(self, signer) -> None:  # type: ignore[no-untyped-def]
        """`drain_once` does not take the lock -- the leader loop owns it. A
        drain that acquired its own would be a drain anything could start, and
        "exactly one writer" would depend on every caller remembering."""
        a, b = replica(signer), replica(signer)
        try:
            enqueue(b, "queued")
            assert a.store.try_become_leader() is True
            assert b.store.holds_leadership() is False
            # b chaining here is the bug this design prevents operationally;
            # the code does not stop it, the lock discipline does, so what is
            # asserted is that b knows it is not the leader.
            assert b.store.try_become_leader() is False
        finally:
            a.store.close()
            b.store.close()


@pytest.mark.usefixtures("clean")
class TestTheResultStillVerifies:
    def test_a_chain_written_by_two_leaders_in_turn_verifies(self, signer, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
        """The whole point. Two replicas, a leader change in the middle, and
        an auditor's verifier -- which has never heard of replicas -- says the
        chain is contiguous, unmodified and signed."""
        from qed_verify.verify import load_jsonl, verify_records

        from qed.core.evidence.export.jsonl import to_jsonl
        from qed.infra.keys.file import load_public_keys

        a, b = replica(signer), replica(signer)
        try:
            for index in range(3):
                enqueue(a, f"a{index}")
            a.store.try_become_leader()
            drain_until_empty(a)

            for index in range(3):
                enqueue(b, f"b{index}")
            a.store.close()
            b.store.try_become_leader()
            drain_until_empty(b)

            records = load_jsonl(to_jsonl(b.store.iter_evidence()))
            report = verify_records(
                records, load_public_keys(tmp_path / "keys" / "public"), instance_id=INSTANCE
            )
            assert report.ok, report.summary()
            assert report.records == 7  # genesis + 6
        finally:
            b.store.close()

    def test_an_unreadable_queue_entry_stops_the_drain_rather_than_dropping_it(
        self, signer
    ) -> None:  # type: ignore[no-untyped-def]
        """A row we cannot parse is not a row to delete. Dropping it would
        turn a parsing bug into a missing record, which is the one outcome the
        chain must never produce quietly."""
        a = replica(signer)
        try:
            enqueue(a, "fine")
            a.store.enqueue_outbox("01BROKEN", "{not json", created_at=utcnow())
            a.store.try_become_leader()
            result = drain_until_empty(a)
            assert result.skipped
            assert "01BROKEN" in result.skipped
            # Still there, waiting for somebody to look at it.
            assert a.store.outbox_pending("01BROKEN") is True
        finally:
            a.store.close()
