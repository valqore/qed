"""The chain's background loop (SPEC §10.3, §10.4, §104).

``tests/evidence/test_ha_outbox.py`` covers the drain -- that two replicas
produce one contiguous chain. These tests cover the *loop* around it: whether
it runs, whether it re-asks who the leader is, and whether it stops without
leaving a task or a lock behind.

The split that matters is between the loop's two jobs. **Draining** is the HA
path only. **Maintenance** -- checkpoint, publish, purge -- runs on both, so
the loop itself is always applicable, and the SQLite tests below assert that it
runs *without* an election rather than that it does not run at all.
``tests/evidence/test_checkpoints.py`` covers what maintenance does; this
covers when it is allowed to.

The PostgreSQL half needs ``QED_TEST_POSTGRES_DSN``.
"""

from __future__ import annotations

import asyncio
import os
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest
import yaml

from qed.api.leader import TICK_SECONDS, LeaderLoop
from qed.core.schemas import Assurance, EvidenceType, utcnow
from qed.infra.storage.postgres import PostgresStore
from qed.runtime import Session, open_session, settle

DSN = os.environ.get("QED_TEST_POSTGRES_DSN", "")

#: Named rather than inlined: a DSN carries a password, and the point of
#: `store_env` is that it never reaches a config file somebody commits.
DSN_ENV = "QED_TEST_POSTGRES_DSN"


def factory(directory: Path, config: Path | None = None) -> Callable[[], Session]:
    """How the loop opens its own session, as the app does it.

    A session is a database connection and a `sqlite3` connection belongs to
    the thread that opened it, so `start()` refuses without this.
    """
    return lambda: open_session(directory=directory, config_path=config, strict_policy=False)


def enqueue(session: Session, note: str) -> str:
    appended = session.writer.append(
        type_=EvidenceType.proposal, assurance=Assurance.kernel, payload={"note": note}
    )
    return appended.ref


class TestOnSqliteThereIsNoElection:
    def test_there_is_nothing_to_drain(self, qed_dir: Path) -> None:
        """One process writes its own records on the way in, so there is
        nothing queued and no lock to hold."""
        session = open_session(directory=qed_dir)
        try:
            assert session.writer.deferred is False
            assert LeaderLoop(session).drains is False
        finally:
            session.close()

    def test_the_loop_still_applies(self, qed_dir: Path) -> None:
        """Because maintenance does. A SQLite instance needs checkpoints,
        anchors and retention, and before this loop existed it got them only
        if somebody ran `qed checkpoint` by hand."""
        session = open_session(directory=qed_dir)
        try:
            assert LeaderLoop(session).applicable is True
        finally:
            session.close()

    def test_a_tick_chains_nothing_and_claims_to_be_the_writer(self, qed_dir: Path) -> None:
        """One process, one chain, no election -- so it may append, and
        `leading` says so for `/v1/status`."""
        session = open_session(directory=qed_dir)
        try:
            loop = LeaderLoop(session)
            assert loop.tick_once() == 0
            assert loop.leading is True
            assert loop.last_error == ""
        finally:
            session.close()

    @pytest.mark.asyncio
    async def test_stopping_without_a_lock_is_quiet(self, qed_dir: Path) -> None:
        session = open_session(directory=qed_dir)
        try:
            loop = LeaderLoop(session, tick=0.01, own_session=factory(qed_dir))
            loop.start()
            assert loop._thread is not None
            await loop.stop()
            assert loop._thread is None
        finally:
            session.close()

    @pytest.mark.asyncio
    async def test_stopping_something_never_started_does_not_raise(self, qed_dir: Path) -> None:
        session = open_session(directory=qed_dir)
        try:
            await LeaderLoop(session).stop()
        finally:
            session.close()


@pytest.mark.skipif(not DSN, reason="set QED_TEST_POSTGRES_DSN to run the leader tests")
class TestOnPostgres:
    @pytest.fixture(autouse=True)
    def clean(self) -> Iterator[None]:
        store = PostgresStore(DSN)
        store._conn.execute(
            "DROP SCHEMA public CASCADE; CREATE SCHEMA public; "
            "GRANT ALL ON SCHEMA public TO public;"
        )
        store.close()
        yield

    @pytest.fixture
    def session(self, qed_dir: Path, tmp_path: Path) -> Iterator[Session]:
        self.directory = qed_dir
        self.config = tmp_path / "qed.yaml"
        config = self.config
        config.write_text(yaml.safe_dump({"evidence": {"store_env": DSN_ENV}}), encoding="utf-8")
        session = open_session(directory=qed_dir, config_path=config)
        # Opening a session queues `policy_loaded` for a bundle hash this
        # database has not seen. Correct, and uninteresting here: settling it
        # up front lets each test below count only the records it enqueued.
        settle(session)
        try:
            yield session
        finally:
            # Draining here is the loop's business, not the session's: settling
            # on close would hide whether the loop ever drained anything.
            session.close(settle_chain=False)

    def test_the_loop_applies(self, session: Session) -> None:
        assert session.writer.deferred is True
        assert LeaderLoop(session).applicable is True

    def test_one_tick_chains_what_was_queued(self, session: Session) -> None:
        loop = LeaderLoop(session)
        refs = [enqueue(session, f"n{index}") for index in range(3)]
        assert session.store.outbox_depth() == 3

        assert loop.tick_once() == 3
        assert loop.leading is True
        assert loop.chained == 3
        assert session.store.outbox_depth() == 0
        # Contiguous and in enqueue order. Which numbers they are depends on
        # what the chain already held, so the shape is what is asserted.
        resolved = [session.store.resolve_outbox_ref(ref) for ref in refs]
        assert resolved == [session.store.last_seq() - 2 + offset for offset in range(3)]

    def test_an_idle_tick_costs_nothing_and_says_nothing(self, session: Session) -> None:
        loop = LeaderLoop(session)
        assert loop.tick_once() == 0
        assert loop.last_error == ""

    def test_a_follower_tick_chains_nothing(self, session: Session) -> None:
        """The lock is the whole mechanism: a replica that cannot take it does
        not append, which is what stops the chain forking."""
        leader_store = PostgresStore(DSN)
        try:
            assert leader_store.try_become_leader() is True
            enqueue(session, "queued")

            loop = LeaderLoop(session)
            assert loop.tick_once() == 0
            assert loop.leading is False
            assert session.store.outbox_depth() == 1
            # And it did not checkpoint either. A follower that ran
            # maintenance would be a second writer, which is the whole thing
            # the lock prevents.
            assert loop.checkpoints == 0
        finally:
            leader_store.close()

    def test_leadership_is_re_asked_every_tick(self, session: Session) -> None:
        """Not remembered. The lock can be lost without this process being
        told -- a connection reset, a failover, an administrator calling
        ``pg_advisory_unlock_all`` -- and a replica that kept appending on a
        remembered "I am the leader" is the one failure the lock prevents.
        """
        loop = LeaderLoop(session)
        enqueue(session, "first")
        assert loop.tick_once() == 1
        assert loop.leading is True

        # Taken away underneath it, exactly as a failover would.
        session.store.resign_leadership()
        other = PostgresStore(DSN)
        try:
            assert other.try_become_leader() is True
            enqueue(session, "second")
            assert loop.tick_once() == 0
            assert loop.leading is False, "it acted on a stale claim"
        finally:
            other.close()

    def test_a_failing_tick_is_recorded_rather_than_lost(self, session: Session) -> None:
        """A leader that stopped draining silently looks exactly like a cluster
        with nothing to do, and the only symptom would be a queue depth nobody
        was watching."""
        loop = LeaderLoop(session)
        enqueue(session, "fine")
        session.store.enqueue_outbox("01BROKEN", "{not json", created_at=utcnow())
        loop.tick_once()
        assert "01BROKEN" in loop.last_error

    @pytest.mark.asyncio
    async def test_stopping_resigns_so_the_next_replica_does_not_wait(
        self, session: Session
    ) -> None:
        """Correctness does not need this -- closing the connection releases
        the lock -- but a replica that resigns on the way out saves the next
        one from waiting for the server to notice a dead connection."""
        loop = LeaderLoop(session, tick=0.01, own_session=factory(self.directory, self.config))
        loop.start()
        assert loop._thread is not None

        for _ in range(300):
            if loop.leading:
                break
            await asyncio.sleep(0.01)
        assert loop.leading is True, "the loop never took the lock"

        await loop.stop()
        assert loop._thread is None
        assert loop.leading is False
        assert session.store.holds_leadership() is False

        follower = PostgresStore(DSN)
        try:
            assert follower.try_become_leader() is True
        finally:
            follower.close()

    @pytest.mark.asyncio
    async def test_the_running_loop_drains_on_its_own(self, session: Session) -> None:
        """What makes the deferred path work in a server: nobody calls the
        drain, the loop notices."""
        loop = LeaderLoop(session, tick=0.01, own_session=factory(self.directory, self.config))
        loop.start()
        try:
            ref = enqueue(session, "queued while running")
            for _ in range(300):
                if session.store.resolve_outbox_ref(ref) is not None:
                    break
                await asyncio.sleep(0.01)
            assert session.store.resolve_outbox_ref(ref) is not None
        finally:
            await loop.stop()

    def test_the_default_tick_is_inside_the_spec_promise(self) -> None:
        """SPEC §104 promises a replacement leader "within seconds"."""
        assert 0 < TICK_SECONDS <= 5
