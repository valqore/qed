"""The same chain, byte for byte, on SQLite and on PostgreSQL (SPEC §15).

This is the test the dialect seam exists to make possible, and the one that
would have caught the mistake the seam could have introduced.

The chain's whole claim is that a third party can verify an export without
trusting the instance that produced it. If the two backends disagreed about so
much as a timestamp's precision, an export from a Postgres deployment would
fail verification against the same records written on SQLite, and nobody would
notice until an auditor did. So the records are written twice, with the same
signer and the same clock, and compared field by field.

Skipped without ``QED_TEST_POSTGRES_DSN``. CI sets it from a service
container; locally, `docker run -d -p 55432:5432 -e POSTGRES_PASSWORD=qed-dev
-e POSTGRES_DB=qed postgres:17` and

    QED_TEST_POSTGRES_DSN=postgresql://postgres:qed-dev@127.0.0.1:55432/qed
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

import pytest

from qed.core.schemas import Assurance, EvidenceType, rfc3339_ms, utcnow
from qed.infra.chain_writer import ChainWriter
from qed.infra.keys.file import init_keys, load_signer
from qed.infra.storage.postgres import PostgresStore
from qed.infra.storage.store import SqliteStore

DSN = os.environ.get("QED_TEST_POSTGRES_DSN", "")

pytestmark = pytest.mark.skipif(
    not DSN, reason="set QED_TEST_POSTGRES_DSN to run the Postgres backend tests"
)

INSTANCE = "qed-cross-backend"

#: Fixed, so the two runs hash the same bytes. `ts` is inside the record hash,
#: so a test that let each backend take its own clock would compare two
#: different chains and prove nothing.
WHEN = utcnow()

PAYLOADS: list[tuple[EvidenceType, dict[str, object]]] = [
    (EvidenceType.proposal, {"n": 1, "note": "the first record"}),
    (EvidenceType.verdict, {"decision": "ALLOW", "hits": []}),
    (EvidenceType.execution_result, {"status": "ok", "duration_ms": 12.5}),
    (EvidenceType.budget_update, {"steps_used": 3}),
    # A payload with the shapes that differ between the two engines: a bool,
    # a null, a nested object, a number that is not an integer, and a string
    # with a quote in it.
    (
        EvidenceType.admin_action,
        {
            "flag": True,
            "absent": None,
            "nested": {"a": [1, 2, {"b": "c"}]},
            "ratio": 0.5,
            "quoted": 'it\'s "quoted"',
        },
    ),
]


@pytest.fixture
def postgres() -> Iterator[PostgresStore]:
    """A clean database for each test.

    Dropping and recreating every table rather than the database, because the
    connection is already open and a test that reconnected would be testing a
    different thing.
    """
    store = PostgresStore(DSN)
    _wipe(store)
    store.close()
    store = PostgresStore(DSN)
    try:
        yield store
    finally:
        store.close()


def _wipe(store: PostgresStore) -> None:
    store._conn.execute(
        "DROP SCHEMA public CASCADE; CREATE SCHEMA public; GRANT ALL ON SCHEMA public TO public;"
    )


def write_all(writer: ChainWriter) -> list[dict[str, object]]:
    """Write the fixture records and return them as the export would."""
    written = []
    for index, (type_, payload) in enumerate(PAYLOADS):
        record = writer.append(
            type_=type_,
            assurance=Assurance.kernel,
            payload=payload,
            ts=WHEN.replace(microsecond=index * 1000),
        )
        written.append(record.model_dump(mode="json"))
    return written


@pytest.fixture
def signer(tmp_path: Path):  # type: ignore[no-untyped-def]
    """One key for both backends. Two keys would make the comparison
    meaningless: the hashes would differ for an uninteresting reason."""
    directory = tmp_path / "keys"
    init_keys(directory)
    return load_signer(directory)


class TestTheChainIsByteIdenticalAcrossBackends:
    def both(self, tmp_path: Path, signer, postgres: PostgresStore):  # type: ignore[no-untyped-def]
        with SqliteStore(tmp_path / "qed.db") as sqlite:
            on_sqlite = write_all(ChainWriter(sqlite, signer, instance_id=INSTANCE))
        on_postgres = write_all(ChainWriter(postgres, signer, instance_id=INSTANCE))
        return on_sqlite, on_postgres

    def test_every_hash_matches(self, tmp_path: Path, signer, postgres: PostgresStore) -> None:
        """The one that matters. A difference here means an export from one
        deployment would not verify against records written by the other."""
        on_sqlite, on_postgres = self.both(tmp_path, signer, postgres)
        assert [r["hash"] for r in on_sqlite] == [r["hash"] for r in on_postgres]

    def test_every_prev_hash_matches(self, tmp_path: Path, signer, postgres: PostgresStore) -> None:
        on_sqlite, on_postgres = self.both(tmp_path, signer, postgres)
        assert [r["prev_hash"] for r in on_sqlite] == [r["prev_hash"] for r in on_postgres]

    def test_every_signature_matches(self, tmp_path: Path, signer, postgres: PostgresStore) -> None:
        on_sqlite, on_postgres = self.both(tmp_path, signer, postgres)
        assert [r["sig"] for r in on_sqlite] == [r["sig"] for r in on_postgres]

    def test_the_whole_record_matches(
        self, tmp_path: Path, signer, postgres: PostgresStore
    ) -> None:
        """Field by field, including the payload. A backend that coerced a
        bool to an integer or dropped a null would show up here even if the
        hashes happened to agree."""
        on_sqlite, on_postgres = self.both(tmp_path, signer, postgres)
        assert on_sqlite == on_postgres

    def test_an_export_from_postgres_verifies(
        self, tmp_path: Path, signer, postgres: PostgresStore
    ) -> None:
        """Through the real verifier, which reimplements the format on purpose
        (SPEC §10.7) and has never heard of either backend."""
        from qed_verify.verify import load_jsonl, verify_records

        from qed.core.evidence.export.jsonl import to_jsonl
        from qed.infra.keys.file import load_public_keys

        write_all(ChainWriter(postgres, signer, instance_id=INSTANCE))
        records = load_jsonl(to_jsonl(postgres.iter_evidence()))
        report = verify_records(
            records, load_public_keys(tmp_path / "keys" / "public"), instance_id=INSTANCE
        )
        assert report.ok, report.summary()
        assert report.records == len(PAYLOADS) + 1  # genesis


class TestTimestampsAreStoredAsText:
    """Because ``ts`` is hashed into the record.

    A native timestamp column would let the backend's own precision change the
    bytes -- Postgres stores microseconds, the format carries milliseconds --
    and the chain would stop being comparable across backends. The format is
    `rfc3339_ms` in both, and this pins it rather than leaving it to the DDL.
    """

    def test_postgres_round_trips_the_exact_string(self, postgres: PostgresStore) -> None:
        stamp = rfc3339_ms(WHEN)
        postgres.set_meta("probe", stamp)
        assert postgres.get_meta("probe") == stamp

    def test_the_column_really_is_text(self, postgres: PostgresStore) -> None:
        row = postgres._conn.execute(
            "SELECT data_type FROM information_schema.columns "
            "WHERE table_name = 'evidence' AND column_name = 'ts'"
        ).fetchone()
        assert row is not None
        assert row["data_type"] == "text"


class TestTheStoreBehavesTheSame:
    """A sample of the forty methods, on the backend they were not written for.

    Not a second copy of the SQLite store's tests -- those already cover the
    logic, and the logic is now literally the same code. What is worth checking
    is the handful of places the drivers could still differ: the chain's write
    lock, the atomic budget charge, and anything reading a boolean back.
    """

    def test_the_sequence_is_assigned_in_order(self, signer, postgres: PostgresStore) -> None:
        write_all(ChainWriter(postgres, signer, instance_id=INSTANCE))
        seqs = [record.seq for record in postgres.iter_evidence()]
        assert seqs == list(range(len(PAYLOADS) + 1))

    def test_a_duplicate_hash_is_refused_by_the_primary_key(
        self, signer, postgres: PostgresStore
    ) -> None:
        """What replaces SQLite's `BEGIN IMMEDIATE` on this backend: a second
        writer's insert fails rather than succeeding with a duplicate."""
        writer = ChainWriter(postgres, signer, instance_id=INSTANCE)
        record = writer.append(
            type_=EvidenceType.proposal, assurance=Assurance.kernel, payload={"n": 1}
        )
        with pytest.raises(Exception):  # the driver's own integrity error
            postgres.append_evidence(record)

    def test_a_boolean_comes_back_as_a_boolean(self, signer, postgres: PostgresStore) -> None:
        """Postgres has a real boolean type; SQLite stores 0 and 1. Both have
        to arrive as `dev=False`."""
        writer = ChainWriter(postgres, signer, instance_id=INSTANCE, dev=True)
        writer.append(type_=EvidenceType.proposal, assurance=Assurance.kernel, payload={})
        records = list(postgres.iter_evidence())
        assert all(record.dev is True for record in records)

    def test_the_budget_charge_is_atomic(self, postgres: PostgresStore) -> None:
        from qed.core.budget import Charge
        from qed.core.schemas import Budget

        postgres.upsert_budget_caps("jti-1", Budget(steps=10))
        for _ in range(5):
            postgres.charge_budget("jti-1", Charge(steps=1), now=utcnow())
        state = postgres.load_budget("jti-1")
        assert state is not None
        assert state.steps_used == 5

    def test_migrations_are_recorded_once(self, postgres: PostgresStore) -> None:
        """Opening a second store against the same database must not re-run
        them -- 0002 onwards are plain ALTERs and would fail."""
        before = [
            row["name"]
            for row in postgres._conn.execute("SELECT name FROM schema_migrations ORDER BY name")
        ]
        second = PostgresStore(DSN)
        try:
            after = [
                row["name"]
                for row in second._conn.execute("SELECT name FROM schema_migrations ORDER BY name")
            ]
        finally:
            second.close()
        assert before == after
        assert len(before) >= 4


class TestLeadership:
    """SPEC §15's `pg_try_advisory_lock`. Exactly one replica appends."""

    def test_the_first_replica_gets_it(self, postgres: PostgresStore) -> None:
        assert postgres.try_become_leader() is True
        assert postgres.holds_leadership() is True

    def test_the_second_does_not(self, postgres: PostgresStore) -> None:
        assert postgres.try_become_leader() is True
        other = PostgresStore(DSN)
        try:
            assert other.try_become_leader() is False
            assert other.holds_leadership() is False
        finally:
            other.close()

    def test_it_never_blocks(self, postgres: PostgresStore) -> None:
        """`pg_try_advisory_lock`, not `pg_advisory_lock`. A replica that
        blocked here would hang its own startup behind the leader's lifetime."""
        import time

        postgres.try_become_leader()
        other = PostgresStore(DSN)
        try:
            started = time.monotonic()
            other.try_become_leader()
            assert time.monotonic() - started < 2.0
        finally:
            other.close()

    def test_resigning_hands_over(self, postgres: PostgresStore) -> None:
        postgres.try_become_leader()
        other = PostgresStore(DSN)
        try:
            assert other.try_become_leader() is False
            postgres.resign_leadership()
            assert other.try_become_leader() is True
        finally:
            other.close()

    def test_a_dead_connection_releases_it(self, postgres: PostgresStore) -> None:
        """The reason the lock is session-scoped rather than a row in a table.
        A lease would need a heartbeat, a clock, and a decision about what to
        do when the clock is wrong."""
        leader = PostgresStore(DSN)
        assert leader.try_become_leader() is True
        assert postgres.try_become_leader() is False
        leader.close()  # as a crashed replica's connection would
        assert postgres.try_become_leader() is True
