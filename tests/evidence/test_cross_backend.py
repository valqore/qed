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
        appended = writer.append(
            type_=type_,
            assurance=Assurance.kernel,
            payload=payload,
            ts=WHEN.replace(microsecond=index * 1000),
        )
        # These writers are deliberately direct on both backends -- the
        # comparison is about the *chain*, so both sides have to be chained the
        # same way. `record` is only None in deferred mode.
        assert appended.record is not None
        written.append(appended.record.model_dump(mode="json"))
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
        appended = writer.append(
            type_=EvidenceType.proposal, assurance=Assurance.kernel, payload={"n": 1}
        )
        assert appended.record is not None
        with pytest.raises(Exception):  # the driver's own integrity error
            postgres.append_evidence(appended.record)

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

    def test_the_daily_rollup_accumulates(self, postgres: PostgresStore) -> None:
        """`principal_hash` is what makes this a second write, to
        `budget_daily`, and it is the only upsert in the store that *adds* to
        the existing row rather than replacing it.

        It was missed here once, because this test used to omit
        `principal_hash` -- so the branch never ran on PostgreSQL and the
        statement's bare `steps_used = steps_used + excluded.steps_used`, which
        SQLite accepts and PostgreSQL calls ambiguous, reached a container. The
        argument is the whole point of the test.
        """
        from qed.core.budget import Charge
        from qed.core.schemas import Budget

        now = utcnow()
        postgres.upsert_budget_caps("jti-daily", Budget(steps=10, money_cents=500))
        for _ in range(3):
            postgres.charge_budget(
                "jti-daily",
                Charge(steps=1, tokens=7, money_cents=11),
                now=now,
                principal_hash="principal-abc",
            )
        assert postgres.daily_usage("principal-abc", rfc3339_ms(now)[:10]) == (3, 21, 33)

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
        do when the clock is wrong.

        The release is **prompt, not synchronous**. `close()` sends a terminate
        and returns; the server releases the session's advisory locks when it
        reaps that backend, and the next `pg_try_advisory_lock` can arrive
        first. This asserted the immediate retry and failed on CI while passing
        on every local run -- a race in the test, but it names a real property
        of the takeover: a crashed leader's lock frees up *shortly* after the
        crash, which is why `qed/api/leader.py` retries on an interval instead
        of once.
        """
        import time

        leader = PostgresStore(DSN)
        assert leader.try_become_leader() is True
        assert postgres.try_become_leader() is False
        leader.close()  # as a crashed replica's connection would

        deadline = time.monotonic() + 10.0
        while not postgres.try_become_leader():
            assert time.monotonic() < deadline, (
                "the lock was still held 10s after the leader's connection closed; "
                "a crashed replica would have stalled the chain for at least that long"
            )
            time.sleep(0.05)


class TestTheWholeDecisionPathRunsOnPostgres:
    """The net under every other test in this file.

    The tests above assert that the *chain* is byte-identical across backends.
    They do not exercise most of the forty-odd repository methods, and a
    statement SQLite accepts and PostgreSQL refuses is invisible until the
    method runs. One did: `charge_budget`'s daily rollup reached a container
    before anybody noticed.

    So this drives a real decision through `check_proposal`, with a budget, a
    mandate and an approval, against PostgreSQL -- the same call the API makes
    on every request. It is not a substitute for a focused test; it is the
    thing that fails first when a new statement is dialect-specific.
    """

    @pytest.fixture(autouse=True)
    def clean(self) -> Iterator[None]:
        store = PostgresStore(DSN)
        _wipe(store)
        store.close()
        yield

    def session(self, directory: Path, config: Path):  # type: ignore[no-untyped-def]
        import yaml

        from qed.infra.keys.file import init_keys
        from qed.runtime import open_session

        init_keys(directory)
        config.write_text(
            yaml.safe_dump(
                {"instance_id": INSTANCE, "evidence": {"store_env": "QED_TEST_POSTGRES_DSN"}}
            ),
            encoding="utf-8",
        )
        return open_session(directory=directory, config_path=config)

    def test_a_proposal_with_a_budget_is_decided_and_charged(self, tmp_path: Path) -> None:
        from qed.core.budget import Charge
        from qed.core.schemas import ActionProposal, Budget, BudgetState
        from qed.runtime import check_proposal, settle
        from tests.conftest import BASE_PROPOSAL, deep_merge

        session = self.session(tmp_path / "qed", tmp_path / "qed.yaml")
        try:
            proposal = ActionProposal.model_validate(
                deep_merge(BASE_PROPOSAL, {"id": "01JBPGPATH0000000000000001"})
            )
            session.store.upsert_budget_caps(
                proposal.principal.token_jti, Budget(steps=10, money_cents=1000)
            )
            outcome = check_proposal(
                session,
                proposal,
                budget=BudgetState(token_jti=proposal.principal.token_jti, steps_used=0),
            )
            assert outcome.verdict.decision.value in {"ALLOW", "BLOCK", "REQUIRE_APPROVAL"}
            assert outcome.records, "a decision with no evidence"

            # The daily rollup: the write that was missing from this file.
            session.store.charge_budget(
                proposal.principal.token_jti,
                Charge(steps=1),
                now=utcnow(),
                principal_hash="principal-xyz",
            )

            settle(session)
            assert session.store.count_evidence() >= 3
        finally:
            session.close(settle_chain=False)

    def test_the_resulting_chain_verifies(self, tmp_path: Path) -> None:
        from qed_verify.verify import load_jsonl, verify_records

        from qed.core.evidence.export.jsonl import to_jsonl
        from qed.core.schemas import ActionProposal
        from qed.infra.keys.file import PUBLIC_DIR_NAME, load_public_keys
        from qed.runtime import check_proposal, settle
        from tests.conftest import BASE_PROPOSAL, deep_merge

        directory = tmp_path / "qed"
        session = self.session(directory, tmp_path / "qed.yaml")
        try:
            for index in range(3):
                check_proposal(
                    session,
                    ActionProposal.model_validate(
                        deep_merge(BASE_PROPOSAL, {"id": f"01JBPGPATH000000000000000{index}"})
                    ),
                )
            settle(session)
            report = verify_records(
                load_jsonl(to_jsonl(session.store.iter_evidence())),
                load_public_keys(directory / PUBLIC_DIR_NAME),
                instance_id=INSTANCE,
            )
            assert report.ok, report.summary()
        finally:
            session.close(settle_chain=False)


class TestReplicasStartingAtTheSameMoment:
    """SPEC §104's rolling restart, as the thing that nearly broke it.

    Two replicas booting together both called `record_bundle`, both saw no row,
    both inserted, and the loser died on `UniqueViolation: policy_bundles_pkey`
    **before its API came up**. A simultaneous start or a rolling restart could
    therefore leave a replica refusing to serve, over a bundle the other
    replica had already recorded correctly.

    Found by starting the docker-compose HA stack, not by a test -- which is
    why there is now a test.
    """

    @pytest.fixture(autouse=True)
    def clean(self) -> Iterator[None]:
        store = PostgresStore(DSN)
        _wipe(store)
        store.close()
        yield

    def test_two_stores_can_record_the_same_bundle(self, signer) -> None:  # type: ignore[no-untyped-def]
        """One insert wins, the other is told it was not first. Neither
        raises: another replica getting there first is the normal case for
        every replica after the first, not an error."""
        now = utcnow()
        first, second = PostgresStore(DSN), PostgresStore(DSN)
        try:
            a = first.record_bundle(
                bundle_hash="b" * 64, version="1", rules_count=46, loaded_at=now
            )
            b = second.record_bundle(
                bundle_hash="b" * 64, version="1", rules_count=46, loaded_at=now
            )
            assert [a, b] == [True, False]
        finally:
            first.close()
            second.close()

    def test_four_replicas_racing_produce_one_winner(self, signer) -> None:  # type: ignore[no-untyped-def]
        """The real shape: N replicas, one bundle, exactly one `policy_loaded`
        record. More than one would claim the bundle was loaded twice; none
        would mean the chain never recorded which rules were in force."""
        from concurrent.futures import ThreadPoolExecutor

        now = utcnow()
        stores = [PostgresStore(DSN) for _ in range(4)]
        try:
            with ThreadPoolExecutor(max_workers=4) as pool:
                results = list(
                    pool.map(
                        lambda store: store.record_bundle(
                            bundle_hash="c" * 64, version="1", rules_count=46, loaded_at=now
                        ),
                        stores,
                    )
                )
        finally:
            for store in stores:
                store.close()
        assert sum(results) == 1, results

    def test_two_sessions_opening_together_both_come_up(
        self, signer, qed_dir: Path, tmp_path: Path
    ) -> None:  # type: ignore[no-untyped-def]
        """End to end: `open_session` is what calls `record_bundle`, and it is
        what was dying. Both have to return a usable session."""
        import yaml

        from qed.runtime import open_session

        config = tmp_path / "qed.yaml"
        config.write_text(
            yaml.safe_dump(
                {
                    "instance_id": INSTANCE,
                    "evidence": {"store_env": "QED_TEST_POSTGRES_DSN"},
                }
            ),
            encoding="utf-8",
        )
        sessions = []
        try:
            for _ in range(3):
                sessions.append(
                    open_session(directory=qed_dir, config_path=config, strict_policy=False)
                )
            assert len(sessions) == 3
            # Drain first: on the deferred path `policy_loaded` sits in the
            # outbox until a leader chains it, so counting chained records
            # straight after opening finds nothing -- which is correct
            # behaviour and not what this test is about.
            from qed.runtime import settle

            settle(sessions[0])
            loaded = [
                record
                for record in sessions[0].store.iter_evidence()
                if record.type is EvidenceType.policy_loaded
            ]
            assert len(loaded) == 1, f"{len(loaded)} policy_loaded records for one bundle"
        finally:
            for session in sessions:
                session.close(settle_chain=False)
