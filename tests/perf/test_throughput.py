"""Throughput (SPEC §22 week 7, §849: "1k rps proposals SQLite/Postgres").

One number up front, because the spec's phrasing invites a misreading: **a
single Python replica decides on the order of 250 proposals a second**, and
1,000 is reached by running four of them. That is not a workaround; it is what
the HA path in ADR-0009 exists for, and SPEC §26 already says the fallback if
per-replica latency were the problem would be a Go hot path — which it is not,
because p95 is 5 ms against a 50 ms budget (`test_decision_latency.py`).

So this file asserts two things:

* **a floor per replica**, so a 2x regression fails a build rather than being
  noticed in a dashboard six weeks later;
* **that concurrency is safe**, which matters more than the number. Several
  replicas enqueueing at once, one leader chaining, and the result is still one
  contiguous chain that `qed-verify` accepts. A throughput figure from a run
  that silently forked the chain would be worse than no figure.

Marked `perf`.
"""

from __future__ import annotations

import os
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from ulid import ULID

from qed.core.schemas import ActionProposal, Assurance, EvidenceType
from qed.runtime import check_proposal, open_session
from tests.conftest import BASE_PROPOSAL, deep_merge

pytestmark = pytest.mark.perf

DSN = os.environ.get("QED_TEST_POSTGRES_DSN", "")

#: Decisions per second, one replica, one thread. The measured figure is ~250
#: on SQLite; a floor of 80 fails on a real regression and tolerates a shared
#: CI runner having a bad minute. A tighter floor would be a test somebody
#: disables, which protects nothing.
FLOOR_RPS = 80.0

#: Appends per second for the chain alone. Higher, because it is the hash, the
#: signature and one insert with no policy evaluation and no store reads.
APPEND_FLOOR_RPS = 300.0


def decisions(session, count: int) -> float:  # type: ignore[no-untyped-def]
    """Run `count` decisions and return decisions per second."""
    started = time.perf_counter()
    for _ in range(count):
        check_proposal(
            session,
            ActionProposal.model_validate(deep_merge(BASE_PROPOSAL, {"id": str(ULID())})),
        )
    return count / (time.perf_counter() - started)


class TestOneReplica:
    def test_the_decision_rate_has_a_floor(
        self, qed_dir: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        session = open_session(directory=qed_dir, strict_policy=False)
        try:
            decisions(session, 50)  # warm up
            rate = decisions(session, 400)
        finally:
            session.close()
        with capsys.disabled():
            print(f"\nsqlite: {rate:.0f} decisions/s, one replica, one thread")
        assert rate > FLOOR_RPS, f"{rate:.0f}/s is below the {FLOOR_RPS:.0f}/s floor"

    def test_the_append_rate_has_a_floor(
        self, qed_dir: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """The chain alone: hash, sign, insert. Separate from the decision rate
        so a regression can be attributed to the policy engine or to the
        ledger rather than to "it got slower"."""
        session = open_session(directory=qed_dir, strict_policy=False)
        try:
            for _ in range(50):
                session.writer.append(
                    type_=EvidenceType.proposal, assurance=Assurance.kernel, payload={"x": 1}
                )
            started = time.perf_counter()
            for _ in range(1000):
                session.writer.append(
                    type_=EvidenceType.proposal, assurance=Assurance.kernel, payload={"x": 1}
                )
            rate = 1000 / (time.perf_counter() - started)
        finally:
            session.close()
        with capsys.disabled():
            print(f"\nsqlite: {rate:.0f} appends/s")
        assert rate > APPEND_FLOOR_RPS, f"{rate:.0f}/s is below {APPEND_FLOOR_RPS:.0f}/s"


@pytest.mark.skipif(not DSN, reason="set QED_TEST_POSTGRES_DSN")
class TestSeveralReplicas:
    """What 1k rps actually looks like: more than one of these.

    Each "replica" here is a real session with its own connection, which is
    what a pod is. They decide concurrently; one of them later chains
    everything.
    """

    @pytest.fixture(autouse=True)
    def clean(self) -> None:
        from qed.infra.storage.postgres import PostgresStore

        store = PostgresStore(DSN)
        store._conn.execute(
            "DROP SCHEMA public CASCADE; CREATE SCHEMA public; "
            "GRANT ALL ON SCHEMA public TO public;"
        )
        store.close()

    def test_four_replicas_decide_concurrently_and_the_chain_survives(
        self, qed_dir: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """The property that makes a throughput number worth quoting.

        Four replicas enqueue at once, one drains, and `qed-verify` reads the
        result as contiguous, unmodified and signed. A figure from a run that
        silently forked the chain would be worse than no figure.
        """
        import yaml
        from qed_verify.verify import load_jsonl, verify_records

        from qed.core.evidence.export.jsonl import to_jsonl
        from qed.infra.chain_drain import drain_until_empty
        from qed.infra.keys.file import PUBLIC_DIR_NAME, load_public_keys

        config = tmp_path / "qed.yaml"
        config.write_text(
            yaml.safe_dump(
                {
                    "instance_id": "qed-perf",
                    "evidence": {"store_env": "QED_TEST_POSTGRES_DSN"},
                }
            ),
            encoding="utf-8",
        )

        replicas = [
            open_session(directory=qed_dir, config_path=config, strict_policy=False)
            for _ in range(4)
        ]
        per_replica = 60
        try:
            # Warm each one, so connection setup is not in the measurement.
            for session in replicas:
                decisions(session, 5)

            started = time.perf_counter()
            with ThreadPoolExecutor(max_workers=len(replicas)) as pool:
                futures = [pool.submit(decisions, session, per_replica) for session in replicas]
                rates = [future.result() for future in futures]
            wall = time.perf_counter() - started
            aggregate = (per_replica * len(replicas)) / wall

            leader = replicas[0]
            assert leader.store.try_become_leader()
            drained = drain_until_empty(leader.writer)
            records = load_jsonl(to_jsonl(leader.store.iter_evidence()))
        finally:
            for session in replicas:
                session.close(settle_chain=False)

        with capsys.disabled():
            print(
                f"\npostgres: {aggregate:.0f} decisions/s aggregate across "
                f"{len(replicas)} replicas "
                f"({min(rates):.0f}-{max(rates):.0f}/s each), "
                f"{drained.chained} records chained by the leader"
            )

        # The assertion that matters.
        report = verify_records(
            records, load_public_keys(qed_dir / PUBLIC_DIR_NAME), instance_id="qed-perf"
        )
        assert report.ok, report.summary()
        seqs = [int(record["seq"]) for record in records]
        assert seqs == list(range(len(seqs))), "the chain forked under concurrent load"
        assert drained.remaining == 0

    def test_more_replicas_decide_more_per_second(
        self, qed_dir: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Deliberately weak: that four replicas beat one, not by how much.

        A scaling *factor* on a shared runner with one local PostgreSQL is a
        measurement of the runner, and asserting one would be asserting
        something this test cannot see.
        """
        import yaml

        config = tmp_path / "qed.yaml"
        config.write_text(
            yaml.safe_dump(
                {"instance_id": "qed-perf", "evidence": {"store_env": "QED_TEST_POSTGRES_DSN"}}
            ),
            encoding="utf-8",
        )

        def aggregate(count: int) -> float:
            sessions = [
                open_session(directory=qed_dir, config_path=config, strict_policy=False)
                for _ in range(count)
            ]
            try:
                for session in sessions:
                    decisions(session, 5)
                started = time.perf_counter()
                with ThreadPoolExecutor(max_workers=count) as pool:
                    for future in [pool.submit(decisions, s, 40) for s in sessions]:
                        future.result()
                return (40 * count) / (time.perf_counter() - started)
            finally:
                for session in sessions:
                    session.close(settle_chain=False)

        one = aggregate(1)
        four = aggregate(4)
        with capsys.disabled():
            print(f"\npostgres: 1 replica {one:.0f}/s, 4 replicas {four:.0f}/s")
        assert four > one, f"four replicas ({four:.0f}/s) did not beat one ({one:.0f}/s)"
