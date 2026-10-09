"""Decision latency (SPEC §18, §22 week 7's exit criterion).

**p95 < 50 ms**, which is the only performance number SPEC §18 commits to.

What is measured is `check_proposal` -- the kernel, from a validated proposal
to a chained verdict -- and not an HTTP round trip. That is deliberate and it
is what the target is about: transport latency belongs to whoever runs the
network, and including it would make the number depend on the client. The
decision path is the part `qed` is responsible for, and `/metrics` measures
exactly the same span in production (`qed/api/routers/proposals.py`).

**On a timing assertion in CI.** A shared runner is noisy, so the budget is
checked against p95 rather than max, the distribution is printed on failure,
and there is a 10x margin to absorb a bad neighbour: locally this sits near
5 ms on SQLite and 11 ms on PostgreSQL. A test that fails at 45 ms would be a
test somebody disables; one that fails at 50 ms when the real number is 5 ms
only fires on a genuine regression.

Marked `perf`, so `pytest -m "not perf"` skips it. It takes about ten seconds.
"""

from __future__ import annotations

import os
import statistics
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest
import yaml
from ulid import ULID

from qed.core.schemas import ActionProposal
from qed.runtime import Session, check_proposal, open_session
from tests.conftest import BASE_PROPOSAL, deep_merge

pytestmark = pytest.mark.perf

#: Milliseconds. SPEC §18: "qed_decision_latency_seconds (histogram; target
#: p95 < 50 ms)".
BUDGET_MS = 50.0

#: Enough samples for a p95 to mean something -- the 95th of 50 samples is the
#: third-slowest, which is noise -- and few enough to run in seconds.
SAMPLES = 500
WARMUP = 50

DSN = os.environ.get("QED_TEST_POSTGRES_DSN", "")


@dataclass
class Distribution:
    samples: list[float]

    @property
    def p50(self) -> float:
        return statistics.median(self.samples)

    @property
    def p95(self) -> float:
        return sorted(self.samples)[int(len(self.samples) * 0.95)]

    @property
    def p99(self) -> float:
        return sorted(self.samples)[int(len(self.samples) * 0.99)]

    @property
    def rps(self) -> float:
        """Single-threaded. Not a throughput claim; see the module docstring
        in `test_throughput.py`."""
        return 1000.0 / statistics.mean(self.samples)

    def report(self, label: str) -> str:
        return (
            f"{label}: n={len(self.samples)} "
            f"p50={self.p50:.2f}ms p95={self.p95:.2f}ms p99={self.p99:.2f}ms "
            f"max={max(self.samples):.2f}ms "
            f"({self.rps:.0f} decisions/s, one thread)"
        )


def measure(work: Callable[[], None], *, samples: int = SAMPLES) -> Distribution:
    for _ in range(WARMUP):
        work()
    times = []
    for _ in range(samples):
        started = time.perf_counter()
        work()
        times.append((time.perf_counter() - started) * 1000)
    return Distribution(times)


def decide(session: Session) -> Callable[[], None]:
    """One decision with a fresh id, because a replayed id is a 409.

    The proposal is built inside the timed call on purpose: validating the
    document is part of deciding, and a benchmark that skipped it would
    measure something no caller ever does.
    """

    def once() -> None:
        proposal = ActionProposal.model_validate(deep_merge(BASE_PROPOSAL, {"id": str(ULID())}))
        check_proposal(session, proposal)

    return once


@pytest.fixture
def sqlite_session(qed_dir: Path) -> Iterator[Session]:
    session = open_session(directory=qed_dir, strict_policy=False)
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def postgres_session(qed_dir: Path, tmp_path: Path) -> Iterator[Session]:
    from qed.infra.storage.postgres import PostgresStore

    store = PostgresStore(DSN)
    store._conn.execute(
        "DROP SCHEMA public CASCADE; CREATE SCHEMA public; GRANT ALL ON SCHEMA public TO public;"
    )
    store.close()

    config = tmp_path / "qed.yaml"
    config.write_text(
        yaml.safe_dump(
            {"instance_id": "qed-perf", "evidence": {"store_env": "QED_TEST_POSTGRES_DSN"}}
        ),
        encoding="utf-8",
    )
    session = open_session(directory=qed_dir, config_path=config, strict_policy=False)
    try:
        yield session
    finally:
        session.close(settle_chain=False)


# --------------------------------------------------------------------------
# The exit criterion
# --------------------------------------------------------------------------


class TestTheDecisionBudget:
    def test_p95_on_sqlite(
        self, sqlite_session: Session, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """The default backend, and the one a laptop and a single-replica
        deployment both use."""
        distribution = measure(decide(sqlite_session))
        with capsys.disabled():
            print("\n" + distribution.report("sqlite  "))
        assert distribution.p95 < BUDGET_MS, distribution.report("sqlite")

    @pytest.mark.skipif(not DSN, reason="set QED_TEST_POSTGRES_DSN")
    def test_p95_on_postgres(
        self, postgres_session: Session, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Slower per decision than SQLite, and expected to be: `check_proposal`
        reads history, budget and the dedupe window, and each of those is a
        network round trip rather than a local page read. Still inside the
        budget with room to spare."""
        distribution = measure(decide(postgres_session), samples=300)
        with capsys.disabled():
            print("\n" + distribution.report("postgres"))
        assert distribution.p95 < BUDGET_MS, distribution.report("postgres")

    def test_the_budget_is_the_one_the_spec_names(self) -> None:
        assert BUDGET_MS == 50.0

    def test_the_slowest_decision_is_not_wildly_off(self, sqlite_session: Session) -> None:
        """A p95 inside budget with a 2-second outlier would be a lock
        somebody is waiting on. Generous, because one GC pause in 500 samples
        is normal and is not what this is looking for."""
        distribution = measure(decide(sqlite_session), samples=200)
        assert max(distribution.samples) < 10 * BUDGET_MS, distribution.report("sqlite")


# --------------------------------------------------------------------------
# Where the time goes
# --------------------------------------------------------------------------


class TestWhatTheChainCosts:
    """One append, so a regression can be attributed rather than just noticed.

    A decision is two records -- proposal and verdict -- so roughly twice this
    plus the policy evaluation and the store reads.
    """

    def test_one_append_on_sqlite(
        self, sqlite_session: Session, capsys: pytest.CaptureFixture[str]
    ) -> None:
        from qed.core.schemas import Assurance, EvidenceType

        writer = sqlite_session.writer

        def once() -> None:
            writer.append(type_=EvidenceType.proposal, assurance=Assurance.kernel, payload={"x": 1})

        distribution = measure(once, samples=300)
        with capsys.disabled():
            print("\n" + distribution.report("append (sqlite)  "))
        assert distribution.p95 < BUDGET_MS / 2, distribution.report("append")

    @pytest.mark.skipif(not DSN, reason="set QED_TEST_POSTGRES_DSN")
    def test_deferring_makes_an_append_faster(
        self, qed_dir: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """ADR-0009's claim, with a number on it.

        On the HA path the decider writes to the outbox and the leader chains
        it later. The append is cheaper because it skips reading the chain tip
        and computing the link -- which on PostgreSQL is two round trips rather
        than two page reads.
        """
        from qed.core.schemas import Assurance, EvidenceType
        from qed.infra.chain_writer import ChainWriter
        from qed.infra.keys.file import load_signer
        from qed.infra.storage.postgres import PostgresStore

        signer = load_signer(qed_dir)
        results: dict[str, Distribution] = {}
        for mode in ("direct", "deferred"):
            wipe = PostgresStore(DSN)
            wipe._conn.execute(
                "DROP SCHEMA public CASCADE; CREATE SCHEMA public; "
                "GRANT ALL ON SCHEMA public TO public;"
            )
            wipe.close()

            store = PostgresStore(DSN)
            writer = ChainWriter(store, signer, instance_id=f"qed-perf-{mode}", write_mode=mode)

            def once(writer: ChainWriter = writer) -> None:
                writer.append(
                    type_=EvidenceType.proposal, assurance=Assurance.kernel, payload={"x": 1}
                )

            results[mode] = measure(once, samples=300)
            store.close()

        with capsys.disabled():
            for mode, distribution in results.items():
                print("\n" + distribution.report(f"append ({mode}, pg)"))

        assert results["deferred"].p50 < results["direct"].p50, (
            "deferring did not make the append cheaper, which is the whole reason the outbox exists"
        )
