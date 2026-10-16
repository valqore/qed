"""The 24-hour counters, which nothing collected for twelve weeks (SPEC §5).

`AG-BUD-007` and `AG-IDN-010` have read `derived.history.*` since week 1 and
neither could ever fire. The spec said the API layer collected the snapshot;
nothing did.

Three claims carry this change, and each one has a way of being quietly false:

* **the rules can now fire.** The first test here is the one that was missing
  before: drive enough blocks past a threshold and assert the rule appears. A
  previous attempt at this guard asserted that the rules *did not* fire for a
  single proposal, which is true whether or not the counters are real -- a
  test whose assertion holds on both sides of the change it was written to
  catch.
* **the two implementations agree.** The store counts in SQL, `qed replay`
  counts over chain records, and one definition implemented twice is a place
  to drift. So they are run over the same chain and compared.
* **it is a cadence.** The point of aligning the window is that the query
  happens once per bucket rather than once per decision, and the only way to
  know is to count the queries.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from ulid import ULID

from qed.core.history import WINDOW, counts_from_records, window_for
from qed.core.schemas import ActionProposal, Decision
from qed.runtime import Session, check_proposal, collect_history, open_session
from tests.conftest import BASE_PROPOSAL, deep_merge

HUMAN = str(BASE_PROPOSAL["principal"]["human_hash"])

CONFIG = """\
instance_id: history-test
mode: enforce
history:
  refresh_seconds: {refresh}
"""


def instance(tmp_path: Path, refresh: int = 0) -> Session:
    from qed.infra.keys.file import init_keys

    state = tmp_path / "state"
    state.mkdir(exist_ok=True)
    (state / "qed.yaml").write_text(CONFIG.format(refresh=refresh), encoding="utf-8")
    init_keys(state)
    return open_session(directory=state, config_path=state / "qed.yaml", strict_policy=False)


def blocking_proposal() -> ActionProposal:
    """An action the baseline pack BLOCKs, from the same principal each time."""
    return ActionProposal.model_validate(
        deep_merge(
            BASE_PROPOSAL,
            {
                "id": str(ULID()),
                "action": {
                    "kind": "mcp_tool",
                    "name": "ec2.AuthorizeSecurityGroupIngress",
                    "target": "sg-0123456789abcdef0",
                },
                "context": {
                    "environment": "prod",
                    "blast_radius_hints": {"writes": True, "scope": "account"},
                },
            },
        )
    )


TS = "2026-10-15T11:00:00.000Z"


def _proposal(identifier: str, human: str) -> dict[str, object]:
    return {
        "type": "proposal",
        "ts": TS,
        "payload": {"proposal": {"id": identifier, "principal": {"human_hash": human}}},
    }


def _verdict(proposal_id: str, decision: str) -> dict[str, object]:
    return {
        "type": "verdict",
        "ts": TS,
        "payload": {"verdict": {"proposal_id": proposal_id, "decision": decision}},
    }


def _bundle_without_history() -> object:
    """A one-rule bundle, for asserting that no query happens."""
    from qed.core.policy.model import PolicyBundle, Rule

    return PolicyBundle(
        rules=[
            Rule(
                rule_id="LOCAL-001",
                name="Nothing to see",
                message="local",
                verdict=Decision.ALLOW,
                severity="LOW",
            )
        ],
        hash="0" * 64,
    )


class TestTheRulesCanNowFire:
    """The test that was missing. `AG-IDN-010` fires at `blocks_24h >= 5`."""

    def test_repeated_blocks_eventually_trip_the_rule(self, tmp_path: Path) -> None:
        session = instance(tmp_path)
        try:
            fired_at = None
            for index in range(8):
                outcome = check_proposal(session, blocking_proposal())
                assert outcome.verdict.decision is Decision.BLOCK
                if any(hit.rule_id == "AG-IDN-010" for hit in outcome.verdict.hits):
                    fired_at = index
                    break
        finally:
            session.close()
        # Five blocks have to be in the chain before the sixth decision sees
        # them, so the rule cannot appear before the sixth call.
        assert fired_at == 5, fired_at

    def test_a_single_action_does_not_trip_it(self, tmp_path: Path) -> None:
        """The other half: counters that were always maxed would also make the
        test above pass."""
        session = instance(tmp_path)
        try:
            outcome = check_proposal(session, blocking_proposal())
        finally:
            session.close()
        assert not any(hit.rule_id == "AG-IDN-010" for hit in outcome.verdict.hits)


class TestTheWindow:
    def test_it_is_exactly_twenty_four_hours(self) -> None:
        """The field is called `calls_24h`. A 24-hour field covering twelve
        hours would be a lie with a test behind it."""
        start, end = window_for(datetime(2026, 10, 15, 12, 34, 56, tzinfo=UTC), 60)
        assert end - start == WINDOW
        assert WINDOW.total_seconds() == 24 * 60 * 60

    def test_it_is_floored_to_the_refresh_interval(self) -> None:
        now = datetime(2026, 10, 15, 12, 34, 56, tzinfo=UTC)
        _, end = window_for(now, 60)
        assert end == datetime(2026, 10, 15, 12, 34, 0, tzinfo=UTC)

    def test_every_moment_in_one_bucket_gets_the_same_window(self) -> None:
        """This is what makes it a cadence rather than a cache, and what makes
        it replayable: the window is a pure function of the timestamp."""
        base = datetime(2026, 10, 15, 12, 34, 0, tzinfo=UTC)
        windows = {
            window_for(base + timedelta(milliseconds=offset), 60) for offset in (0, 1, 500, 59_999)
        }
        assert len(windows) == 1

    def test_the_next_bucket_is_a_different_window(self) -> None:
        base = datetime(2026, 10, 15, 12, 34, 0, tzinfo=UTC)
        assert window_for(base, 60) != window_for(base + timedelta(seconds=60), 60)

    def test_zero_means_no_alignment(self) -> None:
        """Exact to the millisecond, and a query for every decision. Still
        replayable, because the timestamp is in the record."""
        now = datetime(2026, 10, 15, 12, 34, 56, 789000, tzinfo=UTC)
        _, end = window_for(now, 0)
        assert end == now

    def test_it_is_floored_against_the_epoch_not_the_process(self) -> None:
        """Two replicas deciding in the same second must agree, and a replay
        months later must land on the same boundary -- so the alignment cannot
        be relative to anything in this process."""
        now = datetime(2026, 10, 15, 12, 34, 56, tzinfo=UTC)
        _, end = window_for(now, 300)
        assert int(end.timestamp()) % 300 == 0


class TestBothImplementationsAgree:
    """The store counts in SQL; `qed replay` counts over records.

    One definition implemented twice is a place for them to drift, and the
    drift would be invisible: a replay would report a difference in a
    history-dependent rule and an operator would go looking for tampering.
    """

    def test_the_sql_and_the_record_walk_return_the_same_numbers(self, tmp_path: Path) -> None:
        session = instance(tmp_path)
        try:
            for _ in range(7):
                check_proposal(session, blocking_proposal())

            now = datetime.now(UTC) + timedelta(seconds=1)
            start, end = window_for(now, 0)
            from_sql = session.store.history_counts(principal_hash=HUMAN, start=start, end=end)

            from qed.core.evidence.export.jsonl import to_jsonl

            records = [
                json.loads(line)
                for line in to_jsonl(session.store.iter_evidence()).splitlines()
                if line.strip()
            ]
        finally:
            session.close()

        counted, complete = counts_from_records(records, principal_hash=HUMAN, start=start, end=end)
        assert complete
        assert (counted.calls_24h, counted.blocks_24h) == from_sql
        assert counted.calls_24h == 7
        assert counted.blocks_24h == 7

    def test_a_window_that_excludes_everything_agrees_too(self, tmp_path: Path) -> None:
        """Both must agree on zero as well. A query with its comparison
        operators the wrong way round would still match the walk on a window
        that contains everything."""
        session = instance(tmp_path)
        try:
            check_proposal(session, blocking_proposal())
            ancient = datetime(2020, 1, 1, tzinfo=UTC)
            from_sql = session.store.history_counts(
                principal_hash=HUMAN, start=ancient - WINDOW, end=ancient
            )
            from qed.core.evidence.export.jsonl import to_jsonl

            records = [
                json.loads(line)
                for line in to_jsonl(session.store.iter_evidence()).splitlines()
                if line.strip()
            ]
        finally:
            session.close()
        counted, _ = counts_from_records(
            records, principal_hash=HUMAN, start=ancient - WINDOW, end=ancient
        )
        assert from_sql == (0, 0)
        assert (counted.calls_24h, counted.blocks_24h) == (0, 0)


class TestItIsACadence:
    """The query runs once per bucket per principal, not once per decision.

    That is the entire justification for aligning the window instead of asking
    for an exact count every time, and the only way to check it is to count
    the queries.
    """

    def queries(self, session: Session, monkeypatch: pytest.MonkeyPatch) -> list[object]:
        seen: list[object] = []
        real = session.store.history_counts

        def counting(**kwargs: object) -> tuple[int, int]:
            seen.append(kwargs)
            return real(**kwargs)  # type: ignore[arg-type]

        monkeypatch.setattr(session.store, "history_counts", counting)
        return seen

    def test_many_decisions_in_one_bucket_cost_one_query(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        session = instance(tmp_path, refresh=3600)
        try:
            seen = self.queries(session, monkeypatch)
            for _ in range(6):
                check_proposal(session, blocking_proposal())
        finally:
            session.close()
        assert len(seen) == 1, seen

    def test_no_alignment_means_a_query_per_decision(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """`refresh_seconds: 0` is the exact-and-expensive setting, and an
        operator choosing it should get what it says."""
        session = instance(tmp_path, refresh=0)
        try:
            seen = self.queries(session, monkeypatch)
            for _ in range(4):
                check_proposal(session, blocking_proposal())
        finally:
            session.close()
        assert len(seen) == 4, seen

    def test_a_new_bucket_drops_the_old_entries(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The cache must not grow for the life of the process. Nothing ever
        asks about a window that has passed."""
        session = instance(tmp_path, refresh=60)
        try:
            check_proposal(session, blocking_proposal())
            assert len(session.history_cache) == 1
            # Reach into the future: a different bucket, so the stale entry
            # has to go rather than accumulate.
            later = datetime.now(UTC) + timedelta(minutes=5)
            collect_history(session, HUMAN, later)
            assert len(session.history_cache) == 1
        finally:
            session.close()


class TestWhenNoQueryHappensAtAll:
    def test_a_bundle_that_reads_no_history_is_never_queried(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The counters cost a store round-trip, and SPEC §21 has a latency
        budget. A rule set that cannot look at them must not pay for them.

        The bundle is swapped rather than loaded from files, because
        `policy_paths` *adds* to the baseline pack -- which contains the two
        rules that read the counters, so no set of extra files can produce a
        bundle without them.
        """
        session = instance(tmp_path, refresh=0)
        try:
            session.bundle = _bundle_without_history()
            assert not session.bundle.reads_history
            called = False

            def explode(**kwargs: object) -> tuple[int, int]:
                nonlocal called
                called = True
                return 0, 0

            monkeypatch.setattr(session.store, "history_counts", explode)
            check_proposal(session, blocking_proposal())
        finally:
            session.close()
        assert not called

    def test_a_bundle_that_does_read_history_is_queried(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The other direction, without which the test above would pass
        against a build that never queried at all."""
        session = instance(tmp_path, refresh=0)
        try:
            assert session.bundle.reads_history
            called = False
            real = session.store.history_counts

            def counting(**kwargs: object) -> tuple[int, int]:
                nonlocal called
                called = True
                return real(**kwargs)  # type: ignore[arg-type]

            monkeypatch.setattr(session.store, "history_counts", counting)
            check_proposal(session, blocking_proposal())
        finally:
            session.close()
        assert called

    def test_an_absent_principal_is_not_counted(self, tmp_path: Path) -> None:
        """`principal_hash` is NULL for an unattended agent. Grouping every
        one of them under a single NULL identity would make "this principal
        has been blocked repeatedly" mean "some agent somewhere has been"."""
        session = instance(tmp_path)
        try:
            counters = collect_history(session, None, datetime.now(UTC))
        finally:
            session.close()
        assert (counters.calls_24h, counters.blocks_24h) == (0, 0)


class TestAStrippedPayloadIsReported:
    def test_a_purged_proposal_makes_the_count_incomplete(self) -> None:
        """Whose proposal it was is no longer knowable, so both counters
        become lower bounds and `qed replay` must call history assumed
        instead of recovered."""
        now = datetime(2026, 10, 15, 12, 0, 0, tzinfo=UTC)
        counted, complete = counts_from_records(
            [_proposal("01M5A", HUMAN), {"type": "proposal", "ts": TS, "payload": None}],
            principal_hash=HUMAN,
            start=now - WINDOW,
            end=now,
        )
        assert not complete
        assert counted.calls_24h == 1

    def test_a_purged_verdict_makes_the_count_incomplete(self) -> None:
        now = datetime(2026, 10, 15, 12, 0, 0, tzinfo=UTC)
        counted, complete = counts_from_records(
            [_proposal("01M5A", HUMAN), {"type": "verdict", "ts": TS, "payload": None}],
            principal_hash=HUMAN,
            start=now - WINDOW,
            end=now,
        )
        assert not complete
        assert counted.blocks_24h == 0

    def test_a_verdict_is_reached_through_its_proposal(self) -> None:
        """A verdict record carries no principal of its own -- it is not even
        a field of `EvidenceRecord`. The link is `proposal_id`, and getting
        that wrong would count every principal's blocks against everyone."""
        now = datetime(2026, 10, 15, 12, 0, 0, tzinfo=UTC)
        counted, complete = counts_from_records(
            [_proposal("01M5A", HUMAN), _verdict("01M5A", "BLOCK")],
            principal_hash=HUMAN,
            start=now - WINDOW,
            end=now,
        )
        assert complete
        assert (counted.calls_24h, counted.blocks_24h) == (1, 1)

    def test_another_principals_block_is_not_counted(self) -> None:
        now = datetime(2026, 10, 15, 12, 0, 0, tzinfo=UTC)
        counted, complete = counts_from_records(
            [_proposal("01M5B", "b" * 64), _verdict("01M5B", "BLOCK")],
            principal_hash=HUMAN,
            start=now - WINDOW,
            end=now,
        )
        assert complete
        assert (counted.calls_24h, counted.blocks_24h) == (0, 0)

    def test_an_allow_is_not_a_block(self) -> None:
        now = datetime(2026, 10, 15, 12, 0, 0, tzinfo=UTC)
        counted, _ = counts_from_records(
            [_proposal("01M5A", HUMAN), _verdict("01M5A", "ALLOW")],
            principal_hash=HUMAN,
            start=now - WINDOW,
            end=now,
        )
        assert (counted.calls_24h, counted.blocks_24h) == (1, 0)

    def test_a_record_outside_the_window_is_ignored(self) -> None:
        now = datetime(2026, 10, 15, 12, 0, 0, tzinfo=UTC)
        old = {**_proposal("01M5A", HUMAN), "ts": "2026-10-13T11:00:00.000Z"}
        counted, _ = counts_from_records([old], principal_hash=HUMAN, start=now - WINDOW, end=now)
        assert counted.calls_24h == 0


class TestAFailedQueryIsNotFatal:
    def test_the_kernel_still_decides(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Both rules that read these counters are `shadow` rules about a
        usage pattern. Refusing an action because a COUNT query failed would
        be the worst trade available."""
        session = instance(tmp_path)
        try:

            def explode(**kwargs: object) -> tuple[int, int]:
                raise RuntimeError("the database is having a day")

            monkeypatch.setattr(session.store, "history_counts", explode)
            outcome = check_proposal(session, blocking_proposal())
        finally:
            session.close()
        assert outcome.verdict.decision is Decision.BLOCK
