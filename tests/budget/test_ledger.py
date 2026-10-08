"""The budget ledger in SQLite (SPEC §8) and the migration that carries it."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from gate.core.budget import Charge
from gate.core.schemas import Budget
from gate.infra.storage.sqlite import SqliteStore

NOW = datetime.fromisoformat("2026-10-07T12:00:00+00:00")
JTI = "01JB000000000000000000JTI0"
PRINCIPAL = "a" * 64


@pytest.fixture
def store(tmp_path: Path) -> Iterator[SqliteStore]:
    with SqliteStore(tmp_path / "gate.db") as opened:
        yield opened


class TestMigration:
    def test_opening_twice_does_not_reapply_a_migration(self, tmp_path: Path) -> None:
        """`ALTER TABLE ADD COLUMN` is not idempotent, so a second open that
        replayed 0002 would raise `duplicate column name`."""
        path = tmp_path / "gate.db"
        SqliteStore(path).close()
        SqliteStore(path).close()  # must not raise

    def test_every_migration_is_recorded_once(self, store: SqliteStore) -> None:
        rows = store._conn.execute("SELECT name FROM schema_migrations ORDER BY name").fetchall()
        names = [r["name"] for r in rows]
        assert names == sorted(names)
        assert len(names) == len(set(names))
        assert "0002_budget.sql" in names

    def test_a_database_predating_the_ledger_is_upgraded_in_place(self, tmp_path: Path) -> None:
        """Existing `.gate` directories have 0001 applied and no
        `schema_migrations`. 0001 is replayed there, which is safe because it is
        `CREATE TABLE IF NOT EXISTS` throughout, and 0002 then runs once."""
        path = tmp_path / "old.db"
        legacy = sqlite3.connect(path)
        legacy.executescript(
            (Path(__file__).parents[2] / "gate/infra/storage/migrations/0001_init.sql").read_text(
                encoding="utf-8"
            )
        )
        legacy.execute("INSERT INTO budgets (token_jti, steps_used) VALUES (?, ?)", (JTI, 7))
        legacy.commit()
        legacy.close()

        store = SqliteStore(path)
        state = store.load_budget(JTI)
        assert state is not None
        # The pre-existing usage survives; the new cap columns default to
        # uncapped rather than to something that would retroactively block.
        assert state.steps_used == 7
        assert state.budget == Budget()
        store.close()


class TestCapsAndLoad:
    def test_an_unknown_token_has_no_row(self, store: SqliteStore) -> None:
        assert store.load_budget("nope") is None

    def test_caps_round_trip(self, store: SqliteStore) -> None:
        caps = Budget(steps=10, tokens=5000, seconds=600, money_cents=250, currency="EUR")
        store.upsert_budget_caps(JTI, caps)
        state = store.load_budget(JTI)
        assert state is not None
        assert state.budget == caps

    def test_reissuing_a_token_replaces_caps_and_keeps_usage(self, store: SqliteStore) -> None:
        store.upsert_budget_caps(JTI, Budget(steps=10))
        store.charge_budget(JTI, Charge(), now=NOW)
        store.upsert_budget_caps(JTI, Budget(steps=20))
        state = store.load_budget(JTI)
        assert state is not None
        assert state.budget.steps == 20
        assert state.steps_used == 1

    def test_a_charge_does_not_widen_a_cap(self, store: SqliteStore) -> None:
        """Caps are written only by issuance. If a charge could touch them, a
        token could spend its way out of its own limit."""
        store.upsert_budget_caps(JTI, Budget(steps=2))
        store.charge_budget(JTI, Charge(), now=NOW)
        state = store.load_budget(JTI)
        assert state is not None
        assert state.budget.steps == 2


class TestCharge:
    def test_charging_an_unissued_token_creates_an_uncapped_row(self, store: SqliteStore) -> None:
        before, after = store.charge_budget(JTI, Charge(tokens=10), now=NOW)
        assert before.steps_used == 0
        assert after.steps_used == 1
        assert after.budget == Budget()

    def test_charges_accumulate_across_calls(self, store: SqliteStore) -> None:
        store.charge_budget(JTI, Charge(tokens=10, money_cents=3), now=NOW)
        store.charge_budget(JTI, Charge(tokens=5, money_cents=2), now=NOW)
        state = store.load_budget(JTI)
        assert state is not None
        assert (state.steps_used, state.tokens_used, state.money_used_cents) == (2, 15, 5)

    def test_first_seen_is_the_first_charge_not_the_issuance(self, store: SqliteStore) -> None:
        """A `seconds` budget that started at issuance would punish an agent for
        the gap between getting a token and using it."""
        store.upsert_budget_caps(JTI, Budget(seconds=600))
        assert store.load_budget(JTI).first_seen is None  # type: ignore[union-attr]
        later = NOW + timedelta(minutes=30)
        store.charge_budget(JTI, Charge(), now=later)
        assert store.load_budget(JTI).first_seen == later  # type: ignore[union-attr]

    def test_exhausted_at_records_the_first_crossing_only(self, store: SqliteStore) -> None:
        store.upsert_budget_caps(JTI, Budget(steps=1))
        store.charge_budget(JTI, Charge(), now=NOW)
        later = NOW + timedelta(minutes=5)
        store.charge_budget(JTI, Charge(), now=later)
        row = store._conn.execute(
            "SELECT exhausted_at FROM budgets WHERE token_jti = ?", (JTI,)
        ).fetchone()
        assert row["exhausted_at"].startswith("2026-10-07T12:00:00")

    def test_the_returned_before_state_is_the_one_the_charge_saw(self, store: SqliteStore) -> None:
        store.charge_budget(JTI, Charge(), now=NOW)
        before, after = store.charge_budget(JTI, Charge(), now=NOW)
        assert before.steps_used == 1
        assert after.steps_used == 2


class TestDailyAggregate:
    def test_usage_is_aggregated_per_principal_per_day(self, store: SqliteStore) -> None:
        store.charge_budget(JTI, Charge(tokens=10), now=NOW, principal_hash=PRINCIPAL)
        store.charge_budget(JTI, Charge(tokens=5), now=NOW, principal_hash=PRINCIPAL)
        assert store.daily_usage(PRINCIPAL, "2026-10-07") == (2, 15, 0)

    def test_days_are_kept_apart(self, store: SqliteStore) -> None:
        store.charge_budget(JTI, Charge(), now=NOW, principal_hash=PRINCIPAL)
        store.charge_budget(JTI, Charge(), now=NOW + timedelta(days=1), principal_hash=PRINCIPAL)
        assert store.daily_usage(PRINCIPAL, "2026-10-07")[0] == 1
        assert store.daily_usage(PRINCIPAL, "2026-10-08")[0] == 1

    def test_an_unattended_principal_is_not_aggregated(self, store: SqliteStore) -> None:
        """`human_hash` is None for a service identity; there is no principal to
        attribute the day's usage to."""
        store.charge_budget(JTI, Charge(), now=NOW, principal_hash=None)
        assert store.daily_usage(PRINCIPAL, "2026-10-07") == (0, 0, 0)


class TestAtomicity:
    def test_concurrent_charges_do_not_lose_an_update(self, tmp_path: Path) -> None:
        """Two connections to the same file, interleaved. Without the write lock
        both would read `steps_used = 0` and both would write 1."""
        path = tmp_path / "gate.db"
        one = SqliteStore(path)
        two = SqliteStore(path)
        for _ in range(10):
            one.charge_budget(JTI, Charge(), now=NOW)
            two.charge_budget(JTI, Charge(), now=NOW)
        state = one.load_budget(JTI)
        assert state is not None
        assert state.steps_used == 20
        one.close()
        two.close()

    def test_a_failed_charge_leaves_no_partial_row(self, store: SqliteStore) -> None:
        """The daily-aggregate insert is inside the same transaction as the
        usage update, so a failure there must not leave usage incremented."""
        store.charge_budget(JTI, Charge(), now=NOW, principal_hash=PRINCIPAL)
        store._conn.execute("DROP TABLE budget_daily")
        with pytest.raises(sqlite3.OperationalError):
            store.charge_budget(JTI, Charge(), now=NOW, principal_hash=PRINCIPAL)
        state = store.load_budget(JTI)
        assert state is not None
        assert state.steps_used == 1
