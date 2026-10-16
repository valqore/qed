"""The dialect seam's own invariants (SPEC §15).

The store writes its SQL with ``?`` and converts it for psycopg on the way to
the driver. That is a sound trick with exactly one way to go wrong: a literal
``?`` inside a quoted SQL string would be rewritten into ``%s`` and the
statement would change meaning. This file holds that line, and a few others
about the seam that would otherwise be comments nobody checks.

No database needed. These are properties of the source.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

from qed.infra.storage import dialect as dialect_module
from qed.infra.storage.dialect import CHAIN_LOCK_KEY, POSTGRES, SQLITE, migrations

STORE = Path(__file__).resolve().parents[2] / "qed" / "infra" / "storage" / "store.py"


def sql_literals(path: Path) -> list[tuple[int, str]]:
    """Every string constant in the module that looks like SQL."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    keywords = re.compile(
        r"\b(SELECT|INSERT|UPDATE|DELETE|CREATE|ALTER|DROP|BEGIN|COMMIT|ROLLBACK)\b",
        re.IGNORECASE,
    )
    return [
        (node.lineno, node.value)
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and keywords.search(node.value)
    ]


class TestThePlaceholderConversionIsSafe:
    def test_the_scan_finds_the_sql(self) -> None:
        """Guards the test below against passing because it found nothing."""
        found = sql_literals(STORE)
        assert len(found) > 20, len(found)

    def test_no_sql_string_contains_a_quoted_question_mark(self) -> None:
        """The one thing that would make ``?`` -> ``%s`` wrong.

        ``WHERE note = 'why?'`` would become ``WHERE note = 'why%s'`` and bind
        a parameter into the middle of a literal.
        """
        offenders = [
            (line, text)
            for line, text in sql_literals(STORE)
            if re.search(r"'[^']*\?[^']*'|\"[^\"]*\?[^\"]*\"", text)
        ]
        assert not offenders, offenders

    def test_no_sql_string_already_uses_percent_s(self) -> None:
        """It would be converted a second time and bind twice."""
        offenders = [(line, text) for line, text in sql_literals(STORE) if "%s" in text]
        assert not offenders, offenders

    def test_sqlite_conversion_is_the_identity(self) -> None:
        sql = "SELECT * FROM evidence WHERE seq = ? AND type = ?"
        assert SQLITE.convert(sql) == sql

    def test_postgres_conversion_replaces_every_placeholder(self) -> None:
        sql = "SELECT * FROM evidence WHERE seq = ? AND type = ?"
        assert POSTGRES.convert(sql) == "SELECT * FROM evidence WHERE seq = %s AND type = %s"

    def test_a_statement_with_no_parameters_is_untouched(self) -> None:
        sql = "SELECT MAX(seq) AS m FROM evidence"
        assert POSTGRES.convert(sql) == sql


class TestTheMigrationsAreShared:
    def test_there_is_one_set(self) -> None:
        """Not one directory per dialect. The week-1 scripts sit in the SQL
        subset both engines accept, which was replayed against a real
        PostgreSQL 17 rather than taken on trust.

        Spelled out rather than counted, so adding a migration is a decision
        somebody makes here too. A schema change that nobody had to
        acknowledge is how `history_daily` came to be created by 0001 and
        never read by anything for twelve weeks.
        """
        scripts = migrations()
        assert [s.name for s in scripts] == [
            "0001_init.sql",
            "0002_budget.sql",
            "0003_mandates.sql",
            "0004_approvals.sql",
            "0005_outbox_refs.sql",
            # The first to alter an existing table, which is what the ledger
            # in `schema_migrations` was added for: SQLite has no
            # `ADD COLUMN IF NOT EXISTS`, so it must run exactly once.
            "0006_history.sql",
        ]

    def test_they_are_ordered_by_name(self) -> None:
        """The ``schema_migrations`` ledger records the file name, so name
        order is what makes an existing database's ledger still match."""
        names = [s.name for s in migrations()]
        assert names == sorted(names)

    @pytest.mark.parametrize("script", migrations(), ids=lambda p: p.name)
    def test_no_script_uses_a_dialect_only_construct(self, script: Path) -> None:
        """A short list of the ones that have actually bitten people.

        Not a SQL parser: the point is to make the next author stop and think
        about the second backend, which a failing test does and a comment at
        the top of the file demonstrably did not.
        """
        text = script.read_text(encoding="utf-8").upper()
        forbidden = {
            "AUTOINCREMENT": "SQLite only; Postgres uses GENERATED or a sequence",
            "SERIAL": "Postgres only",
            "WITHOUT ROWID": "SQLite only",
            "INSERT OR ": "SQLite only; both accept ON CONFLICT",
            "JSONB": "Postgres only",
            "DATETIME(": "SQLite only",
            "NOW()": "Postgres only; the store passes timestamps in as TEXT",
            "CURRENT_TIMESTAMP": "formats differently, and `ts` is hashed",
        }
        hits = {token: why for token, why in forbidden.items() if token in text}
        assert not hits, f"{script.name}: {hits}"


class TestTheChainLockKey:
    def test_it_is_the_value_spec_15_names(self) -> None:
        assert CHAIN_LOCK_KEY == 0x67617465 == 1734440037

    def test_the_comment_says_what_the_bytes_actually_spell(self) -> None:
        """They spell "gate", the product's former name.

        The rename pass rewrote the spec's comment to claim "qed", which those
        bytes are not. The number stayed and the comment was corrected, because
        changing the lock id is not cosmetic: two replicas on different
        versions would take two different locks, both would believe they were
        leader, and both would assign ``seq``.
        """
        assert CHAIN_LOCK_KEY.to_bytes(4, "big") == b"gate"
        source = Path(dialect_module.__file__).read_text(encoding="utf-8")
        assert '"gate"' in source
        assert "the lock id must never change" in source

    def test_migrating_uses_a_different_key_from_appending(self) -> None:
        """Holding one must not imply holding the other: a replica applying a
        migration is not a replica that may append to the chain."""
        source = Path(dialect_module.__file__).read_text(encoding="utf-8")
        del source  # the keys themselves are what matter
        from qed.infra.storage import postgres

        used = Path(postgres.__file__).read_text(encoding="utf-8")
        assert "CHAIN_LOCK_KEY + 1" in used
        assert "pg_advisory_xact_lock" in used


class TestTheDialectsDisagreeAboutLittle:
    def test_both_begin_a_write_somehow(self) -> None:
        assert SQLITE.begin_write == "BEGIN IMMEDIATE"
        assert POSTGRES.begin_write == "BEGIN"

    def test_only_postgres_runs_a_script_in_one_call(self) -> None:
        assert POSTGRES.script_in_one_call is True
        assert SQLITE.script_in_one_call is False

    def test_the_whole_dialect_is_four_fields(self) -> None:
        """If this grows, the seam is leaking and the two backends are
        drifting into two implementations."""
        from dataclasses import fields

        assert {f.name for f in fields(SQLITE)} == {
            "name",
            "placeholder",
            "begin_write",
            "script_in_one_call",
        }


class TestAskingForPostgresWithoutTheExtra:
    """The message an operator sees, in the configuration most of them have.

    `psycopg` is an optional extra, so this path fires on any install that did
    not ask for it -- including most CI cells. Absence is simulated rather than
    assumed, so the test says the same thing whether or not the extra happens
    to be installed in the environment running it.
    """

    def hide_psycopg(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import sys

        # A None in sys.modules makes `import psycopg` raise ImportError,
        # which is what an install without the extra does.
        monkeypatch.setitem(sys.modules, "psycopg", None)

    def test_it_says_what_to_install(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from qed.infra.storage.postgres import PostgresStore, PostgresUnavailable

        self.hide_psycopg(monkeypatch)
        with pytest.raises(PostgresUnavailable, match=r"valqore-qed\[postgres\]"):
            PostgresStore("postgresql://user:pass@host/db")

    def test_it_says_sqlite_needs_nothing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """So the reader knows they have a choice, not a blocker."""
        from qed.infra.storage.postgres import PostgresStore, PostgresUnavailable

        self.hide_psycopg(monkeypatch)
        with pytest.raises(PostgresUnavailable, match="SQLite needs nothing"):
            PostgresStore("postgresql://user:pass@host/db")

    def test_it_is_not_a_traceback(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """You wrote the connection string and deserve to be told, not shown a
        missing-module stack."""
        from qed.infra.storage.postgres import PostgresStore, PostgresUnavailable

        self.hide_psycopg(monkeypatch)
        with pytest.raises(PostgresUnavailable) as caught:
            PostgresStore("postgresql://user:pass@host/db")
        assert not isinstance(caught.value, ImportError)

    def test_the_dsn_is_never_echoed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """It carries a password, and this message lands in logs and in
        `qed doctor` output."""
        from qed.infra.storage.postgres import PostgresStore, PostgresUnavailable

        self.hide_psycopg(monkeypatch)
        with pytest.raises(PostgresUnavailable) as caught:
            PostgresStore("postgresql://user:sup3rsecret@host/db")
        assert "sup3rsecret" not in str(caught.value)


class TestAnUnreachableDatabaseIsAnErrorRatherThanAHang:
    """libpq has no default `connect_timeout`.

    Without one, a database that does not answer -- a wrong port, a security
    group that drops rather than refuses, a server that went away -- waits on
    the operating system's connect timeout. Measured at over a minute on
    Windows with nothing listening, and that is how it was found: a test run
    stalled with no output after the local Postgres container stopped, which
    reads exactly like a wedged process rather than a database that is down.

    `qed serve` and `qed doctor` both open the store, so the operator-visible
    symptom was a command that printed nothing for a minute. An error in ten
    seconds is strictly better: it names the cause.
    """

    @pytest.fixture
    def captured(self, monkeypatch: pytest.MonkeyPatch) -> dict[str, object]:
        """`connect`'s keyword arguments, with `import psycopg` faked.

        The import is inside `connect`, so `sys.modules` is the seam -- the
        same one the install-hint tests above use. Through the `monkeypatch`
        **fixture**, so pytest undoes it: a hand-rolled `MonkeyPatch()` here
        would leave a fake `psycopg` in `sys.modules` for every test that ran
        afterwards, and this file passing alone would prove nothing.
        """
        import sys as _sys

        seen: dict[str, object] = {}

        rows = type(_sys)("psycopg.rows")
        rows.dict_row = object()  # type: ignore[attr-defined]

        class FakePsycopg:
            Error = RuntimeError

            @staticmethod
            def connect(dsn: str, **kwargs: object) -> object:
                seen.update(kwargs)
                return object()

        monkeypatch.setitem(_sys.modules, "psycopg", FakePsycopg)
        monkeypatch.setitem(_sys.modules, "psycopg.rows", rows)
        return seen

    def test_the_connect_timeout_is_set_when_the_dsn_is_silent(
        self, captured: dict[str, object]
    ) -> None:
        from qed.infra.storage.postgres import CONNECT_TIMEOUT_S, connect

        connect("postgresql://user:pass@host/db")
        assert captured["connect_timeout"] == CONNECT_TIMEOUT_S

    def test_a_dsn_that_sets_its_own_timeout_wins(self, captured: dict[str, object]) -> None:
        """An operator who wrote a timeout meant it. A keyword argument here
        would silently override what they put in the connection string."""
        from qed.infra.storage.postgres import connect

        connect("postgresql://user:pass@host/db?connect_timeout=45")
        assert "connect_timeout" not in captured

    def test_the_bound_is_long_enough_for_libpq_to_honour(self) -> None:
        """libpq silently raises anything under two seconds to two, so a `1`
        here would be a number that does not mean what it says."""
        from qed.infra.storage.postgres import CONNECT_TIMEOUT_S

        assert CONNECT_TIMEOUT_S >= 2

    def test_the_fake_does_not_outlive_these_tests(self) -> None:
        """The guard on the fixture above: if `psycopg` is installed it is the
        real module here, and if it is not installed it is absent."""
        import sys as _sys

        module = _sys.modules.get("psycopg")
        assert module is None or getattr(module, "__name__", "") == "psycopg"
