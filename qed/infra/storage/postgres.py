"""The PostgreSQL backend (SPEC §15, §10.3).

Every repository method comes from :class:`~qed.infra.storage.store.SqlStore`;
this module owns the connection and nothing else. That is the whole point of
the dialect seam: there is one implementation of the chain's append path, so it
cannot behave differently depending on which database somebody deployed.

Why Postgres at all, when SQLite runs the whole product on a laptop: SPEC §22
week 6 wants more than one replica, and more than one replica needs a store
they can share and a way to agree on who appends. The second half is the chain
leader (SPEC §10.3) and the advisory lock in
:mod:`qed.infra.storage.dialect`.

``psycopg`` is an optional extra. Asking for Postgres without it installed says
what to install rather than raising a missing-module traceback — you wrote the
connection string and deserve to be told.
"""

from __future__ import annotations

from typing import Any, Final

from qed.infra.storage.dialect import CHAIN_LOCK_KEY, POSTGRES
from qed.infra.storage.store import Connection, SqlStore

__all__ = ["PostgresStore", "PostgresUnavailable", "connect"]

#: What the API's readiness probe reports when Postgres was asked for and is
#: not installed. Not a crash: an operator fixes this with one pip install.
INSTALL_HINT: Final = (
    "PostgreSQL support is an optional extra. Install it with:\n"
    "    pip install 'valqore-qed[postgres]'\n"
    "SQLite needs nothing and runs the whole product on one machine; Postgres is "
    "for more than one replica (SPEC 15)."
)


class PostgresUnavailable(RuntimeError):
    """``psycopg`` is not installed, or the server cannot be reached."""


def connect(dsn: str) -> Any:
    """Open an autocommit connection with name-addressable rows.

    ``autocommit=True`` so that the explicit ``BEGIN`` / ``COMMIT`` in
    :meth:`SqlStore.append_evidence` is the only transaction boundary, matching
    SQLite's ``isolation_level=None``. With psycopg's default, the driver would
    open its own transaction first and the store's would nest inside it, so a
    ``ROLLBACK`` in the store would unwind more than the store wrote.

    ``dict_row`` so a row answers to ``row["seq"]``, which is what
    ``sqlite3.Row`` already does and what all forty methods are written
    against.
    """
    try:
        import psycopg
        from psycopg.rows import dict_row
    except ImportError as exc:
        raise PostgresUnavailable(INSTALL_HINT) from exc

    try:
        return psycopg.connect(dsn, autocommit=True, row_factory=dict_row)
    except psycopg.Error as exc:
        # The DSN is not echoed: it carries a password, and this message ends
        # up in logs and in `qed doctor` output.
        raise PostgresUnavailable(f"could not connect to PostgreSQL: {exc}") from exc


class PostgresStore(SqlStore):
    """A shared store for more than one replica.

    Migrations run at open, exactly as on SQLite and from the same files. Two
    replicas starting at once both try to apply them; the ``schema_migrations``
    primary key means one of them loses the insert, which is why
    :meth:`SqlStore.migrate` is wrapped here.
    """

    def __init__(self, dsn: str) -> None:
        self.dsn = dsn
        super().__init__(Connection(connect(dsn), POSTGRES))

    # ------------------------------------------------------------- migrations

    def migrate(self) -> None:
        """Apply migrations, tolerating another replica doing it at the moment.

        On SQLite there is one process and the question does not arise. Here,
        two replicas can start together, both read an empty
        ``schema_migrations``, and both run ``0001``. The DDL is
        ``IF NOT EXISTS`` so the second one is harmless, and the ledger's
        primary key makes its bookkeeping insert fail -- which would otherwise
        crash a replica during a perfectly ordinary rollout.

        A transaction-level advisory lock is taken for the duration instead, so
        the second replica waits rather than races. It is released when the
        transaction ends, including by crashing, which a table-based mutex
        could not promise.
        """
        self._conn.execute("BEGIN")
        try:
            # A different key from the chain leader's: holding one must not
            # imply holding the other. A replica migrating is not a replica
            # that may append.
            self._conn.execute("SELECT pg_advisory_xact_lock(?)", (CHAIN_LOCK_KEY + 1,))
            super().migrate()
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise

    # ----------------------------------------------------------- leadership

    def try_become_leader(self) -> bool:
        """``pg_try_advisory_lock`` (SPEC §15). Non-blocking; never waits.

        Session-scoped on purpose: it is held for as long as this replica's
        connection lives and released the moment it dies, which is exactly the
        liveness signal a leader election needs. A lease in a table would need
        a heartbeat, a clock and a decision about what to do when the clock is
        wrong.
        """
        row = self._conn.execute("SELECT pg_try_advisory_lock(?) AS held", (CHAIN_LOCK_KEY,))
        answer = row.fetchone()
        return bool(answer and answer["held"])

    def resign_leadership(self) -> None:
        """Release the lock, for a clean shutdown.

        Not required for correctness -- closing the connection releases it --
        but a replica that resigns on the way out hands over in milliseconds
        instead of after the server notices a dead connection.
        """
        self._conn.execute("SELECT pg_advisory_unlock(?)", (CHAIN_LOCK_KEY,))

    def holds_leadership(self) -> bool:
        """Whether *this session* holds the chain lock.

        Asked of ``pg_locks`` rather than remembered in a Python attribute,
        because the attribute would still say True after the connection had
        been dropped and re-opened underneath us.
        """
        row = self._conn.execute(
            "SELECT count(*) AS n FROM pg_locks "
            "WHERE locktype = 'advisory' AND objid = ? AND pid = pg_backend_pid() "
            "AND granted",
            (CHAIN_LOCK_KEY,),
        )
        answer = row.fetchone()
        return bool(answer and int(answer["n"]) > 0)
