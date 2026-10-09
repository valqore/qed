"""The small set of things SQLite and Postgres do not agree about (SPEC §15).

One store, two backends. The repository methods are written once and run
against both, because the alternative — two classes with forty near-identical
methods each — is two implementations of the chain's append path, and the day
they drift is the day the chain behaves differently depending on which database
somebody deployed.

The list of genuine disagreements turned out to be short:

* **Placeholders.** SQLite takes ``?``, psycopg takes ``%s``. The SQL is
  written with ``?`` and converted on the way to the driver.
  ``tests/evidence/test_store_dialects.py`` asserts no SQL string in the store
  contains a quoted ``?``, which is the one thing that would make the
  conversion wrong.
* **Taking the write lock.** SQLite has ``BEGIN IMMEDIATE``, which blocks other
  writers for the whole transaction. Postgres has no equivalent and does not
  need one for correctness: ``evidence.seq`` is the primary key, so a second
  writer's insert fails rather than succeeding with a duplicate. What Postgres
  needs instead is a lock that makes that failure rare instead of routine,
  which is the chain leader's advisory lock.
* **Multi-statement scripts.** ``sqlite3`` has ``executescript``; psycopg will
  run several statements in one ``execute`` as long as no parameters are bound.

**The DDL is shared, and that was worth checking rather than assuming.** The
week-1 migrations carry a comment claiming they sit in the subset both engines
accept; all four were replayed against a real PostgreSQL 17 before this module
was written, and they do. So there is one set of migration files and no
per-dialect directory — when a migration genuinely needs to diverge, that is
the migration to split, not this module to generalise in advance.

**Timestamps are TEXT in both**, in the exact format the record already carries
(``rfc3339_ms``). That is not laziness: ``ts`` is hashed into the record, so
storing it as a native timestamp type would let the backend's own precision
change the bytes. The chain has to be byte-identical across backends or an
export from one would not verify against the other.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Final

__all__ = ["CHAIN_LOCK_KEY", "MIGRATIONS_DIR", "POSTGRES", "SQLITE", "Dialect", "migrations"]

MIGRATIONS_DIR: Final = Path(__file__).parent / "migrations"

#: ``pg_try_advisory_lock(1734440037)``, which SPEC §15 writes as 0x67617465.
#:
#: Those four bytes spell "gate", the product's name before 2026-10-08. The
#: number is kept and the spec's comment corrected rather than the other way
#: round, for a reason that is not sentiment: **the lock id must never change
#: under a running deployment.** Two replicas on different versions would take
#: two different locks, both would believe they were leader, and both would
#: drain the outbox and assign ``seq`` — a forked chain, which is the one
#: failure the leader exists to prevent. Changing it safely needs every replica
#: stopped first, so it is not the kind of tidying to do in passing.
#:
#: It is also not a format constant: it is never hashed and never appears in
#: evidence, so ADR-0006's rule does not reach it.
CHAIN_LOCK_KEY: Final = 1734440037


@dataclass(frozen=True)
class Dialect:
    """What a backend needs the store to do differently."""

    name: str
    #: What the driver expects in place of ``?``.
    placeholder: str
    #: How to open a transaction that intends to write.
    begin_write: str
    #: Whether the driver runs a multi-statement script in one ``execute``.
    script_in_one_call: bool

    def convert(self, sql: str) -> str:
        """``?`` to whatever the driver wants. A no-op for SQLite."""
        if self.placeholder == "?":
            return sql
        return sql.replace("?", self.placeholder)


SQLITE: Final = Dialect(
    name="sqlite",
    placeholder="?",
    begin_write="BEGIN IMMEDIATE",
    script_in_one_call=False,
)

POSTGRES: Final = Dialect(
    name="postgres",
    placeholder="%s",
    # Plain BEGIN. `BEGIN IMMEDIATE` has no Postgres equivalent, and the
    # guarantee it bought -- two writers cannot agree on one `seq` -- is
    # already enforced by the primary key, which turns the loser's INSERT into
    # an error rather than a duplicate.
    begin_write="BEGIN",
    script_in_one_call=True,
)


def migrations() -> list[Path]:
    """The migration scripts, in name order.

    Name order, because the ``schema_migrations`` ledger records the file name
    rather than its path. Shared across dialects; see the module docstring.
    """
    return sorted(MIGRATIONS_DIR.glob("*.sql"))
