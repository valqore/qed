"""The store (SPEC §15). One implementation, two backends.

Raw SQL, no ORM, forward-only migrations applied at open. Week 1 promised that
"the Postgres backend will use the same shape, so the repository functions do
not change", and this is that promise kept: every method below is written once
and runs against SQLite or PostgreSQL, because both drivers already expose a
compatible ``execute(sql, params) -> cursor`` and the only genuine differences
are collected in :mod:`qed.infra.storage.dialect`.

The alternative was a second class with forty near-identical methods. That is
two implementations of the chain's append path, and the day they drift is the
day the chain behaves differently depending on which database somebody
deployed.

The evidence table is append-only from this module's point of view: the only
statements against it are INSERT, SELECT, and the retention UPDATE that sets
``payload`` to NULL. Nothing here can rewrite a hash or a signature.

**The SQL is written with ``?``** and converted for psycopg on the way to the
driver. ``tests/evidence/test_store_dialects.py`` asserts no SQL string here
contains a quoted ``?``, which is the one thing that would make that wrong.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator, Mapping, Sequence
from datetime import datetime, timedelta
from pathlib import Path
from types import TracebackType
from typing import Any, NamedTuple, Protocol

from qed.core.approval.model import ApprovalDecision, ApprovalRequest, ApprovalStatus
from qed.core.budget import Charge, apply_charge
from qed.core.schemas import (
    Budget,
    BudgetState,
    EvidenceRecord,
    Mandate,
    SigningKeyInfo,
    rfc3339_ms,
    utcnow,
)
from qed.infra.storage.dialect import SQLITE, Dialect, migrations

__all__ = [
    "ChainIntegrityError",
    "Checkpoint",
    "Connection",
    "SqlStore",
    "SqliteStore",
]

_EVIDENCE_COLUMNS = (
    "seq, ts, type, assurance, mode, enforcement, dev, schema_version, "
    "payload_hash, payload, prev_hash, hash, key_id, sig, "
    "proposal_id, approval_id, principal_hash"
)


class ChainIntegrityError(RuntimeError):
    """The store refused a write that would have broken the chain."""


def _receipts(value: object) -> tuple[dict[str, object], ...]:
    """Decode a ``published_to`` column.

    Tolerant on purpose: this is the one column a backup restore or a hand
    edit is likely to touch, and a chain that refused to open because a
    receipt list was malformed would be a chain held hostage by metadata that
    is not part of it.
    """
    if not value:
        return ()
    try:
        decoded = json.loads(value if isinstance(value, str) else str(value))
    except (TypeError, ValueError):
        return ()
    if not isinstance(decoded, list):
        return ()
    return tuple(entry for entry in decoded if isinstance(entry, dict))


class Checkpoint(NamedTuple):
    """A row of ``checkpoints``. Indexable, so older positional reads still work."""

    seq_from: int
    seq_to: int
    merkle_root: str
    #: Seq of the ``checkpoint`` evidence record itself. None only for a row
    #: written before the column existed.
    evidence_seq: int | None
    #: What came back from publishing this checkpoint (SPEC §10.4). Held here
    #: rather than in the record it describes -- a receipt about a record
    #: cannot go inside that record, because it would change the hash it is
    #: about. The *next* checkpoint's payload carries them, which is what makes
    #: them durable; this column is how they get from one to the other.
    published_to: tuple[dict[str, object], ...] = ()


class _Cursor(Protocol):
    """What both drivers' cursors give us. Narrow on purpose."""

    rowcount: int

    def fetchone(self) -> Any: ...
    def fetchall(self) -> Any: ...
    def __iter__(self) -> Any: ...


class Connection:
    """A driver-neutral connection.

    Thin because it can be: ``sqlite3.Connection.execute`` and
    ``psycopg.Connection.execute`` already have the same signature and both
    return an iterable cursor whose rows are addressable by column name --
    ``sqlite3.Row`` for one and ``dict_row`` for the other. So the only work
    here is converting the placeholder and naming where a transaction starts.
    """

    __slots__ = ("_raw", "dialect")

    def __init__(self, raw: Any, dialect: Dialect) -> None:
        self._raw = raw
        self.dialect = dialect

    def execute(self, sql: str, params: Sequence[Any] = ()) -> _Cursor:
        converted = self.dialect.convert(sql)
        cursor: _Cursor = (
            self._raw.execute(converted, params) if params else self._raw.execute(converted)
        )
        return cursor

    def begin_write(self) -> None:
        """Open a transaction that intends to write.

        SQLite takes the write lock here, which is what stops two processes
        on one file agreeing on the same ``seq``. Postgres relies on the
        primary key instead; see the dialect module.
        """
        self.execute(self.dialect.begin_write)

    def commit(self) -> None:
        self.execute("COMMIT")

    def rollback(self) -> None:
        self.execute("ROLLBACK")

    def script(self, text: str) -> None:
        """Run a multi-statement script, however this driver wants it."""
        if self.dialect.script_in_one_call:
            self._raw.execute(text)
        else:
            self._raw.executescript(text)

    def close(self) -> None:
        self._raw.close()


class SqlStore:
    """Every repository method. Backend-agnostic.

    Constructed with an already-open connection so that the two subclasses
    below own the driver details and nothing else does.
    """

    def __init__(self, connection: Connection) -> None:
        self._conn = connection
        self.migrate()

    # ---------------------------------------------------------------- lifecycle

    @property
    def dialect(self) -> Dialect:
        """Which backend this store is talking to.

        Exposed because callers outside storage legitimately want the name --
        `qed status` reports it, and the deferred write path is chosen by it --
        and reaching through `_conn` for that would make every such caller a
        user of a private attribute.
        """
        return self._conn.dialect

    def migrate(self) -> None:
        """Apply each migration once, in name order.

        Until 0002 every script was re-executed on every open, which worked
        only because each statement was ``CREATE TABLE IF NOT EXISTS``. SQLite
        has no ``ADD COLUMN IF NOT EXISTS``, so the first migration that alters
        an existing table has to be run exactly once, and the ledger of what
        has run has to live in the database.

        An existing database has no ledger, so 0001 is replayed there the first
        time this runs. That is safe precisely because 0001 is idempotent, and
        it is why the ledger could be introduced without a backfill step.

        The same scripts run on both backends. All four were replayed against a
        real PostgreSQL 17 before the dialect seam was written, so the week-1
        comment claiming they sit in the shared SQL subset is checked rather
        than trusted.
        """
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS schema_migrations ("
            "  name TEXT PRIMARY KEY, applied_at TEXT NOT NULL)"
        )
        applied = {
            str(row["name"]) for row in self._conn.execute("SELECT name FROM schema_migrations")
        }
        for script in migrations():
            if script.name in applied:
                continue
            self._conn.script(script.read_text(encoding="utf-8"))
            self._conn.execute(
                "INSERT INTO schema_migrations (name, applied_at) VALUES (?, ?)",
                (script.name, rfc3339_ms(utcnow())),
            )

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> SqlStore:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    # ---------------------------------------------------------------- instance

    def set_meta(self, key: str, value: str) -> None:
        self._conn.execute(
            "INSERT INTO instance (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v",
            (key, value),
        )

    def get_meta(self, key: str) -> str | None:
        row = self._conn.execute("SELECT v FROM instance WHERE k = ?", (key,)).fetchone()
        return None if row is None else str(row["v"])

    # ---------------------------------------------------------------- evidence

    def last_seq(self) -> int | None:
        row = self._conn.execute("SELECT MAX(seq) AS m FROM evidence").fetchone()
        return None if row["m"] is None else int(row["m"])

    def last_hash(self) -> str | None:
        row = self._conn.execute("SELECT hash FROM evidence ORDER BY seq DESC LIMIT 1").fetchone()
        return None if row is None else str(row["hash"])

    def last_ts(self) -> datetime | None:
        """The newest record's timestamp, for the clock check (SPEC §17).

        By `seq`, not by `ts`: the newest record is the last one appended, and
        asking for `MAX(ts)` would return the *latest-dated* record, which on a
        chain written by a clock that went backwards is a different row -- and
        the row this needs is the one a backwards clock produced.
        """
        row = self._conn.execute("SELECT ts FROM evidence ORDER BY seq DESC LIMIT 1").fetchone()
        return None if row is None else _parse_ts(str(row["ts"]))

    def append_evidence(
        self,
        record: EvidenceRecord,
        *,
        proposal_id: str | None = None,
        approval_id: str | None = None,
        principal_hash: str | None = None,
    ) -> None:
        """Append one record inside a single immediate transaction.

        ``BEGIN IMMEDIATE`` takes the write lock before the sequence number is
        re-checked, so two processes pointed at the same file cannot both decide
        they own the same ``seq``.
        """
        self._conn.begin_write()
        try:
            last = self.last_seq()
            expected = 0 if last is None else last + 1
            if record.seq != expected:
                raise ChainIntegrityError(
                    f"next sequence number is {expected}, record carries {record.seq}"
                )
            self._conn.execute(
                f"INSERT INTO evidence ({_EVIDENCE_COLUMNS}) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    record.seq,
                    rfc3339_ms(record.ts),
                    record.type.value,
                    record.assurance.value,
                    None if record.mode is None else record.mode.value,
                    None if record.enforcement is None else record.enforcement.value,
                    record.dev,
                    record.schema_version,
                    record.payload_hash,
                    None if record.payload is None else json.dumps(record.payload),
                    record.prev_hash,
                    record.hash,
                    record.key_id,
                    record.sig,
                    proposal_id,
                    approval_id,
                    principal_hash,
                ),
            )
        except BaseException:
            self._conn.rollback()
            raise
        self._conn.commit()

    def iter_evidence(
        self,
        from_seq: int = 0,
        to_seq: int | None = None,
        types: Sequence[str] | None = None,
    ) -> Iterator[EvidenceRecord]:
        """Records in ``seq`` order.

        ``types`` filters for reporting (``GET /v1/evidence?type=``). Note that
        a filtered export is **not** verifiable on its own: ``qed-verify``
        needs contiguous sequence numbers to check the linkage. The API says so
        in its response headers and the CLI refuses to combine the two.
        """
        sql = f"SELECT {_EVIDENCE_COLUMNS} FROM evidence WHERE seq >= ?"
        params: list[object] = [from_seq]
        if to_seq is not None:
            sql += " AND seq <= ?"
            params.append(to_seq)
        if types:
            sql += f" AND type IN ({','.join('?' * len(types))})"
            params.extend(types)
        sql += " ORDER BY seq"
        for row in self._conn.execute(sql, params):
            yield _row_to_record(row)

    def evidence_at(self, seq: int) -> EvidenceRecord | None:
        row = self._conn.execute(
            f"SELECT {_EVIDENCE_COLUMNS} FROM evidence WHERE seq = ?", (seq,)
        ).fetchone()
        return None if row is None else _row_to_record(row)

    def count_evidence(self) -> int:
        row = self._conn.execute("SELECT COUNT(*) AS c FROM evidence").fetchone()
        return int(row["c"])

    def purge_payloads(self, *, through_seq: int, types: Sequence[str] | None = None) -> int:
        """Retention by range (SPEC §10.6). Hashes and signatures are untouched."""
        sql = "UPDATE evidence SET payload = NULL WHERE seq <= ? AND payload IS NOT NULL"
        params: list[object] = [through_seq]
        if types:
            sql += f" AND type IN ({','.join('?' * len(types))})"
            params.extend(types)
        cursor = self._conn.execute(sql, params)
        return int(cursor.rowcount)

    def purge_payload_seqs(self, seqs: Sequence[int]) -> int:
        """Retention for an explicit set of records (SPEC §10.6).

        Explicit rather than a range, because retention is per type: the
        expired set is not contiguous, and a structural record that may never
        be purged can sit in the middle of an otherwise expired stretch.
        :func:`qed.core.evidence.retention.plan_purge` decides which; this
        only carries it out.

        Batched, because a chain with years of history produces a list that is
        longer than a parameter limit -- SQLite's default is 999, and a single
        statement with 40,000 placeholders is refused rather than slow.
        """
        if not seqs:
            return 0
        cleared = 0
        batch = 400
        for start in range(0, len(seqs), batch):
            chunk = list(seqs[start : start + batch])
            placeholders = ",".join("?" * len(chunk))
            cursor = self._conn.execute(
                f"UPDATE evidence SET payload = NULL WHERE payload IS NOT NULL "
                f"AND seq IN ({placeholders})",
                chunk,
            )
            cleared += int(cursor.rowcount)
        return cleared

    # ------------------------------------------------------------ signing keys

    def upsert_signing_key(self, info: SigningKeyInfo) -> None:
        self._conn.execute(
            "INSERT INTO signing_keys (key_id, alg, public_pem, source, created_at, retired_at) "
            "VALUES (?,?,?,?,?,?) ON CONFLICT(key_id) DO UPDATE SET "
            "public_pem = excluded.public_pem, retired_at = excluded.retired_at",
            (
                info.key_id,
                info.alg,
                info.public_pem,
                info.source,
                None if info.created_at is None else rfc3339_ms(info.created_at),
                None if info.retired_at is None else rfc3339_ms(info.retired_at),
            ),
        )

    def retire_signing_key(self, key_id: str, *, at: datetime) -> None:
        """Mark a key as no longer signing (SPEC §10.5).

        The row is never deleted. An auditor verifying a record from before the
        rotation needs that public key, and the OSCAL export ships the whole
        set for exactly that reason.
        """
        self._conn.execute(
            "UPDATE signing_keys SET retired_at = ? WHERE key_id = ?",
            (rfc3339_ms(at), key_id),
        )

    def signing_keys(self) -> list[SigningKeyInfo]:
        rows = self._conn.execute(
            "SELECT key_id, alg, public_pem, source, created_at, retired_at "
            "FROM signing_keys ORDER BY created_at, key_id"
        ).fetchall()
        return [
            SigningKeyInfo(
                key_id=row["key_id"],
                alg=row["alg"],
                public_pem=row["public_pem"],
                source=row["source"],
                created_at=row["created_at"],
                retired_at=row["retired_at"],
            )
            for row in rows
        ]

    # --------------------------------------------------------------- proposals

    def record_proposal(
        self,
        *,
        proposal_json: str,
        verdict_json: str,
        proposal_id: str,
        ts: datetime,
        token_jti: str,
        principal_hash: str | None,
        kind: str,
        name: str,
        target: str,
        params_hash: str,
        environment: str,
        adapter_id: str,
        enforcement: str,
        mode: str,
    ) -> None:
        self._conn.execute(
            "INSERT INTO proposals (id, ts, token_jti, principal_hash, kind, name, target, "
            "params_hash, environment, adapter_id, enforcement, mode, proposal_json, "
            "verdict_json) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                proposal_id,
                rfc3339_ms(ts),
                token_jti,
                principal_hash,
                kind,
                name,
                target,
                params_hash,
                environment,
                adapter_id,
                enforcement,
                mode,
                proposal_json,
                verdict_json,
            ),
        )

    def proposal_exists(self, proposal_id: str) -> bool:
        row = self._conn.execute("SELECT 1 FROM proposals WHERE id = ?", (proposal_id,)).fetchone()
        return row is not None

    def get_proposal(self, proposal_id: str) -> tuple[str, str] | None:
        """The stored ``(proposal_json, verdict_json)`` pair, or ``None``.

        Both are the canonical (JCS) forms that were hashed into the chain, so
        what ``GET /v1/proposals/{id}`` returns is byte-identical to what was
        signed -- not a re-serialisation that might differ in key order.
        """
        row = self._conn.execute(
            "SELECT proposal_json, verdict_json FROM proposals WHERE id = ?", (proposal_id,)
        ).fetchone()
        if row is None:
            return None
        return str(row["proposal_json"]), str(row["verdict_json"])

    # ----------------------------------------------------------- policy bundle

    def record_bundle(
        self, *, bundle_hash: str, version: str | None, rules_count: int, loaded_at: datetime
    ) -> bool:
        """Returns True when this is the first time the bundle has been seen.

        One statement, not a SELECT then an INSERT. Two replicas starting at
        the same moment both saw no row, both inserted, and the loser died on
        `UniqueViolation: policy_bundles_pkey` **before the API came up** -- so
        a simultaneous start or a rolling restart could leave a replica
        refusing to serve, for a bundle the other had already recorded.

        `ON CONFLICT DO NOTHING` makes the race decide itself: exactly one
        caller inserts, and `rowcount` says which. That is also the semantics
        the name promises, and it is why the loser must return False rather
        than raise -- it is not an error that another replica got there first,
        it is the normal case for every replica after the first.
        """
        cursor = self._conn.execute(
            "INSERT INTO policy_bundles (hash, version, loaded_at, rules_count) "
            "VALUES (?,?,?,?) ON CONFLICT(hash) DO NOTHING",
            (bundle_hash, version, rfc3339_ms(loaded_at), rules_count),
        )
        return int(cursor.rowcount) > 0

    def forget_bundles(self) -> int:
        """Drop the "already recorded" marks, so the next session re-records.

        For `qed packs import`. `policy_loaded` is the record of *the rules
        that were in force*, and every verdict points at it -- but the control
        catalogues are part of how those rules are read, and importing one does
        not change the policy hash. Without this, a catalogue could be replaced
        and the only record of it would be an `admin_action` possibly a year
        earlier in the chain, while every `policy_loaded` after it kept saying
        `unsigned: false`.

        The marks are a de-duplication table, not evidence: nothing in the
        chain is touched, and re-recording appends a *new* `policy_loaded` with
        the same `policy_hash` and the new catalogue state. Two records for one
        policy hash is the honest outcome -- the bundle was loaded twice and
        meant something different the second time.
        """
        cursor = self._conn.execute("DELETE FROM policy_bundles")
        return int(cursor.rowcount)

    # ------------------------------------------------------------- checkpoints

    def record_checkpoint(
        self, *, seq_from: int, seq_to: int, merkle_root: str, evidence_seq: int
    ) -> None:
        self._conn.execute(
            "INSERT INTO checkpoints (seq_to, seq_from, merkle_root, evidence_seq, "
            "published_to) VALUES (?,?,?,?,?)",
            (seq_to, seq_from, merkle_root, evidence_seq, json.dumps([])),
        )

    def last_checkpoint(self) -> Checkpoint | None:
        """The newest checkpoint, including the seq of its own record.

        ``evidence_seq`` is needed to date a checkpoint, and SPEC §19's badge
        wants its age. It is *not* ``seq_to + 1``: that happens to be true for
        a writer that checkpoints immediately, and an arithmetic guess about
        where a record lives is the kind of thing that stays correct until the
        day it does not.
        """
        row = self._conn.execute(
            "SELECT seq_from, seq_to, merkle_root, evidence_seq, published_to FROM "
            "checkpoints ORDER BY seq_to DESC LIMIT 1"
        ).fetchone()
        if row is None:
            return None
        return Checkpoint(
            seq_from=int(row["seq_from"]),
            seq_to=int(row["seq_to"]),
            merkle_root=str(row["merkle_root"]),
            evidence_seq=None if row["evidence_seq"] is None else int(row["evidence_seq"]),
            published_to=_receipts(row["published_to"]),
        )

    def record_publication(self, *, seq_to: int, receipts: Sequence[dict[str, object]]) -> None:
        """Store what publishing one checkpoint produced (SPEC §10.4).

        Replaces rather than appends: a publication is retried as a whole, and
        two generations of receipts for one checkpoint would leave a reader to
        guess which is current.
        """
        self._conn.execute(
            "UPDATE checkpoints SET published_to = ? WHERE seq_to = ?",
            (json.dumps(list(receipts)), seq_to),
        )

    # ------------------------------------------------------------- outbox

    def enqueue_outbox(self, outbox_id: str, record_json: str, *, created_at: datetime) -> str:
        """Durably accept a record that is not chained yet (SPEC §10.3).

        This is the write that makes a decision recorded. The sequence number,
        the previous hash, the record hash and the signature are all assigned
        later by whichever replica holds the chain lock -- none of them can be
        computed here, because every one depends on where the record lands in
        an order this process does not control.

        What *is* guaranteed here is durability: once this returns, the record
        exists and the leader will chain it. So "no decision without a record"
        holds at enqueue time, which is what lets the API answer before the
        chain has caught up.
        """
        self._conn.execute(
            "INSERT INTO evidence_outbox (id, created_at, record_json) VALUES (?, ?, ?)",
            (outbox_id, rfc3339_ms(created_at), record_json),
        )
        return outbox_id

    def outbox_depth(self) -> int:
        """How far behind the chain is. SPEC §18's ``qed_chain_lag_records``.

        The number an operator watches: a depth that keeps growing means the
        leader is gone, or is losing the lock faster than it can drain.
        """
        row = self._conn.execute("SELECT count(*) AS n FROM evidence_outbox").fetchone()
        return 0 if row is None else int(row["n"])

    def outbox_batch(self, limit: int = 100) -> list[tuple[str, str]]:
        """The oldest ``limit`` entries as ``(id, record_json)``.

        Ordered by ``created_at, id`` exactly as SPEC §10.3 says, and the tie
        break on ``id`` matters: two replicas enqueueing in the same
        millisecond would otherwise be drained in an order the database chose,
        and the chain's order would differ between two replays of the same
        inputs. ULIDs sort by time within a millisecond, so the order is
        stable and roughly causal.
        """
        rows = self._conn.execute(
            "SELECT id, record_json FROM evidence_outbox ORDER BY created_at, id LIMIT ?",
            (limit,),
        )
        return [(str(row["id"]), str(row["record_json"])) for row in rows]

    def delete_outbox(self, outbox_ids: Sequence[str]) -> int:
        """Remove drained entries. Called inside the drain's transaction."""
        if not outbox_ids:
            return 0
        placeholders = ",".join("?" for _ in outbox_ids)
        cursor = self._conn.execute(
            f"DELETE FROM evidence_outbox WHERE id IN ({placeholders})", tuple(outbox_ids)
        )
        return int(cursor.rowcount)

    def record_outbox_ref(self, outbox_id: str, seq: int) -> None:
        """Remember which ``seq`` an outbox id became (SPEC §13 ``by-ref``).

        Kept after the outbox row is gone, because the id is what the API
        already handed to a caller and ``GET /v1/evidence/by-ref/{id}`` has to
        keep answering it. Without this the reference would resolve only while
        the record was still undrained, which is the window in which nobody
        needs it.
        """
        self._conn.execute(
            "INSERT INTO outbox_refs (id, seq) VALUES (?, ?) ON CONFLICT(id) DO NOTHING",
            (outbox_id, seq),
        )

    def resolve_outbox_ref(self, outbox_id: str) -> int | None:
        """The ``seq`` an outbox id became, or None while it is still pending."""
        row = self._conn.execute(
            "SELECT seq FROM outbox_refs WHERE id = ?", (outbox_id,)
        ).fetchone()
        return None if row is None else int(row["seq"])

    def outbox_pending(self, outbox_id: str) -> bool:
        """Whether the id is still waiting to be chained."""
        row = self._conn.execute(
            "SELECT 1 AS present FROM evidence_outbox WHERE id = ?", (outbox_id,)
        ).fetchone()
        return row is not None

    # ------------------------------------------------------------- budgets

    def upsert_budget_caps(self, token_jti: str, budget: Budget) -> None:
        """Record the caps a token was issued with (SPEC §6.2, §8).

        Caps are written once at issuance and not touched by a charge, so a
        later ``UPDATE`` of usage cannot silently widen them. Re-issuing the
        same ``jti`` replaces the caps and leaves usage alone, which is what a
        re-exchange of an unexpired token should do.
        """
        self._conn.execute(
            "INSERT INTO budgets (token_jti, cap_steps, cap_tokens, cap_seconds, "
            "cap_money_cents, currency) VALUES (?,?,?,?,?,?) "
            "ON CONFLICT(token_jti) DO UPDATE SET "
            "cap_steps = excluded.cap_steps, cap_tokens = excluded.cap_tokens, "
            "cap_seconds = excluded.cap_seconds, cap_money_cents = excluded.cap_money_cents, "
            "currency = excluded.currency",
            (
                token_jti,
                budget.steps,
                budget.tokens,
                budget.seconds,
                budget.money_cents,
                budget.currency,
            ),
        )

    def load_budget(self, token_jti: str) -> BudgetState | None:
        row = self._conn.execute(
            "SELECT * FROM budgets WHERE token_jti = ?", (token_jti,)
        ).fetchone()
        return None if row is None else _row_to_budget(row)

    def charge_budget(
        self,
        token_jti: str,
        charge: Charge,
        *,
        now: datetime,
        principal_hash: str | None = None,
    ) -> tuple[BudgetState, BudgetState]:
        """Apply one charge atomically. Returns ``(before, after)``.

        ``BEGIN IMMEDIATE`` takes the write lock before the row is read, so two
        adapters charging the same token cannot both read the same ``steps_used``
        and write back the same incremented value. This is the same guarantee
        ``append_evidence`` relies on, for the same reason.

        A token with no row is charged against an uncapped state and a row is
        created. Refusing instead would mean the first action of every token
        that skipped issuance is lost to an error, and an uncapped budget is
        already the documented meaning of a cap of 0.
        """
        self._conn.begin_write()
        try:
            row = self._conn.execute(
                "SELECT * FROM budgets WHERE token_jti = ?", (token_jti,)
            ).fetchone()
            before = BudgetState(token_jti=token_jti) if row is None else _row_to_budget(row)
            after = apply_charge(before, charge, now=now)
            stamp = rfc3339_ms(now)
            first_seen = rfc3339_ms(after.first_seen) if after.first_seen is not None else None
            exhausted_at = stamp if after.exhausted(now) else None
            if row is None:
                self._conn.execute(
                    "INSERT INTO budgets (token_jti, steps_used, tokens_used, "
                    "money_used_cents, first_seen, updated_at, exhausted_at) "
                    "VALUES (?,?,?,?,?,?,?)",
                    (
                        token_jti,
                        after.steps_used,
                        after.tokens_used,
                        after.money_used_cents,
                        first_seen,
                        stamp,
                        exhausted_at,
                    ),
                )
            else:
                # `exhausted_at` only ever moves from NULL to a time: the first
                # moment the token was spent is the interesting one, and a
                # later charge must not overwrite it.
                self._conn.execute(
                    "UPDATE budgets SET steps_used = ?, tokens_used = ?, "
                    "money_used_cents = ?, first_seen = ?, updated_at = ?, "
                    "exhausted_at = COALESCE(exhausted_at, ?) WHERE token_jti = ?",
                    (
                        after.steps_used,
                        after.tokens_used,
                        after.money_used_cents,
                        first_seen,
                        stamp,
                        exhausted_at,
                        token_jti,
                    ),
                )
            if principal_hash is not None:
                self._conn.execute(
                    "INSERT INTO budget_daily (principal_hash, day, steps_used, "
                    "tokens_used, money_used_cents) VALUES (?,?,?,?,?) "
                    # The existing row's columns are qualified with the table
                    # name. SQLite accepts the bare name; PostgreSQL calls it
                    # ambiguous and refuses the statement, because `excluded`
                    # has a column of the same name -- which is exactly what
                    # the expression is adding. The only upsert in this file
                    # that accumulates rather than replaces, and so the only
                    # one where the distinction arises.
                    "ON CONFLICT(principal_hash, day) DO UPDATE SET "
                    "steps_used = budget_daily.steps_used + excluded.steps_used, "
                    "tokens_used = budget_daily.tokens_used + excluded.tokens_used, "
                    "money_used_cents = budget_daily.money_used_cents "
                    "+ excluded.money_used_cents",
                    (
                        principal_hash,
                        stamp[:10],
                        charge.steps,
                        charge.tokens,
                        charge.money_cents,
                    ),
                )
        except BaseException:
            self._conn.rollback()
            raise
        self._conn.commit()
        return before, after

    # ------------------------------------------------------------ approvals

    def record_approval(self, request: ApprovalRequest, *, request_json: str) -> None:
        self._conn.execute(
            "INSERT INTO approvals (id, proposal_id, dedupe_key, status, approvers, "
            "created_at, expires_at, escalate_at, escalated, request_json, "
            "principal_hash, window_max_seconds) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                request.id,
                request.proposal_id,
                request.dedupe_key,
                request.status.value,
                json.dumps(request.approvers),
                rfc3339_ms(request.created_at),
                rfc3339_ms(request.expires_at),
                None if request.escalate_at is None else rfc3339_ms(request.escalate_at),
                request.escalated,
                request_json,
                request.principal_hash,
                None if request.window_max is None else int(request.window_max.total_seconds()),
            ),
        )

    def load_approval(self, approval_id: str) -> ApprovalRequest | None:
        row = self._conn.execute("SELECT * FROM approvals WHERE id = ?", (approval_id,)).fetchone()
        return None if row is None else _row_to_approval(row)

    def pending_for_dedupe(
        self, key: str, *, now: datetime, window: timedelta
    ) -> ApprovalRequest | None:
        """A pending request for the same action, young enough to join.

        SPEC §9.2: a retrying agent should land on the request a human is
        already looking at rather than filling the queue with copies.
        """
        row = self._conn.execute(
            "SELECT * FROM approvals WHERE dedupe_key = ? AND status = 'pending' "
            "ORDER BY created_at DESC LIMIT 1",
            (key,),
        ).fetchone()
        if row is None:
            return None
        found = _row_to_approval(row)
        if (now - found.created_at) > window or found.expires_at <= now:
            return None
        return found

    def recently_denied(
        self, key: str, *, now: datetime, window: timedelta
    ) -> ApprovalRequest | None:
        """A denial for the same action, young enough to still mean no.

        Without this an agent that is told no simply asks again, and the
        second request looks exactly like the first to whoever sees it.
        """
        row = self._conn.execute(
            "SELECT * FROM approvals WHERE dedupe_key = ? AND status = 'denied' "
            "ORDER BY decided_at DESC LIMIT 1",
            (key,),
        ).fetchone()
        if row is None or row["decided_at"] is None:
            return None
        decided_at = _parse_ts(str(row["decided_at"]))
        return _row_to_approval(row) if (now - decided_at) <= window else None

    def apply_decision(self, decision: ApprovalDecision) -> bool:
        """Record a decision. False when the request was already decided.

        The status check is in the UPDATE rather than around it, so two
        approvers clicking at the same moment cannot both win.
        """
        cursor = self._conn.execute(
            "UPDATE approvals SET status = ?, decision = ?, approver_hash = ?, "
            "decided_at = ?, reason = ?, window_until = ? "
            "WHERE id = ? AND status = 'pending'",
            (
                decision.status.value,
                decision.kind.value,
                decision.approver_hash,
                rfc3339_ms(decision.decided_at),
                decision.reason,
                None if decision.window_until is None else rfc3339_ms(decision.window_until),
                decision.approval_id,
            ),
        )
        return int(cursor.rowcount) > 0

    def open_window(self, dedupe_key: str, approval_id: str, until: datetime) -> None:
        self._conn.execute(
            "INSERT INTO approval_windows (dedupe_key, approval_id, until) VALUES (?,?,?) "
            "ON CONFLICT(dedupe_key, approval_id) DO UPDATE SET until = excluded.until",
            (dedupe_key, approval_id, rfc3339_ms(until)),
        )

    def active_window(self, dedupe_key: str, *, now: datetime) -> str | None:
        """The approval id of an unexpired window for this action, if any."""
        row = self._conn.execute(
            "SELECT approval_id, until FROM approval_windows WHERE dedupe_key = ? "
            "ORDER BY until DESC LIMIT 1",
            (dedupe_key,),
        ).fetchone()
        if row is None:
            return None
        return str(row["approval_id"]) if _parse_ts(str(row["until"])) > now else None

    def expire_approvals(self, *, now: datetime) -> list[ApprovalRequest]:
        """Move every overdue pending request to `expired`, and return them.

        Returned so the caller can write one `approval_expired` record each:
        a request that simply vanished from the queue is not evidence of
        anything.
        """
        rows = self._conn.execute(
            "SELECT * FROM approvals WHERE status = 'pending' AND expires_at <= ?",
            (rfc3339_ms(now),),
        ).fetchall()
        expired = [_row_to_approval(row) for row in rows]
        if expired:
            self._conn.execute(
                "UPDATE approvals SET status = 'expired' WHERE status = 'pending' "
                "AND expires_at <= ?",
                (rfc3339_ms(now),),
            )
        return expired

    def approval_request_json(self, approval_id: str) -> str | None:
        """The approver view stored when the request was opened.

        Kept rather than rebuilt so it reflects the proposal as it was when
        the question was asked, not as the record looks now.
        """
        row = self._conn.execute(
            "SELECT request_json FROM approvals WHERE id = ?", (approval_id,)
        ).fetchone()
        return None if row is None or row["request_json"] is None else str(row["request_json"])

    def list_approvals(
        self, *, status: str | None = None, limit: int = 50
    ) -> list[ApprovalRequest]:
        sql = "SELECT * FROM approvals"
        params: list[object] = []
        if status is not None:
            sql += " WHERE status = ?"
            params.append(status)
        sql += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        return [_row_to_approval(row) for row in self._conn.execute(sql, params)]

    # ------------------------------------------------------------- mandates

    def record_mandate(self, mandate: Mandate, *, created_at: datetime) -> None:
        """Store a signed mandate (SPEC §6.5).

        The document is written whole, as the canonical JSON that was signed.
        Rebuilding it from columns risks bytes that differ from what the signer
        produced, and a signature that no longer verifies is indistinguishable
        from a forged one.
        """
        self._conn.execute(
            "INSERT INTO mandates (id, for_agent, issued_by_hash, purpose, valid_from, "
            "valid_until, key_id, mandate_json, created_at) VALUES (?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(id) DO UPDATE SET mandate_json = excluded.mandate_json, "
            "key_id = excluded.key_id",
            (
                mandate.id,
                mandate.for_agent,
                mandate.issued_by_hash,
                mandate.purpose,
                rfc3339_ms(mandate.valid.from_),
                rfc3339_ms(mandate.valid.until),
                None if mandate.signature is None else mandate.signature.key_id,
                mandate.model_dump_json(by_alias=True),
                rfc3339_ms(created_at),
            ),
        )

    def load_mandate(self, mandate_id: str) -> Mandate | None:
        row = self._conn.execute(
            "SELECT mandate_json, revoked_at FROM mandates WHERE id = ?", (mandate_id,)
        ).fetchone()
        if row is None:
            return None
        return _row_to_mandate(row)

    def list_mandates(self, *, for_agent: str | None = None) -> list[Mandate]:
        sql = "SELECT mandate_json, revoked_at FROM mandates"
        params: list[object] = []
        if for_agent is not None:
            sql += " WHERE for_agent = ?"
            params.append(for_agent)
        sql += " ORDER BY created_at, id"
        return [_row_to_mandate(row) for row in self._conn.execute(sql, params)]

    def revoke_mandate(
        self, mandate_id: str, *, at: datetime, by_hash: str | None, reason: str
    ) -> bool:
        """Mark a mandate revoked. Returns False if it was already revoked.

        The stored document is not touched: a revoked mandate has to keep
        verifying against the signature its issuer produced, or revoking one
        would destroy the record of who granted it.
        """
        cursor = self._conn.execute(
            "UPDATE mandates SET revoked_at = ?, revoked_by_hash = ?, revoked_reason = ? "
            "WHERE id = ? AND revoked_at IS NULL",
            (rfc3339_ms(at), by_hash, reason, mandate_id),
        )
        return int(cursor.rowcount) > 0

    def daily_usage(self, principal_hash: str, day: str) -> tuple[int, int, int]:
        """``(steps, tokens, money_cents)`` for one principal on one UTC day."""
        row = self._conn.execute(
            "SELECT steps_used, tokens_used, money_used_cents FROM budget_daily "
            "WHERE principal_hash = ? AND day = ?",
            (principal_hash, day),
        ).fetchone()
        if row is None:
            return 0, 0, 0
        return (
            int(row["steps_used"]),
            int(row["tokens_used"]),
            int(row["money_used_cents"]),
        )


def _parse_ts(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _row_to_approval(row: Mapping[str, Any]) -> ApprovalRequest:
    return ApprovalRequest(
        id=str(row["id"]),
        proposal_id=str(row["proposal_id"]),
        dedupe_key=str(row["dedupe_key"]),
        status=ApprovalStatus(str(row["status"])),
        approvers=json.loads(row["approvers"]) if row["approvers"] else [],
        principal_hash=row["principal_hash"],
        created_at=row["created_at"],
        expires_at=row["expires_at"],
        escalate_at=row["escalate_at"],
        escalated=bool(row["escalated"]),
        window_max=(
            None
            if row["window_max_seconds"] is None
            else timedelta(seconds=int(row["window_max_seconds"]))
        ),
    )


def _row_to_mandate(row: Mapping[str, Any]) -> Mandate:
    document = json.loads(str(row["mandate_json"]))
    if row["revoked_at"] is not None:
        # Revocation lives in its own column, so it is applied on the way out
        # rather than written into the signed document. It goes through
        # validation rather than `model_copy`, which does not validate and
        # would leave a raw string where every caller expects a datetime.
        document["revoked_at"] = row["revoked_at"]
    return Mandate.model_validate(document)


def _row_to_budget(row: Mapping[str, Any]) -> BudgetState:
    return BudgetState(
        token_jti=str(row["token_jti"]),
        budget=Budget(
            steps=int(row["cap_steps"]),
            tokens=int(row["cap_tokens"]),
            seconds=int(row["cap_seconds"]),
            money_cents=int(row["cap_money_cents"]),
            currency=str(row["currency"]),
        ),
        steps_used=int(row["steps_used"]),
        tokens_used=int(row["tokens_used"]),
        money_used_cents=int(row["money_used_cents"]),
        first_seen=row["first_seen"],
    )


def _row_to_record(row: Mapping[str, Any]) -> EvidenceRecord:
    payload = row["payload"]
    parsed: dict[str, object] | None = None
    if payload is not None:
        loaded = json.loads(payload)
        if not isinstance(loaded, dict):  # pragma: no cover - we only ever write objects
            raise ValueError(f"record {row['seq']} payload is not an object")
        parsed = loaded
    return EvidenceRecord(
        seq=int(row["seq"]),
        ts=row["ts"],
        type=row["type"],
        assurance=row["assurance"],
        mode=row["mode"],
        enforcement=row["enforcement"],
        dev=bool(row["dev"]),
        schema_version=row["schema_version"],
        payload_hash=row["payload_hash"],
        payload=parsed,
        prev_hash=row["prev_hash"],
        hash=row["hash"],
        key_id=row["key_id"],
        sig=row["sig"],
    )


class SqliteStore(SqlStore):
    """The default. Zero configuration, one file, good enough for a laptop.

    WAL so a reader does not block the writer, and ``isolation_level=None`` so
    the explicit ``BEGIN IMMEDIATE`` in :meth:`SqlStore.append_evidence` is the
    only transaction boundary -- Python's implicit one would otherwise open a
    deferred transaction first and turn the write lock into an upgrade that can
    deadlock.
    """

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        raw = sqlite3.connect(self.path, isolation_level=None)
        raw.row_factory = sqlite3.Row
        raw.execute("PRAGMA journal_mode=WAL")
        raw.execute("PRAGMA foreign_keys=ON")
        super().__init__(Connection(raw, SQLITE))
