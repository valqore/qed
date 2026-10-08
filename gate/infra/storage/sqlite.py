"""SQLite store (SPEC §15).

Raw SQL, no ORM, forward-only migrations applied at open — the same shape the
Postgres backend will use in week 6, so the repository functions do not change.

The evidence table is append-only from this module's point of view: the only
statements against it are INSERT, SELECT, and the retention UPDATE that sets
``payload`` to NULL. Nothing here can rewrite a hash or a signature.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator, Sequence
from datetime import datetime
from pathlib import Path
from types import TracebackType

from gate.core.schemas import EvidenceRecord, SigningKeyInfo, rfc3339_ms

__all__ = ["MIGRATIONS_DIR", "SqliteStore"]

MIGRATIONS_DIR = Path(__file__).parent / "migrations"

_EVIDENCE_COLUMNS = (
    "seq, ts, type, assurance, mode, enforcement, dev, schema_version, "
    "payload_hash, payload, prev_hash, hash, key_id, sig, "
    "proposal_id, approval_id, principal_hash"
)


class ChainIntegrityError(RuntimeError):
    """The store refused a write that would have broken the chain."""


class SqliteStore:
    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.path, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self.migrate()

    # ---------------------------------------------------------------- lifecycle

    def migrate(self) -> None:
        for script in sorted(MIGRATIONS_DIR.glob("*.sql")):
            self._conn.executescript(script.read_text(encoding="utf-8"))

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> SqliteStore:
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
        self._conn.execute("BEGIN IMMEDIATE")
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
            self._conn.execute("ROLLBACK")
            raise
        self._conn.execute("COMMIT")

    def iter_evidence(
        self,
        from_seq: int = 0,
        to_seq: int | None = None,
        types: Sequence[str] | None = None,
    ) -> Iterator[EvidenceRecord]:
        """Records in ``seq`` order.

        ``types`` filters for reporting (``GET /v1/evidence?type=``). Note that
        a filtered export is **not** verifiable on its own: ``gate-verify``
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
        """Retention (SPEC §10.6). Hashes and signatures are never touched."""
        sql = "UPDATE evidence SET payload = NULL WHERE seq <= ? AND payload IS NOT NULL"
        params: list[object] = [through_seq]
        if types:
            sql += f" AND type IN ({','.join('?' * len(types))})"
            params.extend(types)
        cursor = self._conn.execute(sql, params)
        return cursor.rowcount

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
        """Returns True when this is the first time the bundle has been seen."""
        existing = self._conn.execute(
            "SELECT 1 FROM policy_bundles WHERE hash = ?", (bundle_hash,)
        ).fetchone()
        if existing is not None:
            return False
        self._conn.execute(
            "INSERT INTO policy_bundles (hash, version, loaded_at, rules_count) VALUES (?,?,?,?)",
            (bundle_hash, version, rfc3339_ms(loaded_at), rules_count),
        )
        return True

    # ------------------------------------------------------------- checkpoints

    def record_checkpoint(
        self, *, seq_from: int, seq_to: int, merkle_root: str, evidence_seq: int
    ) -> None:
        self._conn.execute(
            "INSERT INTO checkpoints (seq_to, seq_from, merkle_root, evidence_seq, "
            "published_to) VALUES (?,?,?,?,?)",
            (seq_to, seq_from, merkle_root, evidence_seq, json.dumps([])),
        )

    def last_checkpoint(self) -> tuple[int, int, str] | None:
        row = self._conn.execute(
            "SELECT seq_from, seq_to, merkle_root FROM checkpoints ORDER BY seq_to DESC LIMIT 1"
        ).fetchone()
        if row is None:
            return None
        return int(row["seq_from"]), int(row["seq_to"]), str(row["merkle_root"])


def _row_to_record(row: sqlite3.Row) -> EvidenceRecord:
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
