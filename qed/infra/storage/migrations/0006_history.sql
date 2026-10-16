-- SPEC §5 and §15. The 24-hour history counters, which nothing collected.
--
-- `AG-BUD-007` reads `derived.history.calls_24h` and `AG-IDN-010` reads
-- `derived.history.blocks_24h`. Both rules shipped in week 1 and neither could
-- ever fire: the counters were threaded through `check_proposal` into the
-- engine's context and no caller ever supplied them, so every decision saw
-- zeros. Collecting them needs two things from storage.
--
-- `decision` is denormalised out of the verdict payload. Counting blocks by
-- reading the payload JSON would need a different expression on each backend
-- and would stop working the moment retention strips the payload (SPEC §10.6),
-- so the one field a counter needs becomes a column. It is NULL on every row
-- written before this migration, which means the block counter starts from
-- here rather than claiming a history it cannot see -- stated in `docs/replay.md`
-- because an operator comparing a counter to the chain by hand would otherwise
-- find it short.
--
-- The index is on `(principal_hash, ts)` in that order: every query is "this
-- principal, in this window", so the equality column has to come first.
--
-- Written as the first migration that alters an existing table, which is what
-- the ledger in `schema_migrations` was added for -- SQLite has no
-- `ADD COLUMN IF NOT EXISTS`, so this file must run exactly once.

ALTER TABLE evidence ADD COLUMN decision TEXT;

CREATE INDEX IF NOT EXISTS ix_evidence_principal_ts ON evidence(principal_hash, ts);

-- `history_daily` was created by 0001 and never read or written by anything.
-- It describes a design that was not built: per-principal, per-target, per-day
-- aggregates, where what the rules actually ask for is a rolling window over
-- the chain. Leaving an empty table behind would now be worse than before,
-- because it would read as a second source for numbers that come from
-- `evidence` -- and the first person to find two sources will trust the wrong
-- one.
DROP TABLE IF EXISTS history_daily;
