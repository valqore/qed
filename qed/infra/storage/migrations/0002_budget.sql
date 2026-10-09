-- Budget ledger, part 2 (SPEC §8).
--
-- 0001 created `budgets` with the usage columns. What was missing is the caps:
-- without them the row records what a token spent but not what it was allowed
-- to spend, so `BudgetState.exhausted` had nothing to compare against and the
-- AG-BUD-* rules could never fire against stored state.
--
-- Caps live next to usage so that a charge is one read-modify-write under one
-- write lock. Carrying caps in the token instead would mean the atomic path
-- has to join two sources at decision time.
--
-- This script runs exactly once; `migrate()` keeps a ledger in
-- `schema_migrations`, because `ALTER TABLE ... ADD COLUMN` cannot be made
-- idempotent in SQLite the way `CREATE TABLE IF NOT EXISTS` can.

ALTER TABLE budgets ADD COLUMN cap_steps       INTEGER NOT NULL DEFAULT 0;
ALTER TABLE budgets ADD COLUMN cap_tokens      BIGINT  NOT NULL DEFAULT 0;
ALTER TABLE budgets ADD COLUMN cap_seconds     INTEGER NOT NULL DEFAULT 0;
ALTER TABLE budgets ADD COLUMN cap_money_cents BIGINT  NOT NULL DEFAULT 0;
ALTER TABLE budgets ADD COLUMN currency        TEXT    NOT NULL DEFAULT 'USD';

-- The first moment the token was spent. Only ever moves from NULL to a time:
-- a later charge must not overwrite the cause.
ALTER TABLE budgets ADD COLUMN exhausted_at    TEXT;

-- Per-principal daily aggregate (SPEC §8, last bullet). Feeds
-- `derived.history`; kept here rather than computed from `proposals` so that a
-- retention purge of payloads does not erase the counts a policy reads.
CREATE TABLE IF NOT EXISTS budget_daily (
  principal_hash   TEXT NOT NULL,
  day              TEXT NOT NULL,
  steps_used       INTEGER NOT NULL DEFAULT 0,
  tokens_used      BIGINT  NOT NULL DEFAULT 0,
  money_used_cents BIGINT  NOT NULL DEFAULT 0,
  PRIMARY KEY (principal_hash, day)
);
