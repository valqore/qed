-- SPEC §13's `GET /evidence/by-ref/{outbox_id}`. Forward-only.
--
-- The API hands a caller an outbox id before the record is chained, and has to
-- keep answering that reference afterwards. The outbox row itself is deleted
-- when the leader drains it, so the mapping needs somewhere to live that
-- outlives the queue entry -- otherwise a reference would resolve only during
-- the window in which nobody needs it.
--
-- Deliberately not a column on `evidence`: that table is append-only from the
-- store's point of view and carries only what the chain format defines. An
-- outbox id is an artefact of how a record arrived, not part of what it says.
CREATE TABLE IF NOT EXISTS outbox_refs (
  id  TEXT PRIMARY KEY,
  seq BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_outbox_refs_seq ON outbox_refs(seq);
