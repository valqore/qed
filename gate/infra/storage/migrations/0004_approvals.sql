-- Approvals: the columns separation of duties needs (SPEC §9).
--
-- 0001 created `approvals` with the state machine's own columns. What was
-- missing is the one fact the whole control turns on: who the action was for.
-- Without `principal_hash` on the row, "the approver is not the principal"
-- cannot be checked at decision time, and a service that cannot check it can
-- only claim it.
--
-- `window_max` comes from the rule that fired. It is stored per request
-- rather than looked up at decision time because the rule set can be
-- reloaded between the request and the decision, and an approver should be
-- bounded by the rule that was in force when the action was proposed.
--
-- Runs exactly once; see `schema_migrations` and the note in 0002.

ALTER TABLE approvals ADD COLUMN principal_hash     TEXT;
ALTER TABLE approvals ADD COLUMN window_max_seconds INTEGER;

CREATE INDEX IF NOT EXISTS ix_approvals_status_expiry ON approvals (status, expires_at);
