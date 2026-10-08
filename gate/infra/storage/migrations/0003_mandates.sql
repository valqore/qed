-- Mandate lifecycle (SPEC §6.5).
--
-- 0001 created `mandates` with the document and its validity window. What was
-- missing is everything the lifecycle needs: who signed it, when it was
-- stored, and -- when it is revoked -- by whom and why.
--
-- The document column (`mandate_json`) keeps the canonical JSON that was
-- signed, whole. Rebuilding a document from columns risks bytes that differ
-- from what the signer produced -- a key order, a dropped default -- and a
-- signature that no longer verifies is indistinguishable from a forged one.
--
-- `revoked_at` stays a column rather than an edit to that document, because
-- revocation is an act of the gate recorded in the chain, not something the
-- original signer authorised. A revoked mandate must keep verifying, or
-- revoking one would destroy the proof of who granted the authority.
--
-- Runs exactly once; see `schema_migrations` and the note in 0002.

ALTER TABLE mandates ADD COLUMN purpose         TEXT NOT NULL DEFAULT '';
ALTER TABLE mandates ADD COLUMN key_id          TEXT;
ALTER TABLE mandates ADD COLUMN created_at      TEXT;
ALTER TABLE mandates ADD COLUMN revoked_by_hash TEXT;
ALTER TABLE mandates ADD COLUMN revoked_reason  TEXT;

CREATE INDEX IF NOT EXISTS mandates_for_agent ON mandates (for_agent);
