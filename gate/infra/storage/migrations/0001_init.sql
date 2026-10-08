-- SPEC §15. Forward-only. Applied at startup; never edited after release.
-- Dialect note: these statements are deliberately in the SQL subset both
-- SQLite and PostgreSQL accept, so the Postgres path in week 6 reuses the file.

CREATE TABLE IF NOT EXISTS evidence (
  seq            BIGINT PRIMARY KEY,
  ts             TEXT    NOT NULL,
  type           TEXT    NOT NULL,
  assurance      TEXT    NOT NULL,
  mode           TEXT,
  enforcement    TEXT,
  dev            BOOLEAN NOT NULL DEFAULT FALSE,
  schema_version TEXT    NOT NULL,
  payload_hash   TEXT    NOT NULL,
  payload        TEXT,                       -- JSON; NULL once purged (SPEC §10.6)
  prev_hash      TEXT    NOT NULL,
  hash           TEXT    NOT NULL UNIQUE,
  key_id         TEXT    NOT NULL,
  sig            TEXT    NOT NULL,
  proposal_id    TEXT,                       -- denormalised for queries
  approval_id    TEXT,
  principal_hash TEXT
);
CREATE INDEX IF NOT EXISTS ix_evidence_ts ON evidence(ts);
CREATE INDEX IF NOT EXISTS ix_evidence_proposal ON evidence(proposal_id);
CREATE INDEX IF NOT EXISTS ix_evidence_type ON evidence(type);

CREATE TABLE IF NOT EXISTS evidence_outbox (
  id          TEXT PRIMARY KEY,
  created_at  TEXT NOT NULL,
  record_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS checkpoints (
  seq_to       BIGINT PRIMARY KEY,
  seq_from     BIGINT,
  merkle_root  TEXT,
  evidence_seq BIGINT,
  published_to TEXT
);

CREATE TABLE IF NOT EXISTS signing_keys (
  key_id     TEXT PRIMARY KEY,
  alg        TEXT,
  public_pem TEXT,
  source     TEXT,
  created_at TEXT,
  retired_at TEXT
);

CREATE TABLE IF NOT EXISTS principals (
  principal_hash TEXT PRIMARY KEY,
  sub            TEXT,
  display_name   TEXT,
  idp_iss        TEXT,
  created_at     TEXT,
  erased_at      TEXT
);

CREATE TABLE IF NOT EXISTS tokens (
  jti            TEXT PRIMARY KEY,
  principal_hash TEXT,
  agent_chain    TEXT,
  scope          TEXT,
  budget         TEXT,
  mandate_id     TEXT,
  parent_jti     TEXT,
  exp            TEXT,
  issued_at      TEXT,
  revoked_at     TEXT
);

CREATE TABLE IF NOT EXISTS budgets (
  token_jti        TEXT PRIMARY KEY,
  steps_used       INTEGER DEFAULT 0,
  tokens_used      BIGINT  DEFAULT 0,
  money_used_cents BIGINT  DEFAULT 0,
  first_seen       TEXT,
  updated_at       TEXT
);

CREATE TABLE IF NOT EXISTS proposals (
  id              TEXT PRIMARY KEY,
  ts              TEXT,
  token_jti       TEXT,
  principal_hash  TEXT,
  kind            TEXT,
  name            TEXT,
  target          TEXT,
  params_hash     TEXT,
  environment     TEXT,
  adapter_id      TEXT,
  enforcement     TEXT,
  mode            TEXT,
  proposal_json   TEXT,
  verdict_json    TEXT,
  linked_approval TEXT
);

CREATE TABLE IF NOT EXISTS approvals (
  id            TEXT PRIMARY KEY,
  proposal_id   TEXT,
  dedupe_key    TEXT,
  status        TEXT,
  approvers     TEXT,
  created_at    TEXT,
  expires_at    TEXT,
  escalate_at   TEXT,
  escalated     BOOLEAN DEFAULT FALSE,
  decided_at    TEXT,
  approver_hash TEXT,
  decision      TEXT,
  window_until  TEXT,
  reason        TEXT,
  request_json  TEXT
);
CREATE INDEX IF NOT EXISTS ix_approvals_dedupe ON approvals(dedupe_key, status);

CREATE TABLE IF NOT EXISTS approval_windows (
  dedupe_key  TEXT,
  approval_id TEXT,
  until       TEXT,
  PRIMARY KEY (dedupe_key, approval_id)
);

CREATE TABLE IF NOT EXISTS mandates (
  id             TEXT PRIMARY KEY,
  for_agent      TEXT,
  issued_by_hash TEXT,
  mandate_json   TEXT,
  valid_from     TEXT,
  valid_until    TEXT,
  revoked_at     TEXT
);

CREATE TABLE IF NOT EXISTS adapters (
  adapter_id       TEXT PRIMARY KEY,
  kind             TEXT,
  secret_hash      TEXT,
  cert_fingerprint TEXT,
  created_at       TEXT,
  rotated_at       TEXT
);

CREATE TABLE IF NOT EXISTS policy_bundles (
  hash           TEXT PRIMARY KEY,
  version        TEXT,
  loaded_at      TEXT,
  rules_count    INTEGER,
  diff_json      TEXT,
  loaded_by_hash TEXT
);

CREATE TABLE IF NOT EXISTS history_daily (
  principal_hash TEXT,
  target         TEXT,
  day            TEXT,
  calls          INTEGER,
  blocks         INTEGER,
  PRIMARY KEY (principal_hash, target, day)
);

CREATE TABLE IF NOT EXISTS instance (
  k TEXT PRIMARY KEY,
  v TEXT
);
