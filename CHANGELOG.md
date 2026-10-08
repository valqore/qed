# Changelog

All notable changes to this project. Format: [Keep a Changelog]. Versioning:
semver, with `schema_version` of `ActionProposal` / `EvidenceRecord` tracked
independently (SPEC §25.6).

## [0.1.0] — 2026-10-07

Weeks 1 and 2 of the SPEC §22 build order.

> **Tagged locally, not published.** SPEC §22 week 2 also makes the repository
> public as `v0.1.0`. That step waits on the three pre-repo decisions — patent
> scope, product name, licence timing — and the CI job *No LICENSE file until
> SPEC 24.2 closes* enforces the wait. See `PATENT-AND-LICENCE-GATE.md` and
> `REPO-AND-PUBLICATION-PLAN.md`.

### Added — week 2 (SPEC §22)

- `gate/adapters/mcp/`: the MCP proxy. MCP server toward the agent, MCP client
  toward the upstream, over stdio or Streamable HTTP, on the official `mcp` SDK.
  `initialize` keeps the upstream's `serverInfo` and adds a note to
  `instructions`; capabilities are mirrored rather than claimed, so the proxy
  never advertises `prompts` to a client whose upstream has none. `resources/read`
  and `prompts/get` are forwarded, recorded and never refused (SPEC §12.1).
- `gate/adapters/mcp/intent.py`: tool-call classification into the SPEC §3.1
  hints. Reads the arguments as well as the tool name. See "Changed from the
  spec" below — this is the week 1 review's carry-forward item.
- `gate/adapters/mcp/targets.py`: `target_template` with `{server}`, `{tool}`,
  `{env}` and `{args.<dotted.path>}`. Validated at startup; substituted values
  are sanitised, because a tool argument is attacker-influenced input.
- `gate/adapters/common.py`: proposal building shared by every adapter —
  `params_hash` over the whole parameters, a bounded `params_redacted` that
  honours the SPEC §17 16 KB limit, ULID proposal ids.
- `gate/api/`: FastAPI app. `POST /v1/proposals`, `GET /v1/proposals/{id}`,
  `POST /v1/proposals/{id}/result`, `GET /v1/evidence`,
  `GET /v1/evidence/by-ref/{ref}`, `GET /healthz`, `GET /readyz`. RFC 9457
  `problem+json` throughout, including for 404s and validation failures.
  `readyz` is false without a signing key, with a broken policy bundle, or
  without usable adapter authentication (SPEC §17).
- `gate/api/auth.py`: adapter authentication. `X-Gate-Adapter-Id` plus an
  HMAC-SHA256 over method, path, timestamp, nonce and body digest. Secrets come
  from environment variables named in `gate.yaml`, never from the file itself.
- `gate/core/evidence/export/oscal.py`: OSCAL 1.1.2 `assessment-results`. One
  observation per evidence record, one finding per (rule hit, control), public
  keys and checkpoint roots in `back-matter`. All identifiers are derived
  version-5 UUIDs, so the same range exports byte-identically every time.
  Validated against the vendored NIST schema in CI (SPEC §10.8, MUST pass).
- CLI: `gate serve` and `gate mcp`; `gate export --format oscal`.
- `deploy/Dockerfile`: two-stage, distroless, non-root, no shell in the runtime
  image, no `VOLUME` line (an anonymous volume is how an evidence chain
  disappears on `docker run`).
- `gate/core/evidence/hashing.py::principal_hash`: one definition of how a human
  principal is hashed, so the proxy today and week 3's token verification
  attribute to the same principal.
- `docs/api.md`, `docs/mcp-proxy.md`, `docs/oscal.md`; `docs/assurance-classes.md`
  updated for the three classes that now exist.
- Tests: the week 2 exit criterion end to end against a real MCP server process
  (`tests/adapters/`), API and auth suites (`tests/api/`), OSCAL schema
  validation with negative controls (`tests/evidence/test_oscal_schema.py`), and
  14 golden cases built through the real adapter path
  (`tests/policy/test_golden_mcp.py`). 922 tests, up from 595.

### Fixed — week 2

- `gate/core/evidence/masking.py`: the card-number masker corrupted identifiers
  gate itself generates. Luhn is a checksum, not an identifier — a run of
  eighteen zeros passes it exactly, because the sum is 0 and 0 is divisible by
  10 — so the ULID-shaped `token_jti` `01JB000000000000000000JTI0` was rewritten
  to `01JB[masked:card]JTI0` *inside the chain*, in every proposal record. The
  recorded token then no longer matched the token the API and the week 3 budget
  ledger know about, and a corrupted identifier is indistinguishable from a
  redacted one. A candidate now also has to have more than one distinct digit
  and an issued-card prefix (2–6). Every real card range is still masked.

  This changes `payload_hash` for records whose payload contains such a run.
  Nothing has been released and no fixtures existed, so no chain in the world
  is affected; the hash algorithm itself is unchanged and existing records still
  verify, since each was hashed over whatever it stored.

### Changed — week 2

- `gate mcp` requires `--human` or `--mandate`. Without identity, `evaluate`
  short-circuits to a synthetic `AG-IDN-007` BLOCK *before* any rule in the
  bundle runs, so the chain would fill with identical identity blocks in which
  no policy rule had ever been evaluated — and in shadow mode nothing would be
  stopped and nothing would look wrong. `--human` is recorded as
  adapter-asserted in `client_fingerprint`, which SPEC §3.1 defines as advisory
  and never enforced on. Verified identity is week 3.
- `gate/config.py`: `api` and `adapters` sections are now read, and removed from
  `UNIMPLEMENTED_SECTIONS`.
- `SqliteStore`: added `get_proposal`, `evidence_at`, and a `types` filter on
  `iter_evidence`.
- SPEC §20.3: `jsonschema` added to the dev/test dependencies, for the OSCAL
  schema check. SPEC §10.8 permits JSON Schema in place of `oscal-cli`, which
  would put a JVM in CI.
- `mcp` is pinned `>=2.3,<3`. The 2.0 SDK replaced the decorator-based low-level
  server with the `on_*` callbacks the proxy uses, so a 1.x resolution would not
  import.

### Changed from the spec — week 2

- **`mcp/gateway.py` is not ported as SPEC Appendix B says.** Its blast-radius
  function reads:

  ```python
  try:
      from valqore.agents.action_intent import normalize

      ...
  except Exception:
      nb, nct = "low", "unknown"
  ```

  `action_intent` imports `valqore.codegen.validate` at module level, which
  pulls in the IaC parser and the rule engine. The Phase-0 inventory measured
  import isolation with `sys.modules`, which only sees top-level imports of
  already-loaded modules, so that chain did not show up. Ported as written into
  a tree with no `valqore` package, the import raises, the bare `except`
  swallows it, and the function returns `low` for everything. Nothing errors and
  nothing logs; blast radius silently degrades to matching the tool name, and
  `execute_sql` carrying `DROP TABLE orders` stops routing to approval. In
  shadow mode nobody would notice, and enforce starts in week 10.

  The useful half — the verb tables, earned on tools agents really call — is
  written out in `gate/adapters/mcp/intent.py` with no import that can fail.
  Valqore's "sensitive → high" half is deliberately left out: the kernel's
  `blast_radius.py` already scores that surface, already reads `params_redacted`,
  and is inside the policy hash where an auditor can replay it.
  `tests/adapters/test_import_boundary.py` holds both halves of the line — an
  import allowlist for `intent.py`, and a check that no broad `except` on the
  decision path neither logs, records nor refuses.

### Added — week 1 (SPEC §22)

- Repo skeleton, `ruff` + `mypy --strict` + `pytest` in CI, no-network and
  no-LLM import guards on `gate.core`.
- `gate/core/schemas.py`: full SPEC §3 domain model on Pydantic v2, frozen and
  `extra="forbid"`. Timestamps are RFC 3339 UTC at millisecond precision with a
  deterministic serializer.
- `gate/core/jcs.py`: RFC 8785 canonical JSON, used for every hash.
- `gate/core/evidence/`: record construction, SPEC §10.2 hash, Ed25519
  signatures, Merkle checkpoints, secret/PII masking at write.
- `gate/infra/storage/sqlite.py` + forward-only migrations: the evidence ledger
  and the SPEC §15 tables week 1 needs.
- `gate/infra/keys/file.py`: file-backed Ed25519 keys, `gate keys init`.
- `gate/core/policy/`: loader (rules, overrides, disables), linter (all SPEC
  §4.3 error classes), predicate evaluator (SPEC §4.4), engine (SPEC §5),
  deterministic blast-radius table.
- `gate/core/policy/packs/agent-baseline/`: 15 baseline rules.
- `packages/gate-verify/`: standalone verifier, `cryptography` only.
- CLI: `keys init`, `check`, `policy lint|explain`, `export`, `verify`.
- 62 golden policy cases; chain, Merkle, masking, JCS, lint and CLI suites.

### Deliberately not added

- No `LICENSE` file and no `license` metadata. See
  `PATENT-AND-LICENCE-GATE.md` — SPEC §24.2 (patent scope) must close first
  because the Apache-2.0 patent grant is irrevocable once distributed.

### Changed from the spec

- `gate/core/policy/blast_radius.py` is **written fresh**, not ported from
  Valqore `governance/blast_radius.py`. See `docs/adr/0001-blast-radius-table.md`.
