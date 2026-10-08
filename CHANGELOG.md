# Changelog

All notable changes to this project. Format: [Keep a Changelog]. Versioning:
semver, with `schema_version` of `ActionProposal` / `EvidenceRecord` tracked
independently (SPEC §25.6).

## [Unreleased]

### Added — approval service, core and CLI (SPEC §9, week 4)

- A `REQUIRE_APPROVAL` verdict now resolves against what a human has already
  said about that exact action: an open window makes it ALLOW, a recent
  denial makes it BLOCK, a pending request links to it, and otherwise a
  request is opened. All four happen before the verdict is written, so the
  chain records the decision that was acted on.
- **Separation of duties is enforced, not reported.** The approver may not be
  the principal (`AG-SOD-001`), may not be a service identity, and must be in
  the group the rule named (`AG-SOD-002`). A refused attempt is written to the
  chain: somebody trying to approve their own production delete is exactly
  what an auditor wants to find later, and a refusal that leaves no trace is
  indistinguishable from an attempt that never happened.
- Dedupe on `sha256(principal | name | target | params_hash)`. Parameters are
  in, because an approval for `DROP TABLE orders_archive` must not cover
  `DROP TABLE orders`. Environment and time are out, because two identical
  actions a minute apart are one question and an approver should see one
  request, not forty.
- `--window` grants every identical action for a period, keyed on the dedupe
  key so it covers *that action* rather than that person or that rule.
  Windows are not extendable. The length is the smallest of the request, the
  rule ceiling and the service ceiling; an approver cannot widen a rule's own
  bound by asking.
- The rule's timeout, approvers and window ceiling are copied onto the
  request at creation, not looked up at decision time. The bundle can be
  reloaded in between, and an approver should be bounded by the rule in force
  when the action was proposed. Where rules disagree the tighter one wins.
- `gate approve` and `gate approvals [--expire]`; `approval_requested`,
  `approval_decided` and `approval_expired` reach the chain.
- `0004_approvals.sql` adds `principal_hash` and `window_max_seconds`.
  Without the principal on the row, "the approver is not the principal"
  cannot be checked at decision time -- only claimed.
- `docs/approvals.md`.

Not yet: Slack Block Kit, `/events` SSE, the web approval page. The decision
path they would call is finished and is the one `gate approve` uses.

### Added — baseline pack, 15 rules to 45 (SPEC §22 week 3)

Thirty new rules across the five existing families: blast radius 10, budget 7,
data 12, identity 8, skills 8. 29 enforce, 16 shadow; 18 BLOCK, 27
REQUIRE_APPROVAL. The golden table goes from 74 cases to 107 and every rule
has one, which `test_every_shipped_rule_is_exercised` enforces.

The theme of the second set is that it mostly does not read the declared
hints. The first fifteen trust what the adapter said; these match the verb,
the target, or the absence of something, because an adapter that forgot to set
`deletes` on a teardown call is exactly the case the hints cannot catch.

Four of them are about the actions that make later actions invisible or
unrecoverable -- audit logging off, encryption off, backups weakened, data
made public -- which are worth blocking on their own terms whatever the agent
was trying to achieve.

### Fixed — three rules I got wrong, caught by the existing suites

- **`` does not bound a snake_case verb.** `terminate` never matches
  `terminate_instances`, because `_` is a word character, and tool names are
  full of snake_case. AG-BLR-007 and AG-BLR-010 silently matched nothing until
  their own cases failed.
- **AG-SKL-007 flagged `resources/read`**, which is an MCP protocol method and
  entirely ordinary. The regex only allowed the `server.tool` shape. Caught by
  the MCP golden table, which builds proposals through the real adapter rather
  than hand-writing them -- the exact gap its docstring says it exists to
  close.
- **AG-BLR-007 blocked single-instance teardown**, escalating a documented
  REQUIRE_APPROVAL to BLOCK with no approval path. Narrowed to the verbs that
  take a whole system away; AG-BLR-003 already handles one instance, with a
  route for a person to say yes.

Two more were over-broad rather than wrong and were narrowed before they
shipped: AG-BUD-005 fired on reads (ambient noise is how a shadow rule gets
ignored) and AG-IDN-004 was harsher than the AG-BLR-004 it backs up.

### Added — `history` in policy cases

`derived.history` is a documented field path and rules read it, but a case
could not set it, so any rule keyed on call or block counts was untestable.
An untestable rule is one nobody can change safely.

### Added — `gate policy test` (SPEC §14)

- Runs cases you write against the rules you have loaded. Touches nothing: no
  chain, no store, no network. Exit 0 all passed, 1 a case failed.
- `expect.rules` is the **exact** set of rule ids and is required, not
  optional. A case that checks only the decision passes when the right answer
  arrives from the wrong rule, which is worse than no case because it reads
  like coverage. Pinning the exact set means a case fails both when a rule
  stops firing and when an unrelated one starts -- the second is what catches
  a rule widened by accident.
- Every case is evaluated twice, the second time against a reshuffled bundle.
  ADR-002.2 says a decision must not depend on rule load order and this is the
  only thing that shows it; rule authors get the check on their own rules for
  free. `--no-order-check` opts out while iterating.
- `--coverage` lists loaded rules no case mentions.
- A case whose proposal does not validate is a failing case, not an exception,
  so one malformed entry does not hide every case after it.
- `docs/policy-testing.md`.

### Changed — the golden suite and the CLI share one comparison

`tests/policy/test_golden.py` now compares through `gate.core.policy.cases`,
the same code `gate policy test` uses. Two comparison routines would drift and
the one that drifted would be the user's; ours is the one with a CI job behind
it. The 74 golden cases still each run twice -- the shuffle moved inside
`run_case` rather than being a separate parametrized test, which is why the
total test count falls while coverage does not.

### Added — mandate lifecycle (SPEC §6.5)

- `gate mandate sign | list | revoke`, completing §6. Mandates were already
  consumed by `gate check --mandate`, the MCP proxy and the API envelope;
  there was no way to issue, store or withdraw one.
- `gate/core/mandates.py` (pure): the signing payload, signature verification
  and the active/inactive question. Ed25519 only, with no algorithm field read
  off the document -- the same rule as the token path.
- **What is signed is the document minus `signature` and minus `revoked_at`.**
  A signature cannot cover itself; the second exclusion is the one that
  matters. Revocation is an act of the gate, recorded in the chain, not an
  edit the signer authorised, so a revoked mandate still verifies against the
  signature its issuer produced. Including `revoked_at` would mean revoking a
  mandate destroyed the proof of who granted the authority -- exactly the
  record an investigation needs.
- The document is stored whole, as the canonical JSON that was signed.
  Rebuilding it from columns risks bytes that differ from what the signer
  produced, and a signature that no longer verifies is indistinguishable from
  a forged one.
- `mandate_issued` and `mandate_revoked` reach the evidence chain. Revoking
  twice is refused rather than recorded twice.
- An unknown signing key is a failure, not a skip: treating "this instance
  does not hold that key" as "probably fine" is how an unsigned document gets
  accepted.

### Added — delegation (SPEC §6), week 3

- **`POST /v1/token`** (RFC 8693): an IdP token in, a narrower budgeted gate
  token out. Scope is intersected with what the subject's groups hold, budget
  is capped per axis, lifetime is the smallest of the request, an hour, the
  parent's remaining life and the mandate's. `refused_scope` comes back so a
  misconfigured agent fails at the exchange rather than at its first action.
- **`gate login`** (RFC 8628 device flow) and **`gate token`**. Both were
  already in SPEC §14's list of 18, so no spec update was needed. The refresh
  token goes to the OS keychain, or a 0600 file with a warning where there is
  none.
- **`GET /.well-known/jwks.json`**, outside `/v1` on purpose: every `/v1` route
  refuses an unsigned request and that test has no exemption list.
- `gate/core/delegation/` (pure) and `gate/infra/{tokens,jwks}.py` (I/O).
- `deploy/keycloak/`: a real Keycloak with the realm imported, and `demo.sh`,
  which runs the week-3 exit criterion end to end.
- `docs/delegation.md`.

### Fixed — three things only a real identity provider showed

Found by running the demo against Keycloak 26 instead of a fixture. All three
were invisible to the synthetic tests, because those built claims the way the
gate itself writes them.

- **`scope` is a space-delimited string** (RFC 6749 §3.3), not a list. Both
  forms are accepted now.
- **A token could declare its own kind.** `TokenClaims.token_type` defaulted to
  `"gate"`, so an IdP token — which carries no such claim — arrived looking
  gate-issued and was handed to the narrowing check as its own parent, failing
  every exchange. Whether a token is gate-issued is decided by *which key
  verified it*; the field is gone and a test asserts nothing reads it again.
  This is the same rule as never reading `alg` from the token.
- **A narrowing violation during mint escaped as a 500.** It is a caller asking
  for more than the subject token holds, so it is a 400.

### Fixed — `--config` on the commands that open a session

`export`, `status`, `checkpoint` and `verify` opened a session without a config
path, so they read the default `instance_id` and refused to touch a chain
written by any deployment that had set one. The demo hit it on its first
complete run.

### Changed — Keycloak realm requests the `basic` client scope

Keycloak 26 omits `sub` from the access token without it. A token with no
subject cannot name a principal, so the gate refuses it — correctly, but the
shipped realm should not produce one.

### Added — budget ledger (SPEC §8), week 3

- **Budgets are persisted and charged.** `check_proposal` previously passed an
  empty `BudgetState` into the engine, so `derived.budget.*` was always zero
  and the three AG-BUD-* rules could never fire against stored state. The caps
  now live in `budgets` next to the usage, a decision reads them, and an action
  that runs is charged.
- `gate.core.budget` holds the arithmetic and stays pure: `charge_for` (cost
  from the adapter's estimate), `apply_charge`, `newly_exhausted`. The atomic
  read-modify-write is `SqliteStore.charge_budget`, under the same
  `BEGIN IMMEDIATE` write lock `append_evidence` uses and for the same reason —
  two adapters charging one token must not both read the same `steps_used`.
- **A charge follows what happened, not what was decided.** In enforce mode a
  BLOCK stops the action and nothing is spent. In shadow mode — the shipped
  default — the adapter proceeds whatever the verdict says, the tokens are
  really spent upstream, and the ledger says so. `effective_decision` already
  encoded that difference.
- Usage may exceed its cap and is not clamped. Clamping would make the ledger
  disagree with what was spent, and the overshoot is what tells an operator the
  cap was set too low.
- `first_seen` is set by the first charge, not at issuance: a `seconds` budget
  that started ticking when a token was minted would punish an agent for the
  gap before it was used.
- Per-principal daily aggregate (`budget_daily`), kept as its own table so a
  retention purge of payloads cannot erase counts a policy reads.
- **No evidence record per charge.** SPEC §8 writes one only on exhaustion, and
  §6.2 writes `budget_update` only when a token is issued. A record per allowed
  action would double the chain, restate what the verdict record already
  implies, and put a signature and an insert on the hot path the week-7 p95
  target has to defend. The first draft of this change did write one; the
  record counts in eleven existing tests were what caught it.
- 41 tests: arithmetic, ledger, migration, and the runtime rules above.
  End-to-end on the CLI: a 2-step token allows two actions, the third is
  blocked by the AG-BUD-001 short-circuit, exactly one `budget_exhausted` sits
  after the verdict that caused it, and `gate-verify` still passes on the
  resulting chain.

### Changed — migrations are applied once

- `SqliteStore.migrate` replayed every script on every open, which worked only
  while every statement was `CREATE TABLE IF NOT EXISTS`. SQLite has no
  `ADD COLUMN IF NOT EXISTS`, so 0002 could not be written that way. A
  `schema_migrations` ledger now records what has run. An existing database has
  no ledger, so 0001 is replayed there once — safe precisely because it is
  idempotent, which is why no backfill was needed.

### Added — licence applied, name settled (SPEC §24.1, §24.2)

- **Apache-2.0 is applied.** `LICENSE` (verbatim, 202 lines) and `NOTICE` at
  the root, and the same two files copied into `packages/gate-verify/` —
  copied, not referenced, because PEP 639 `license-files` globs cannot escape
  a project directory. CI asserts the two licence texts stay byte-identical,
  since a verifier shipped under a stale licence text is the kind of detail an
  auditor is paid to notice.
- `license = "Apache-2.0"` in both `pyproject.toml` files as an **SPDX
  expression**, not the `{text = ...}` table: setuptools 77 deprecated the
  table and now treats a `License ::` classifier next to the expression as an
  error, so there is no such classifier.
- The `Private :: Do Not Upload` classifier is gone from both projects. A PyPI
  upload is no longer refused by its own metadata.
- `PATENT-AND-LICENCE-GATE.md` is deleted. **SPEC §24.2 closed on 2026-10-08:
  Valqore holds no patent filings and has nothing pending**, so the
  irrevocable Apache-2.0 §3 grant transfers nothing. It was answered before
  distribution, which was the entire purpose of withholding the licence.
- The CI job *No LICENSE file until SPEC 24.2 closes* now asserts the
  opposite: both licence files present, both projects declaring Apache-2.0,
  the guard-rail classifier not back, and the gate-verify copy identical.
- **SPEC §24.1 closed: the product is "Valqore Gate".** `gate` stays the
  command, the import package and the repository name. Zero refactor — the
  evidence format already carries no product name (ADR-0006), so nothing in a
  chain written today depends on this choice.

### Still not public

The remote stays private until the PyPI, npm, GHCR, Homebrew-tap, domain and
EUIPO/USPTO reservations are in place (`REPO-AND-PUBLICATION-PLAN.md` §5).
Applying a licence is reversible for as long as nobody has received the code;
publishing is not.

### Changed — evidence format

- **Breaking, pre-release.** The hash domain separators no longer carry the
  product name (ADR-0006). `"gate-genesis:"` becomes
  `"evidence-chain/1:genesis:"`, `"gate-principal:"` becomes
  `"evidence-chain/1:principal:"`, and `chain_format` / `chain-format` becomes
  `evidence-chain/1`. Genesis hashes and principal hashes therefore change.
  Nothing outside the test suite has written a chain, so there is nothing to
  migrate; doing this after a design partner runs the kernel would have meant
  either invalidating their evidence or shipping a retired name in the format
  forever. SPEC §24.1's "the name is a placeholder, a rename is a single
  refactor" is true after this change and was not true before it.
- `gate/core/evidence/format.py` is the single definition. `gate-verify` keeps
  its own copy, as SPEC §10.7 requires, and `tests/evidence/test_format_constants.py`
  checks the two agree, pins the exact bytes against digests recorded outside
  the package, and fails if a candidate product name appears in a hash input.

## [0.1.0] — 2026-10-07

Weeks 1 and 2 of the SPEC §22 build order.

> **Tagged locally, not published.** SPEC §22 week 2 also makes the repository
> public as `v0.1.0`. At this tag that step was waiting on the three pre-repo
> decisions — patent scope, product name, licence timing. All three closed on
> 2026-10-08; see [Unreleased]. The public push now waits only on the name
> reservations in `REPO-AND-PUBLICATION-PLAN.md` §5.

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

- No `LICENSE` file and no `license` metadata, because SPEC §24.2 (patent
  scope) had to close first — the Apache-2.0 patent grant is irrevocable once
  distributed. Lifted in [Unreleased] on 2026-10-08, when §24.2 came back
  clean.

### Changed from the spec

- `gate/core/policy/blast_radius.py` is **written fresh**, not ported from
  Valqore `governance/blast_radius.py`. See `docs/adr/0001-blast-radius-table.md`.
