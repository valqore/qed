# qed — Implementation Specification v0.3.1

**Status:** Ready for implementation · 4 Oct 2026 (consistency review applied)
**Name:** product **Valqore QED**; `qed` is the command, the import package and the repository (§24.1, closed 2026-10-08 — no longer a placeholder)
**Supersedes:** ARCHITECTURE_PLAN.md v0.2 (plan), incorporates DESIGN_DECISIONS.md ADR-001…008 (all ACCEPTED)
**Language:** Python 3.12+ · **License:** Apache-2.0 (kernel), AGPL-3.0 (UI), proprietary (cloud)

---

## 0. How to use this document

This is both the architecture reference and the prompt for whoever (human or coding agent) implements `qed`. Read §1–§3 fully before writing code. Implement in the order of §22. Every section marked **MUST** is a hard requirement; **SHOULD** is a strong default; **MAY** is optional.

**Prompt preamble for a coding agent:**

> You are implementing `qed`, a self-hosted, vendor-neutral policy + evidence kernel for AI-agent actions. Follow `docs/SPEC.md` exactly. The kernel's decision path MUST contain no LLM calls and no network calls (`qed.core.*` imports no HTTP client; a test enforces this). Every decision MUST be deterministic and replayable. Every evidence record MUST be Ed25519-signed and hash-chained with a `key_id` and `schema_version`. Do not add dependencies beyond §20.3 without updating this spec. Prefer small pure functions, Pydantic v2 models, and explicit types. When the spec is silent, choose the simplest option that keeps the decision path pure, and record the choice in `docs/adr/`.

---

## 1. Mission, scope, non-goals

### 1.1 One sentence
An AI agent proposes an action → `qed` verifies who it acts for and with what budget → deterministic rules decide ALLOW / BLOCK / REQUIRE_APPROVAL → a human approves if required → every step is written to a tamper-evident, independently verifiable evidence chain exportable as OSCAL.

### 1.2 In scope (v1)
- Kernel: delegation verification, policy engine, budget ledger, approval service, evidence ledger, credential broker, mandate registry.
- Adapters: MCP proxy (stdio + HTTP/SSE), Claude Code / Codex hooks, HTTP forward proxy, Python SDK, CI command.
- Exports: JSONL, CSV, OSCAL 1.1.2 `assessment-results`, SSE event stream, Prometheus metrics, OCSF-shaped SIEM events.
- Minimal live UI: pending approvals + decision stream.
- Standalone verifier `qed-verify` (stdlib + `cryptography` only).

### 1.3 Explicitly out of scope (v1)
Identity provider functionality; payments; programmatic terms-of-service acceptance; agent self-registration (MCP CIMD); outbound request signing (RFC 9421); skill content scanning; LLM-based anomaly detection; IaC/Kubernetes manifest scanning (stays in Valqore); analytics dashboards; multi-tenant hosting; TypeScript SDK; Okta/AgentCore gateway plugins.

### 1.4 Design invariants (MUST)
1. **No LLM in the trust path.** `qed.core.*` never imports or calls a model. Explanations MAY be LLM-generated in `qed.explain.*`, never consulted by the engine.
2. **No network in the core.** `qed.core.*` imports no `httpx`, `requests`, `aiohttp`, sockets. Enforced by `tests/test_core_has_no_network.py`.
3. **Determinism.** `evaluate(proposal, policy_bundle, budget_state) → Verdict` is a pure function. Same inputs → byte-identical `Verdict` (excluding `ts`).
4. **Evidence is third-party verifiable.** Ed25519 only; no HMAC path exists. The service refuses to start without a signing key (no dev fallback). Dev mode requires explicit `--dev` and stamps every record `dev: true`.
5. **Single chain.** All event types go to one `EvidenceRecord` chain. No side journals.
6. **Vendor neutrality.** Core knows nothing about Okta, Claude, AWS. Adapters and `qed.remote` do.
7. **Zero bytes out by default.** All `qed.remote.*` features are opt-in, outbound-only, carry no customer data (hashes/signatures only), and degrade gracefully when disabled.
8. **PII never enters the chain.** Principals are stored as salted hashes; mapping lives in an erasable table (ADR-005).

---

## 2. Architecture

### 2.1 Component diagram

```
┌──────────────────────────────────────────────────────────────────────────┐
│ AGENTS / CLIENTS   Claude Code · Codex · Cursor · LangGraph · kagent · CI │
└──────┬──────────────┬──────────────────┬───────────────┬─────────────────┘
       │ MCP          │ hook (stdin/out) │ HTTPS_PROXY   │ import qed
┌──────▼──────┐ ┌─────▼─────┐ ┌──────────▼───────┐ ┌─────▼──────┐
│ adapters.mcp│ │adapters.  │ │adapters.http_proxy│ │adapters.sdk│   ← normalize → ActionProposal
│ (stdio/http)│ │hooks      │ │(CONNECT/host-path)│ │ @guard     │   ← attach delegation token
└──────┬──────┘ └─────┬─────┘ └──────────┬───────┘ └─────┬──────┘   ← enforce verdict, report result
       └──────────────┴────────┬─────────┴───────────────┘
                               │ HTTPS  POST /v1/proposals  (adapter mTLS or bearer)
┌──────────────────────────────▼───────────────────────────────────────────┐
│ qed.api (FastAPI)                                                         │
│   routers: proposals · token · approvals · evidence · policies · admin · events │
├───────────────────────────────────────────────────────────────────────────┤
│ qed.core  (pure; no network, no LLM)                                      │
│  delegation ─► policy ─► budget ─► approval ─► evidence                    │
│  mandate     broker(credential resolve only; I/O in qed.infra)            │
├───────────────────────────────────────────────────────────────────────────┤
│ qed.infra  storage(sqlite|postgres) · keys(file|kms) · secrets(env|file|vault) │
│             channels(slack|web|cli) · chain_writer(leader+outbox)          │
├───────────────────────────────────────────────────────────────────────────┤
│ qed.remote (optional, outbound-only)  anchor · packs · intel · buildinfo  │
└───────────────────────────────────────────────────────────────────────────┘
          ▲ OIDC/JWKS (IdP)                 ▲ auditors: qed-verify, OSCAL
```

### 2.2 Request lifecycle (happy path, REQUIRE_APPROVAL)

```
1  adapter      builds ActionProposal, attaches Bearer <delegation_token>, POST /v1/proposals
2  api          authenticates adapter (adapter_id + key or mTLS); rate-limits
3  delegation   verifies JWT (JWKS or qed-issued), checks act-chain narrowing, extracts budget+mandate
4  evidence     append {type: proposal}                                  ← assurance: kernel
5  budget       load BudgetState(token_jti); if exhausted → verdict BLOCK (AG-BUD-001)
6  policy       evaluate(proposal, bundle, budget) → Verdict{REQUIRE_APPROVAL, rules, blast, policy_hash}
7  evidence     append {type: verdict}
8  approval     dedupe (ADR-006.3); create ApprovalRequest; notify channels
9  evidence     append {type: approval_requested}
10 api          respond 202 {verdict: REQUIRE_APPROVAL, approval_id, poll_url, expires_at}
11 adapter      blocks the tool call now (returns ToolError/exit 2 with explanation) OR polls (SDK mode)
12 human        decides via Slack/web/CLI → SoD check → evidence {approval_decided}
13 adapter      (on retry within window or on poll) → verdict ALLOW via approval → forwards call
14 broker       (enforcing adapters) injects upstream credential; agent credential stripped
15 adapter      POST /v1/proposals/{id}/result → evidence {executed, execution_result}  ← assurance: broker|adapter
16 budget       decrement steps/tokens/money
17 events       SSE fan-out to UI/SIEM; metrics updated
```

ALLOW path: steps 1–7, then 13–17 immediately (synchronous 200). BLOCK path: 1–7, respond 200 `{verdict: BLOCK, rules, fix}`, adapter denies.

### 2.3 Processes and deployment shapes
- **Single process** (`qed serve`): API + core + chain writer + channels + UI. SQLite. Laptop / small team.
- **HA** (Helm, ≥2 replicas, Postgres): every replica serves API and decides; exactly one holds `pg_try_advisory_lock(1734440037)` (0x67617465) and drains `evidence_outbox` into the chain (ADR-004). Leader loss → lock released → another replica acquires within seconds; outbox is durable.
- **CI one-shot** (`qed check`): no server; evaluates locally with a policy bundle, writes evidence to a local file or posts to a server if configured.

---

## 3. Domain model (Pydantic v2, `qed/core/schemas.py`)

All models: `model_config = ConfigDict(frozen=True, extra="forbid")`. IDs are ULIDs (26 chars). Timestamps are RFC 3339 UTC with millisecond precision.

### 3.1 ActionProposal
```python
class Principal(BaseModel):
    human_hash: str | None  # sha256(sub + instance_salt) hex; None for unattended
    agent_chain: list[str]  # ordered, outermost first: ["claude-code@laptop-ali", "sub:planner"]
    mandate_id: str | None  # required when human_hash is None
    token_jti: str
    client_fingerprint: (
        str | None
    )  # adapter-provided; ADVISORY (spoofable) — never used for enforcement


class ActionKind(StrEnum):
    mcp_tool = "mcp_tool"
    http = "http"
    shell = "shell"
    skill = "skill"
    custom = "custom"


class Action(BaseModel):
    kind: ActionKind
    name: str  # "github.create_pull_request" | "POST /v2/sg" | "Skill:deploy-prod"
    target: str  # URI-ish resource id: "repo:acme/payments", "db:prod/orders", "aws:ec2:sg-123"
    params_hash: str  # sha256 of canonical JSON of raw params (raw never sent)
    params_redacted: dict | None  # masked copy (ADR-005 masks); optional
    method: str | None  # http only


class BlastHints(BaseModel):
    writes: bool = False
    deletes: bool = False
    scope: Literal["single_resource", "multi_resource", "account", "global"] = "single_resource"


class CostEstimate(BaseModel):
    tokens: int = 0
    money_cents: int = 0
    currency: str = "USD"


class Enforcement(StrEnum):
    advisory = "advisory"
    enforcing = "enforcing"


class Mode(StrEnum):
    shadow = "shadow"
    enforce = "enforce"


class Context(BaseModel):
    environment: Literal["dev", "staging", "prod"]
    tags: list[str] = []
    adapter: str  # "mcp-proxy/0.3.1"
    adapter_id: str  # registered adapter identity
    enforcement: Enforcement  # ADR-001
    mode: Mode  # ADR-003 (service-level, as seen by adapter)
    cost_estimate: CostEstimate = CostEstimate()
    blast_radius_hints: BlastHints = BlastHints()
    intent: str | None  # agent-declared intent, masked
    summary: str  # adapter-built one-liner for approvers, masked


class ActionProposal(BaseModel):
    schema_version: Literal["1.0"] = "1.0"
    id: str  # ULID
    ts: datetime
    principal: Principal
    action: Action
    context: Context
```

### 3.2 Verdict
```python
class Decision(StrEnum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"


class RuleHit(BaseModel):
    rule_id: str
    verdict: Decision
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    mode: Mode
    message: str
    fix: str | None
    compliance: list[ComplianceRef]


class Verdict(BaseModel):
    proposal_id: str
    decision: Decision  # effective (shadow rules excluded)
    would_decision: Decision  # if all shadow rules were enforced (ADR-003)
    hits: list[RuleHit]  # ALL triggered rules, enforce and shadow
    blast_radius: int  # 0–100
    policy_hash: str  # sha256 of canonical bundle
    engine_version: str
    default_applied: bool  # True when no rule matched (AG-DEF-001 recorded)
    approval_id: str | None
    via_approval: str | None  # approval id when ALLOW came from an open window
```

### 3.3 Delegation token (JWT claims)
```json
{
  "iss": "https://qed.acme.internal", "sub": "ali@acme.com" | "svc:sre-agent",
  "aud": "qed", "exp": 1760000000, "iat": 1759998200, "jti": "01J...",
  "act": { "sub": "claude-code@laptop-ali", "act": { "sub": "sub:planner" } },   // RFC 8693 nested actor
  "scope": "mcp:postgres:read mcp:github:* http:aws:ec2:describe*",
  "https://qed.dev/budget": { "steps": 50, "tokens": 200000, "seconds": 1800, "money_cents": 0, "currency": "USD" },
  "https://qed.dev/mandate": "md_01J..." ,          // required for svc: subjects
  "https://qed.dev/env": ["dev","staging"],          // allowed environments
  "https://qed.dev/parent_jti": "01J..."             // when exchanged from another qed token
}
```
Signed by qed's **token key** (separate from evidence key). Alg: EdDSA (Ed25519). Max lifetime 60 min (attended), mandate-bounded (unattended).

### 3.4 Mandate (ADR-008.2)
```yaml
mandate:
  schema_version: "1.0"
  id: md_01J...
  issued_by_hash: <principal_hash>          # the human who signed
  for_agent: "svc:sre-agent"                # IdP client_id or k8s SA
  purpose: "Automated remediation for payment-api alerts"
  allowed:
    kinds: [http]
    name_globs: ["GET *", "PUT /ec2/*", "POST /ec2/*"]
    target_globs: ["aws:ec2:*", "aws:rds:describe*"]
    environments: [prod]
  budget: { steps: 20, tokens: 0, seconds: 600, money_cents: 0 }   # per token
  oversight:
    approvers: [sre-oncall]
    require_approval_when: ["blast_radius > 60"]
  valid: { from: "2026-10-01T00:00:00Z", until: "2026-12-31T23:59:59Z" }
  signature: { key_id: "oidc:okta:kid-abc", alg: "RS256|EdDSA", sig: "..." }   # signed via qed mandate sign (OIDC-authenticated)
```
Stored in `mandates`; issuance appended as evidence `mandate_issued`. Policy engine treats `allowed` as an **additional constraint** (outside → BLOCK `AG-IDN-006`).

### 3.5 EvidenceRecord (ADR-004)
```python
class EvidenceType(StrEnum):
    genesis = "genesis"
    proposal = "proposal"
    verdict = "verdict"
    approval_requested = "approval_requested"
    approval_decided = "approval_decided"
    approval_expired = "approval_expired"
    executed = "executed"
    execution_result = "execution_result"
    budget_update = "budget_update"
    budget_exhausted = "budget_exhausted"
    policy_loaded = "policy_loaded"
    key_rotated = "key_rotated"
    mandate_issued = "mandate_issued"
    mandate_revoked = "mandate_revoked"
    ungated_window = "ungated_window"
    correction = "correction"
    checkpoint = "checkpoint"
    admin_action = "admin_action"


class Assurance(StrEnum):
    kernel = "kernel"
    broker = "broker"
    adapter = "adapter"
    self_ = "self"  # ADR-007


class EvidenceRecord(BaseModel):
    schema_version: Literal["1.0"]
    seq: int  # 0 = genesis, strictly increasing
    ts: datetime
    type: EvidenceType
    assurance: Assurance
    mode: Mode | None  # for proposal/verdict/executed
    enforcement: Enforcement | None
    dev: bool = False
    payload_hash: str  # sha256(JCS(payload))
    payload: dict  # redacted; may be purged after retention (hash remains)
    prev_hash: str
    hash: str  # see §10.2
    key_id: str
    sig: str  # base64url Ed25519 over hash bytes
```

### 3.6 Other entities
`ApprovalRequest`, `ApprovalDecision`, `BudgetState`, `PolicyBundle`, `SigningKey`, `Upstream`, `AdapterIdentity`, `Checkpoint`, `PrincipalMap` — fields in §15 DDL.

---

## 4. Policy language (ADR-002)

### 4.1 File layout
`policies/` directory; `*.yaml` files; each a list of rules. A **bundle** = all files, sorted by `rule_id`, canonicalized. Baseline pack ships in `qed/core/policy/packs/agent-baseline/`.

### 4.2 Rule schema
```yaml
- rule_id: AG-BLR-003                 # ^[A-Z]{2,6}(-[A-Z0-9]{2,8})+$ ; unique in bundle
  name: Destructive action in production
  severity: HIGH                       # LOW|MEDIUM|HIGH|CRITICAL — reporting only, never affects decision
  mode: enforce                        # enforce|shadow (default: pack/service setting)
  applies_to:                          # ALL listed constraints must hold (AND); omitted = any
    kinds: [mcp_tool, http, shell]
    name_globs: ["*"]
    target_globs: ["db:prod/*", "aws:*"]
    environments: [prod]
    adapters: ["mcp-proxy/*"]
  when:                                # predicate tree; omitted = always (given applies_to)
    any:
      - { field: context.blast_radius_hints.deletes, equals: true }
      - { field: action.params_redacted.sql, regex: "(?i)^\\s*(drop|truncate|alter)\\b" }
  verdict: REQUIRE_APPROVAL            # BLOCK|REQUIRE_APPROVAL  (no ALLOW rules)
  approval:                            # only for REQUIRE_APPROVAL
    approvers: [sre-oncall, dba]       # groups (from IdP claims) or principals
    timeout: 10m
    window_max: 30m                    # cap for "approve for N minutes"; default from service config
    escalate_to: [platform-leads]      # optional
    escalate_after: 5m
  message: "Destructive change to a production datastore."
  fix: "Run against staging first or request approval with an explicit intent."
  compliance:
    - { framework: eu_ai_act, control: "Art. 14" }
    - { framework: nist_ai_rmf, control: "GOVERN-1.5" }
    - { framework: owasp_agentic, control: "ASI04" }
  references: ["https://..."]
```

### 4.3 Override and disable
```yaml
- rule_id: AG-DAT-007
  override:
    verdict: REQUIRE_APPROVAL          # may only move BLOCK→REQUIRE_APPROVAL (soften); never →ALLOW
    applies_to: { environments: [staging] }   # may only NARROW
    approval: { approvers: [sec-team] }
- rule_id: AG-SKL-002
  disabled: true
  reason: "We do not use skills; re-enable when Claude Code rollout starts."   # REQUIRED
  disabled_by: "platform-team"
```
Lint errors: override target missing; override hardening; `disabled` without `reason`; duplicate `rule_id`; invalid regex; unknown field path.

### 4.4 Predicates
Leaf: `{ field: <dotted path into ActionProposal | derived>, <op>: <value> }`
Ops: `equals`, `not_equals`, `in`, `not_in`, `glob`, `regex`, `gt`, `gte`, `lt`, `lte`, `exists` (bool), `contains` (string/array).
Composite: `any: [...]`, `all: [...]`, `not: {...}`.
Derived fields available: `derived.blast_radius` (int, computed before rules), `derived.budget.steps_remaining`, `derived.budget.tokens_remaining`, `derived.budget.seconds_remaining`, `derived.budget.money_remaining_cents`, `derived.mandate.present` (bool), `derived.mandate.within` (bool), `derived.chain_depth` (int), `derived.history.calls_24h`, `derived.history.blocks_24h`.
Field access on `params_redacted` only; raw params never reach the engine.

### 4.5 Precedence and defaults (MUST)
1. Compute `applies_to` filter → candidate rules.
2. Evaluate `when` for each candidate → hits.
3. Effective decision = max over **enforce-mode** hits by order `BLOCK > REQUIRE_APPROVAL`; if no enforce hits → `default_verdict` (config; default `ALLOW`) and `default_applied = true`, synthetic hit `AG-DEF-001`.
4. `would_decision` = same over **all** hits (enforce + shadow).
5. Mandate constraint check (`derived.mandate.within == false` for unattended) → synthetic `AG-IDN-006` BLOCK, enforce mode, regardless of rules.
6. Budget exhausted → synthetic `AG-BUD-001` BLOCK before step 1 (short-circuit; still record).
7. Result is independent of rule file order (test).

### 4.6 Baseline pack (`agent-baseline`, ~50 rules) — categories and representative IDs
- `AG-IDN-*` identity/delegation: 001 missing token, 002 expired, 003 chain not narrowing, 004 scope mismatch, 005 unknown adapter, 006 outside mandate, 007 unattended without mandate.
- `AG-BUD-*` budgets: 001 exhausted (BLOCK), 002 ≥80% consumed (shadow→warn via REQUIRE_APPROVAL off by default), 003 money budget hit.
- `AG-BLR-*` blast radius: 001 account/global scope in prod (BLOCK), 002 multi-resource delete (REQUIRE_APPROVAL), 003 destructive in prod (REQUIRE_APPROVAL), 004 IAM/secret/policy mutation (REQUIRE_APPROVAL), 005 scale > threshold.
- `AG-SOD-*` separation of duties: 001 approver == proposer (enforced in approval service, surfaced as rule), 002 agent attempted self-approval.
- `AG-DAT-*` data/egress: 001 secret pattern in params, 002 PII pattern in params, 003 egress to non-allowlisted domain, 007 open ingress 0.0.0.0/0 (BLOCK).
- `AG-SKL-*` skills: 001 unknown skill source, 002 skill requests tools outside token scope, 003 skill without allowed-tools manifest.
- `AG-DEF-001` no rule matched (synthetic).
Each rule carries `compliance` mappings imported from Valqore's AIG rules (mapping data only).

---

## 5. Policy engine algorithm (`qed/core/policy/engine.py`)

```python
def evaluate(
    p: ActionProposal, bundle: PolicyBundle, budget: BudgetState, ctx: DerivedContext
) -> Verdict:
    hits: list[RuleHit] = []
    if budget.exhausted():
        return _synthetic(p, "AG-BUD-001", BLOCK, bundle, ctx)
    derived = compute_derived(p, budget, ctx)  # blast radius, mandate.within, history
    if p.principal.human_hash is None and not derived.mandate.present:
        return _synthetic(p, "AG-IDN-007", BLOCK, bundle, ctx)
    if derived.mandate.present and not derived.mandate.within:
        return _synthetic(p, "AG-IDN-006", BLOCK, bundle, ctx)
    for rule in bundle.active_rules():  # sorted by rule_id; disabled excluded
        if not applies(rule.applies_to, p):
            continue
        if rule.when is None or predicate(rule.when, p, derived):
            hits.append(RuleHit.from_rule(rule))
    enforce_hits = [h for h in hits if h.mode == enforce]
    decision = max_decision(enforce_hits) if enforce_hits else bundle.default_verdict
    would = max_decision(hits) if hits else bundle.default_verdict
    if not enforce_hits:
        hits.append(_default_hit())
    return Verdict(
        decision=decision,
        would_decision=would,
        hits=sorted(hits, key=lambda h: h.rule_id),
        blast_radius=derived.blast_radius,
        policy_hash=bundle.hash,
        engine_version=ENGINE_VERSION,
        default_applied=not enforce_hits,
        proposal_id=p.id,
    )
```
`max_decision`: `BLOCK` > `REQUIRE_APPROVAL`. Blast radius: deterministic table (kind, scope, writes/deletes, environment, name patterns) → 0–100; documented in `docs/blast-radius.md`; ported from Valqore `governance/blast_radius.py` with the K8s-specific parts removed.

`compute_derived.history` reads a **snapshot** passed in `ctx` (collected by the API layer before calling the engine) — the engine itself performs no I/O.

---

## 6. Delegation, tokens, mandates (`qed/core/delegation`, `qed/api/routers/token.py`)

### 6.1 Verifying an incoming token
1. Parse JWT header; `kid` → key: qed token key (qed-issued) or IdP JWKS (cached by `qed.infra.jwks`, offline cache for air-gap).
2. Validate `iss` ∈ configured issuers, `aud == "qed"`, `exp`, `nbf`, `iat` skew ≤ 60 s.
3. Flatten `act` chain → `agent_chain`. Depth ≤ `max_chain_depth` (default 4).
4. If `parent_jti` present: load parent; assert `scope ⊆ parent.scope`, `budget ≤ parent.budget` (each field), `exp ≤ parent.exp`, `env ⊆ parent.env`. Violation → `AG-IDN-003`.
5. `sub` starts with `svc:` → unattended → `mandate` claim REQUIRED, mandate loaded and `valid.until > now`, `for_agent == sub`, not revoked.
6. Produce `Principal` (hash the human `sub` with instance salt; map table upsert).

### 6.2 Token exchange endpoint `POST /v1/token` (RFC 8693)
Request (form or JSON): `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`, `subject_token` (IdP access/ID token **or** a qed token), `subject_token_type`, `actor_token` (optional; agent identity assertion), `requested_token_type=urn:ietf:params:oauth:token-type:jwt`, `scope`, `resource=qed`, extras: `agent_id`, `budget` (requested; capped), `mandate_id` (unattended).
Logic: verify subject; compute allowed scope = `scopes_by_group(IdP groups) ∩ requested`; budget = `min(requested, policy cap for group/mandate)`; lifetime = `min(requested or token_ttl_default, 60m, parent.exp, mandate.valid.until)`; sign with token key; evidence `budget_update{type: token_issued}`.
Response: `{access_token, issued_token_type, token_type: "Bearer", expires_in, scope}`.

### 6.3 Attended login — `qed login` (RFC 8628 device flow)
`qed login` → IdP device authorization → user approves in browser → refresh token stored in OS keychain (`keyring` lib; file fallback with 0600 and a warning). `qed token` uses refresh → IdP access token → §6.2 exchange. Adapters call `qed token` transparently when cached token has < 5 min left.

### 6.4 Unattended — client credentials / K8s SA
Agent obtains IdP client-credentials token (or projected SA token with `aud=qed`) → §6.2 with `mandate_id`. No mandate → 403 `mandate_required`.

### 6.5 Mandate lifecycle (`qed mandate sign|list|revoke`)
`sign`: operator authenticates via device flow; CLI builds the mandate YAML; qed verifies the signer is in `mandate_signers` group; stores; appends `mandate_issued`. `revoke`: appends `mandate_revoked`; tokens referencing it fail at §6.1 step 5 on next use (and `budget_exhausted` is not needed — rejection happens at verification).

---

## 7. Credential broker (ADR-001) (`qed/core/broker`, I/O in `qed/infra/secrets`)

### 7.1 Configuration `upstreams.yaml`
```yaml
upstreams:
  - id: postgres-prod
    kind: mcp                      # mcp | http
    match: { mcp_server: "postgres", environments: [prod] }     # how proposals map to this upstream
    credential:
      source: vault                # env | file | vault
      ref: "secret/data/qed/postgres-prod#DATABASE_URL"
      inject: { type: env, name: DATABASE_URL }                 # for stdio MCP child process
    enforcement: enforcing
  - id: aws-prod
    kind: http
    match: { host_globs: ["*.amazonaws.com"], environments: [prod] }
    credential:
      source: vault
      ref: "aws/creds/qed-prod"                               # dynamic STS creds, TTL 15m
      inject: { type: sigv4 }                                   # sign outgoing request; strip agent auth
    enforcement: enforcing
  - id: github
    kind: mcp
    match: { mcp_server: "github" }
    credential: { source: env, ref: GITHUB_TOKEN, inject: { type: header, name: Authorization, format: "Bearer {value}" } }
```
### 7.2 Behavior (MUST)
- Enforcing adapters strip any agent-supplied `Authorization`/cookies before forwarding.
- Credentials resolved per request, cached in memory ≤ TTL, never logged, never in evidence (only `upstream_id`).
- If an upstream is not configured → adapter is `advisory` for that target and says so in `context.enforcement`.
- `qed doctor` prints posture: enforcing vs advisory per upstream.
- Vault: AppRole or K8s auth; token renewal handled in `qed.infra.secrets.vault`.

---

## 8. Budget ledger (`qed/core/budget`, storage in `qed/infra/storage`)

- Key: `token_jti`. Columns: `steps_used, tokens_used, seconds_first_seen, money_used_cents, updated_at`.
- Atomic decrement: SQLite `BEGIN IMMEDIATE`; Postgres `UPDATE … SET steps_used = steps_used + 1 … WHERE token_jti=$1 RETURNING *`.
- `seconds` budget = `now - first_seen ≤ budget.seconds` (checked at verification).
- Tokens/money from `context.cost_estimate` (adapter-provided; missing → 0 and `AG-BUD-004 unknown_cost` shadow hit).
- Exhaustion → `budget_exhausted` evidence + webhook `budget.exhausted`.
- Optional per-principal daily aggregate (`principal_hash, date`) for policies using `derived.history`.

---

## 9. Approval service (ADR-006) (`qed/core/approval`, channels in `qed/infra/channels`)

### 9.1 State machine
`pending → approved | denied | expired | superseded`. `escalated` is a flag, not a state.

### 9.2 Creation
Dedupe key `K = sha256(principal_hash | action.name | action.target | params_hash)`. If a `pending` request with `K` exists and age < `dedupe_window` (10 min) → link (`proposal.linked_approval`) and return it. If a `denied` with `K` exists and age < 10 min → BLOCK `denied_recently`, no new request.
Request payload (what approvers see): `summary`, `intent`, principal display (from map table), agent chain, environment, `hits` (ids + messages), `blast_radius`, `history` (24h calls/blocks for this principal+target), `params_redacted` (collapsed), `expires_at`, allowed `window_max`.

### 9.3 Decision
Inputs: `approval_id`, `decision ∈ {approve_once, approve_window, deny}`, `window_minutes` (default = service `window_default` 15 m; must be ≤ rule `window_max` if set ≤ service `window_max` 60 m), `reason` (optional; required for deny if config says so), approver identity from channel auth (Slack user → mapped principal via IdP email; web/CLI → OIDC).
SoD (MUST): `approver_hash != principal.human_hash`; approver ∈ rule approvers (group membership from IdP claims, refreshed per decision); approver is human (not `svc:`). Violations recorded `AG-SOD-001/002` and rejected.
Window: creates `approval_window(K, until)`; subsequent proposals matching `K` within window → `ALLOW` with `via_approval`. Windows are **not** extendable; new request after expiry.

### 9.4 Timeout/escalation
Background ticker (leader-only in HA) expires requests → `approval_expired` evidence; escalation at `escalate_after` → notify second group, `escalated=true`. No reachable approvers (group empty / channel failure) → `approval_unreachable` payload flag.

### 9.5 Channels
- **Slack**: Block Kit message with buttons; interactivity endpoint verifies `X-Slack-Signature`; user id → email via `users.info` → principal. Updates message on decision.
- **Web**: `/ui/approvals` (SSO), buttons call `POST /v1/approvals/{id}`.
- **CLI**: `qed approve <id> [--window 15m] [--reason]` using the operator's device-flow identity.
- **Webhook**: generic POST on `approval_requested|decided|expired` for Teams/PagerDuty (v1 generic; native v1.x).

---

## 10. Evidence ledger (ADR-004/005/007) (`qed/core/evidence`, `qed/infra/chain_writer`)

### 10.1 Canonicalization
`JCS` (RFC 8785) for all payload hashing. `payload_hash = sha256(JCS(payload))`.

### 10.2 Hash and signature
```
H = SHA256( schema_version || 0x1f || str(seq) || 0x1f || ts_rfc3339_ms || 0x1f || type || 0x1f || payload_hash || 0x1f || prev_hash )
hash = hex(H)
sig  = base64url( Ed25519.sign(signing_key[key_id], H) )
genesis.prev_hash = hex(SHA256("gate-genesis:" + instance_id))
```
**Superseded by ADR-0006.** The implementation hashes
`"evidence-chain/1:genesis:" + instance_id`, and `principal_hash` likewise uses
`"evidence-chain/1:principal:"`. The product name is deliberately absent from
both: it was `gate` when this line was written and it is QED now, and a hash
domain that carries a brand makes a rename either break every existing chain or
leave a dead name in the one file an auditor reads most closely. The literal
above is left as written so that ADR-0006 still quotes something real.
`assurance`, `mode`, `enforcement`, `dev`, `key_id` are inside `payload` as well (so they are covered by `payload_hash`) and mirrored as columns for querying.

### 10.3 Writer model
- SQLite: single process, direct append in one transaction (`seq = last+1`).
- Postgres: deciders insert into `evidence_outbox(id, created_at, record_json)`; leader (advisory lock) drains in `created_at, id` order, assigns `seq`, computes hash/sig, inserts into `evidence`, deletes outbox row — one transaction per batch (≤100). Decision latency is independent of chain latency.
- API responses return `evidence_ref = outbox id` immediately; `GET /v1/evidence/by-ref/{id}` resolves to `seq` once committed.

### 10.4 Checkpoints
Every 1,000 records or 3,600 s (first reached): compute Merkle root over `hash` of records since last checkpoint (binary tree, duplicate last leaf when odd); append `checkpoint{from_seq, to_seq, merkle_root}`; signed like any record; publish via configured `publishers` (`s3-object-lock`, `git-tag`, `file`, `email`, and `qed-anchor` — the `qed.remote.anchor` client, configured as a publisher entry rather than under `remote:` so there is one source of truth for which anchors are live, ADR-0013). **`qed-anchor` sends six values, not the record** (`log_id`, `seq`, `hash`, `merkle_root`, `key_id`, `sig`): a checkpoint payload carries the previous checkpoint's receipts, whose `target` names the operator's buckets and git remotes, and invariant §1.7 says these features carry hashes and signatures only. `log_id` is required with no default. Publication results (`published_to[]`, receipts) are stored in `checkpoints` table (not in the chain, to avoid recursion); the **next** checkpoint's payload includes the previous checkpoint's receipts.

### 10.5 Keys
`SigningKey(key_id, alg="Ed25519", public_pem, created_at, retired_at, source: file|kms)`. Rotation: `qed keys rotate` → new key active → `key_rotated{old_key_id, new_key_id, new_public_pem}` record signed by the **old** key (continuity) → subsequent records by new key. `qed keys export-public` for auditors. KMS mode (AWS KMS Ed25519 unsupported → use `ECDSA_P256` variant; `alg` field accommodates; default file/Vault-transit Ed25519).

### 10.6 Retention and PII (ADR-005)
`payload` may be purged after `retention` (per type); `payload_hash/hash/sig/prev_hash` never purged → chain verifies forever. Principals appear only as `principal_hash`. Masking at write: regex set for email, phone, IBAN, credit card, JWT, AWS keys, GitHub tokens, private key blocks, `password=` patterns; test fixtures in `tests/masking/`.

### 10.7 Verification (`packages/qed-verify`)
Inputs: records (JSONL or DB export), public keys (PEM by `key_id`), optional checkpoint receipts.
Checks: `seq` contiguous from 0; `prev_hash` linkage; `hash` recomputation (needs `payload_hash`, not payload — works on purged records); signature with `key_id`; `key_rotated` continuity; checkpoint Merkle roots; optional receipt match (S3 object metadata / transparency log inclusion proof).
Modes: `--full`, `--checkpoints`, `--range from:to`. Output: human summary + JSON report + exit code. Zero dependencies beyond `cryptography`.

### 10.8 Exports
- JSONL (raw records), CSV (flattened), **OSCAL 1.1.2 `assessment-results`**: one `result` per export; each evidence record → `observation` (type by `assurance`), each `RuleHit` → `finding` with `related-observations`, `target.target-id = compliance.control` using canonical framework ids; `back-matter` includes public keys and checkpoint receipts. Validate in CI with NIST `oscal-cli` (or JSON Schema) — **MUST pass**.
- `docs/assurance-classes.md` for auditors explains `kernel/broker/adapter/self`.

---

## 11. Compliance mapping (`qed/compliance`)

- `frameworks.yaml`: canonical ids and aliases (`soc2: ["SOC2","SOC 2"]`, `iso42001: ["ISO/IEC 42001","ISO 42001"]`, `eu_ai_act`, `nist_ai_rmf`, `dora`, `owasp_agentic`, `owasp_mcp`, `owasp_llm`, `nist_csf`, `iso27001`). Loader normalizes; unknown framework → lint warning.
- Packs v1 — **authored here, not imported** (ADR-0011: `valqore-engine` is proprietary and this repo is Apache-2.0; titles written against the standards' own published material): `eu_ai_act`, `nist_ai_rmf`, `iso_42001`, `dora`, `owasp_agentic`, `owasp_mcp`, `owasp_llm`, `soc2`, plus `nist_csf` and `iso_27001`. Each pack: controls with ids/labels, the standard's `source` URL, and the edition where identifiers depend on it; rule→control links come from rule `compliance` blocks. A label is the catalogue's description, never a quotation.
- Each pack declares `catalogue: complete|partial`, and **coverage refuses a percentage for a partial one** (ADR-0011) — `n of n` over a curated subset reads as complete and is not. A partial pack must state its `scope`. An unmapped framework still ships a catalogue so the zero is visible. A control no catalogue defines is a lint **error** (an unknown *framework* stays a warning): it would reach OSCAL looking like a real mapping.
- Honesty flags: pack metadata `depth: article|category|pack` — EU AI Act `article`, NIST AI RMF `category`, **DORA `article` since week 9** (Chapter II mapped to Articles 8, 9 and 10, titles checked against EUR-Lex). **ISO 42001 stays `pack`**: the deepening it needs is Annex A, and ISO/IEC 42001 is sold rather than published, so those titles are not available from an authoritative source — ADR-0011 forbids writing them from memory. Unblocked by a licensed copy or by a design partner publishing a signed pack. Exposed in OSCAL as a property so auditors see mapping depth.
- Signed pack updates (`qed.remote.packs`, ADR-0012): a bundle is **one self-contained signed JSON envelope** (`*.qedpack.json`), not a detached `.sig` — two files can be separated and the failure is quiet. The signature is over `qed/core/jcs.py`'s canonical form of the envelope minus `signature`, so `key_id`, `issuer` and `issued_at` are all covered. The **pack key is not the evidence key** (the evidence key says what this instance did; a pack key says what a publisher published), there is no default key, and the bundle's own `key_id` is never accepted as the answer to which key to use — `qed packs import --public-key PEM`. `qed packs verify` shows a bundle and installs nothing. Every import appends an `admin_action` (bundle hash, issuer, `issued_at`, key id, frameworks, signed or not) and **re-issues `policy_loaded`**, because importing a catalogue does not change the policy hash and `policy_loaded` is the record every verdict points at. Unsigned packs load behind `--unsigned` with `unsigned: true` in `policy_loaded` and the frameworks named; provenance comes from the manifest the import wrote, never from the catalogue files. **Refused:** a bundle that would leave an installed rule citing a control it does not define (checked before anything is written — an import must not be able to stop the kernel deciding), and a bundle issued before the installed one. The `url` feed is not built; the air-gap import reaches no network, so no key under `remote:` is read yet.

---

## 12. Adapters (`qed/adapters/*`)

Common adapter library `qed/adapters/common.py`: build proposal, attach token (auto-refresh), call API with timeout (default 2 s decision, configurable), fail-mode handling, local pending queue for `fail_open` (`~/.qed/pending.jsonl`, replayed as `ungated_window`/late records when kernel returns), result reporting.

### 12.1 MCP proxy (`qed mcp -- <cmd>` / `qed mcp --upstream-url …`)
- Implements MCP server toward the client and MCP client toward upstream (both stdio and Streamable HTTP/SSE) using the official `mcp` Python SDK.
- `initialize`: passthrough; inject `qed` into `serverInfo.name` suffix? **No** — keep upstream identity, add capability note in `instructions`.
- `tools/list`: fetch upstream list; filter by token scope (`mcp:<server>:<tool>` globs); cache per session.
- `tools/call`: build `ActionProposal{kind: mcp_tool, name: "<server>.<tool>", target: derive_target(server, tool, args), params_hash, params_redacted, summary, intent from _meta.intent}`; POST; on ALLOW forward with broker credential (if configured) else passthrough; on BLOCK return MCP `ToolError` with `message = "[qed BLOCK] <rule ids>: <message>. Fix: <fix>"`; on REQUIRE_APPROVAL return `ToolError` `"[qed APPROVAL PENDING] id=<approval_id> expires=<ts>. Retry after approval."` (MCP has no async tool completion in v1; SDK mode can poll).
- Target derivation: configurable per server in `upstreams.yaml` (`target_template: "db:{env}/{args.table}"`); default `"<server>:<tool>"`.
- Resources/prompts: passthrough (read-only) but logged as `proposal{kind: mcp_tool, name: "<server>.resources/read"}` in shadow (never blocked in v1).
- Fail mode default `closed`. Mode default from service.

### 12.2 Coding-agent hooks (`qed install claude-code|codex`)
- Claude Code: writes `PreToolUse` hook into project/user settings calling `qed hook claude-code`; reads JSON on stdin (`tool_name`, `tool_input`, `session_id`, `cwd`); maps `Bash → shell`, `Edit/Write → custom(name=fs.write)`, `mcp__<server>__<tool> → mcp_tool`, `Skill → skill`; summary from tool input; exit 0 allow, exit 2 block with reason on stderr (Claude Code shows it to the model); `REQUIRE_APPROVAL` → exit 2 with pending message (hook cannot wait; `--wait` option polls up to timeout for interactive use).
- Codex: equivalent hook/wrapper per Codex docs (implement when API confirmed; wrapper fallback that intercepts `exec`).
- Always `enforcement: advisory`. Fail default `open` in `dev`, `closed` in `prod` profile.
- `qed install` also prints how to lock hooks via managed settings (advisory hardening).

### 12.3 HTTP forward proxy (`qed proxy`)
- Listens for `CONNECT` (host:port) and plain HTTP. v1 default `mode: host_path`: for CONNECT, decision on `host` (+ SNI) only, tunnel passthrough; for plain HTTP, full method/path. Optional `mode: mitm` with customer CA: decrypts, decides on method/path/body-shape, injects broker credentials (sigv4/header), re-encrypts.
- Proposal: `kind: http, name: "<METHOD> <path-or-host>", target: map_host_to_target(host)` (e.g., `*.amazonaws.com` → `aws:<service>:…` using `upstreams.match`).
- Fail default `closed`.

### 12.4 Python SDK (`qed.sdk`)
```python
from qed.sdk import QED, guard

g = QED.from_env()  # QED_URL, token via qed token or QED_TOKEN


@guard(g, kind="custom", target="crm:accounts", summary=lambda a, kw: f"update account {a[0]}")
def update_account(account_id, fields): ...


# or explicit
v = g.propose(
    kind="http",
    name="POST /payments",
    target="stripe:charges",
    params=payload,
    intent="refund order 123",
)
if v.decision == "REQUIRE_APPROVAL":
    v = g.wait(v.approval_id, timeout=600)
```
`guard` raises `QedBlocked(verdict)` / `QedApprovalPending(verdict)`; reports results automatically (`assurance: adapter`).

### 12.5 CI command (`qed check proposal.json [--policies ./policies] [--server URL]`)
Evaluates (locally or via server), prints verdict, exit 0 ALLOW / 2 BLOCK / 3 REQUIRE_APPROVAL. Writes evidence to server if configured, else `./qed-evidence.jsonl` (self-signed with a CI key, `assurance: self`).

### 12.6 Adapter identity
Each adapter registers (`qed adapters add mcp-proxy-ci`) → `adapter_id` + secret (or mTLS cert). API rejects unknown adapters (`AG-IDN-005`). Rotation via CLI.

---

## 13. HTTP API (`qed/api`)

Base `/v1`. Auth: adapters → `X-QED-Adapter-Id` + HMAC-signed request (or mTLS); humans/admins → OIDC bearer. All responses JSON; errors RFC 9457 problem+json.

| Method & path | Purpose | Notes |
|---|---|---|
| `POST /proposals` | Submit ActionProposal | 200 `{verdict, evidence_ref, approval?}`; 202 when REQUIRE_APPROVAL |
| `GET /proposals/{id}` | Fetch proposal + verdict | |
| `POST /proposals/{id}/result` | Report execution `{status, http_status?, error?, cost_actual?}` | assurance from adapter enforcement |
| `POST /token` | RFC 8693 exchange | §6.2 |
| `GET /approvals?status=pending` | List | approver-scoped |
| `GET /approvals/{id}` | Detail for approver UI | |
| `POST /approvals/{id}` | `{decision, window_minutes?, reason?}` | SoD enforced |
| `GET /evidence?from&to&type&format=jsonl|csv|oscal&packs=` | Export | streaming |
| `GET /evidence/by-ref/{outbox_id}` | Resolve to seq | |
| `GET /evidence/verify?from&to` | Server-side verify (convenience; auditors use qed-verify) | |
| `GET /policies` · `POST /policies:reload` · `POST /policies:lint` | Bundle mgmt | reload requires admin approval (ADR-007.2) |
| `GET /mandates` · `POST /mandates` · `POST /mandates/{id}:revoke` | Mandates | signer group |
| `GET /upstreams` | Posture (no secrets) | |
| `GET /events` | SSE stream of evidence (redacted) | UI, SIEM |
| `GET /metrics` | Prometheus | |
| `GET /healthz` · `GET /readyz` | Health | `readyz` false without signing key |
| `POST /admin/keys:rotate` · `GET /admin/keys/public` | Keys | admin approval |

Rate limits: per adapter 100 proposals/s default; per principal 20/s. 429 with `Retry-After`. **Built in week 10**, with three things the line above does not say. The bucket holds **3 seconds' worth** (`BURST_SECONDS`), because an agent making thirty tool calls while deciding what to do next is ordinary and a one-second bucket at 20/s would refuse it -- on `fail: closed` a 429 is a blocked action, so a limit on a gate is a kill switch under load. The sustained rate is unchanged. The limit is **per process**, reported as such in `/v1/status`: four replicas admit four times the number. And it lives under **`api.rate_limit`**, not `adapters.rate_limit`, because `adapters` is a list of credentials in this build and a mapping there would not parse. A refusal writes nothing to the chain.

---

## 14. CLI (`qed`, Typer) — 18 top-level commands (vs. Valqore's 208); no new top-level command without a spec update

`serve [--ui] [--dev]` · `mcp -- <cmd> | --upstream-url` · `proxy` · `hook <agent>` · `install <agent>` · `login` · `token` · `check` · `approve` · `mandate sign|list|revoke` · `policy lint|test|explain|normalize-frameworks` · `keys init|rotate|export-public` · `export` · `verify` (thin wrapper over qed-verify) · `replay <proposal_id>` · `doctor [--offline]` · `adapters add|list|rotate` · `packs import|list|verify`.

---

## 15. Storage schema (SQL; SQLite and Postgres dialects via `qed/infra/storage/migrations/NNNN_*.sql`)

```sql
CREATE TABLE evidence (
  seq BIGINT PRIMARY KEY, ts TEXT NOT NULL, type TEXT NOT NULL, assurance TEXT NOT NULL,
  mode TEXT, enforcement TEXT, dev BOOLEAN NOT NULL DEFAULT FALSE, schema_version TEXT NOT NULL,
  payload_hash TEXT NOT NULL, payload TEXT,                 -- JSON; NULL after purge
  prev_hash TEXT NOT NULL, hash TEXT NOT NULL UNIQUE, key_id TEXT NOT NULL, sig TEXT NOT NULL,
  proposal_id TEXT, approval_id TEXT, principal_hash TEXT   -- denormalized for queries
);
CREATE INDEX ix_evidence_ts ON evidence(ts); CREATE INDEX ix_evidence_proposal ON evidence(proposal_id);
CREATE TABLE evidence_outbox (id TEXT PRIMARY KEY, created_at TEXT NOT NULL, record_json TEXT NOT NULL);
CREATE TABLE checkpoints (seq_to BIGINT PRIMARY KEY, seq_from BIGINT, merkle_root TEXT, evidence_seq BIGINT, published_to TEXT /*JSON*/);
CREATE TABLE signing_keys (key_id TEXT PRIMARY KEY, alg TEXT, public_pem TEXT, source TEXT, created_at TEXT, retired_at TEXT);
CREATE TABLE principals (principal_hash TEXT PRIMARY KEY, sub TEXT, display_name TEXT, idp_iss TEXT, created_at TEXT, erased_at TEXT);
CREATE TABLE tokens (jti TEXT PRIMARY KEY, principal_hash TEXT, agent_chain TEXT, scope TEXT, budget TEXT, mandate_id TEXT, parent_jti TEXT, exp TEXT, issued_at TEXT, revoked_at TEXT);
CREATE TABLE budgets (token_jti TEXT PRIMARY KEY, steps_used INT DEFAULT 0, tokens_used BIGINT DEFAULT 0, money_used_cents BIGINT DEFAULT 0, first_seen TEXT, updated_at TEXT);
CREATE TABLE proposals (id TEXT PRIMARY KEY, ts TEXT, token_jti TEXT, principal_hash TEXT, kind TEXT, name TEXT, target TEXT, params_hash TEXT, environment TEXT, adapter_id TEXT, enforcement TEXT, mode TEXT, proposal_json TEXT, verdict_json TEXT, linked_approval TEXT);
CREATE TABLE approvals (id TEXT PRIMARY KEY, proposal_id TEXT, dedupe_key TEXT, status TEXT, approvers TEXT, created_at TEXT, expires_at TEXT, escalate_at TEXT, escalated BOOLEAN DEFAULT FALSE, decided_at TEXT, approver_hash TEXT, decision TEXT, window_until TEXT, reason TEXT, request_json TEXT);
CREATE INDEX ix_approvals_dedupe ON approvals(dedupe_key, status);
CREATE TABLE approval_windows (dedupe_key TEXT, approval_id TEXT, until TEXT, PRIMARY KEY(dedupe_key, approval_id));
CREATE TABLE mandates (id TEXT PRIMARY KEY, for_agent TEXT, issued_by_hash TEXT, mandate_json TEXT, valid_from TEXT, valid_until TEXT, revoked_at TEXT);
CREATE TABLE adapters (adapter_id TEXT PRIMARY KEY, kind TEXT, secret_hash TEXT, cert_fingerprint TEXT, created_at TEXT, rotated_at TEXT);
CREATE TABLE policy_bundles (hash TEXT PRIMARY KEY, version TEXT, loaded_at TEXT, rules_count INT, diff_json TEXT, loaded_by_hash TEXT);
CREATE TABLE history_daily (principal_hash TEXT, target TEXT, day TEXT, calls INT, blocks INT, PRIMARY KEY(principal_hash, target, day));
```
Postgres additionally: `SELECT pg_try_advisory_lock(1734440037)` (= 0x67617465, ASCII "qed") for chain leader. No ORM; thin repository functions with parameterized SQL; migrations applied at startup (forward-only).

---

## 16. Configuration (`qed.yaml` reference)

```yaml
instance_id: acme-prod-qed            # used in genesis hash; stable
mode: shadow | enforce                 # service default (ADR-003)
default_verdict: ALLOW                 # ADR-002.1
environment_profile: prod | dev        # affects adapter fail defaults
identity:
  issuers: [{ iss: https://acme.okta.com, jwks_cache: /data/jwks/okta.json }]
  token_key: file:///data/token-key.pem
  token_ttl_default: 30m            # attended tokens; hard cap 60m
  max_chain_depth: 4
  scopes_by_group: { developers: ["mcp:*:read", "mcp:github:*"], sre: ["http:aws:*", "mcp:*"] }
  budget_caps_by_group: { developers: { steps: 100, tokens: 500000, seconds: 3600 } }
  mandate_signers: [oncall-leads]
approvals:
  channels: [slack, web]
  slack: { bot_token_env: SLACK_BOT_TOKEN, signing_secret_env: SLACK_SIGNING_SECRET, channel: "#agent-approvals" }
  default_timeout: 10m
  window_default: 15m
  window_max: 60m
  dedupe_window: 10m
  deny_reason_required: true
evidence:
  store: sqlite:///data/qed.db | postgresql://…
  signing_key: file:///data/evidence-key.pem | vault-transit://qed-evidence | awskms://alias/qed (ECDSA_P256)
  checkpoint: { every_records: 1000, every_seconds: 3600, publishers: [{ type: s3-object-lock, bucket: acme-qed-anchors }, { type: file, path: /data/anchors }] }
  retention: { payload: 7y, default: forever }
  masking: default | strict
adapters:
  mcp:   { fail: closed, decision_timeout: 2s }
  http:  { fail: closed, mode: host_path }
  hooks: { fail: open_in_dev }
  rate_limit: { per_adapter_rps: 100, per_principal_rps: 20 }
broker: { upstreams_file: /etc/qed/upstreams.yaml, secrets: { vault: { addr: https://vault.acme, auth: kubernetes } } }
remote:                                   # all optional, outbound-only, hashes only
  anchor: { enabled: false, url: https://anchor.qed.dev }
  packs:  { enabled: false, url: https://packs.qed.dev, public_key: … }
  intel:  { enabled: false }
observability: { metrics: true, events_sse: true, siem: { format: ocsf, webhook: https://splunk… } }
ui: { enabled: true, oidc_client_id: … }
```
Secrets never in `qed.yaml`; only env names or secret-store refs.

---

## 17. Security requirements and threat model summary

Full STRIDE in `THREAT_MODEL.md`. Key MUSTs:
- Service refuses to start without evidence signing key and token key (`readyz=false`).
- Admin operations (`policies:reload`, `keys:rotate`, upstream changes, adapter add) go through the approval service with SoD and produce `admin_action` evidence — qed governs itself. **Built in week 10 (ADR-0014)** for `keys_rotate` and `packs_import`, the two that exist: `admin.self_governed` with `admin.approvers`, reusing the same `ApprovalRequest` and `check_separation_of_duties` as an agent's action. **Off by default** (it needs a second person; `qed doctor` reports which it is either way, and the record carries `self_governed: false` rather than omitting it). An approval is bound to one operation and spent once, read back out of the chain. `--break-glass` proceeds and records that it did — a gate with no break-glass moves the rotation outside the tool, where nothing records it. On the CLI the requester is **self-asserted**, so what this buys there is two invocations by two subjects, not proof of identity; the API path proves it with a token.
- Broker credentials in memory only; redact in all logs; never in evidence or events.
- Adapter authentication mandatory; unknown adapters rejected.
- Replay: duplicate `proposal.id` → 409 and `correction`-free rejection record.
- Clock: warn if NTP drift > 5 s; `seq` guarantees order regardless of `ts`. **Built in week 10**, with one deviation stated in its own output: it does **not** query NTP (the kernel is offline by design, invariant §1.7) and instead compares the newest record's `ts` against the system clock, which catches a clock that went backwards. Weaker signal, no network. Reported by `qed status` and `qed doctor`; never enforced, because halting on a clock would trade a cosmetic problem for an outage.
- Input limits: proposal ≤ 64 KB; `params_redacted` ≤ 16 KB; regex evaluation with timeouts (use `re2`-style guard via `regex` module `timeout`). **Fuzzed in week 10** (`tests/test_fuzz_parsers.py`, `hypothesis`): JCS, the proposal schema, the policy loader, the pack-bundle envelope and the config loader, each asserting that a malformed input yields the refusal its caller handles and nothing else. It found two leaks — raw `yaml` errors out of the policy loader, and `UnicodeDecodeError` out of the pack-bundle reader.
- Supply chain: SBOM (Syft), cosign keyless signing, SLSA provenance; `qed doctor` verifies own binary signature when possible.
- Dependencies pinned; `pip-audit` in CI. **Built in week 10**: its own job, on push and on a daily schedule, auditing both the installed environment (transitives included, not `--strict` because our own packages are editable installs) and the declared dependency set (`--strict`, so nothing is quietly skipped).

---

## 18. Observability

- **Events**: `GET /v1/events` SSE; each event = redacted `EvidenceRecord` summary (`seq, ts, type, decision, rule_ids, principal_display?, agent, action.name, target, environment, assurance, mode`). Backfill via `?from_seq=`.
- **Metrics** (Prometheus): `qed_decisions_total{decision,mode,environment,adapter_kind}`, `qed_decision_latency_seconds` (histogram; target p95 < 50 ms), `qed_approvals_total{decision}`, `qed_approval_wait_seconds`, `qed_budget_exhausted_total`, `qed_chain_lag_records` (outbox depth), `qed_chain_last_checkpoint_age_seconds`, `qed_ungated_windows_total`, `qed_no_rule_matched_ratio`.
- **SIEM**: OCSF-shaped JSON (class `Authorization` / `API Activity` mapping documented in `docs/siem.md`) via webhook or stdout; CEF optional.

---

## 19. Live UI (separate AGPL package `qed-ui` from repo `valqore/qed-ui`; served by `qed serve --ui`)

The Apache kernel wheel contains **no UI code** (license separation). `pip install valqore-qed[ui]` pulls the `qed-ui` wheel; `qed serve --ui` serves its static assets if the package is importable, otherwise prints how to install it. Single-page, no build step at runtime (prebuilt assets inside the `qed-ui` wheel). Pages:
1. **Live** — decision stream (SSE), filter by decision/agent/env; chain status badge (`seq`, last checkpoint age, verify ok).
2. **Approvals** — pending list with full context (§9.2), buttons Approve once / Approve for N / Deny.
3. **Budgets** — active tokens with bars (steps/tokens/time).
No analytics, no trends. SSO via OIDC (same issuers). Read-only except approval buttons.

---

## 20. Repository, tooling, standards

### 20.1 Layout
```
qed/
  pyproject.toml  README.md  SPEC.md(this)  GOVERNANCE.md  SECURITY.md  THREAT_MODEL.md  CHANGELOG.md  LICENSE(Apache-2.0)
  qed/
    core/   schemas.py  policy/{engine.py,loader.py,lint.py,predicates.py,blast_radius.py,packs/agent-baseline/*.yaml}
            delegation/{verify.py,exchange.py,chain.py}  mandate/{model.py,service.py}
            budget/ledger.py  approval/{service.py,sod.py,dedupe.py}  evidence/{record.py,hashing.py,signing.py,merkle.py,export/{jsonl.py,csv.py,oscal.py}}
            broker/resolve.py
    infra/  storage/{sqlite.py,postgres.py,migrations/}  chain_writer.py  keys/{file.py,vault_transit.py,awskms.py}
            secrets/{env.py,file.py,vault.py}  jwks.py  channels/{slack.py,web.py,cli.py,webhook.py}  publishers/{s3.py,git.py,file.py,email.py}
    api/    app.py  auth.py  routers/{proposals,token,approvals,evidence,policies,mandates,upstreams,admin,events,health}.py
    adapters/ common.py  mcp/  hooks/{claude_code.py,codex.py}  http_proxy/  sdk/  ci.py
    compliance/ frameworks.yaml  packs/*.yaml  loader.py
    remote/  anchor.py  packs.py  intel.py  buildinfo.py
    explain/ (optional local model; never imported by core)
    cli.py
  packages/qed-verify/  (own pyproject; stdlib + cryptography)
  deploy/  Dockerfile  docker-compose.yml(keycloak, postgres, qed)  helm/qed/
  examples/ keycloak-local/ okta-xaa/ aws-agentcore/ langgraph/ crewai/ demos/prod-db-drop/
  docs/  evidence-format.md  policy-language.md  blast-radius.md  assurance-classes.md  onboarding-shadow-to-enforce.md  siem.md  adr/
  tests/
```
### 20.2 Standards
Python 3.12+, `ruff` (lint+format) and `mypy --strict` mandatory in CI; `from __future__ import annotations`; no `Any` in `qed.core`; docstrings on public functions; 100% of `qed.core` covered by tests; conventional commits; semver; `CHANGELOG.md` in repo.

### 20.3 Dependencies (kernel wheel) — MUST NOT exceed without spec update
`fastapi`, `uvicorn[standard]`, `pydantic>=2`, `authlib` (JWT/JWKS/OAuth), `cryptography`, `typer`, `httpx` (infra/adapters only), `pyyaml`, `mcp` (adapters only), `python-ulid`, `regex`, `keyring`. Optional extras: `[postgres] psycopg[binary]`, `[vault] hvac`, `[aws] boto3`, `[slack] slack-sdk`, `[mitm] mitmproxy`, `[ui] qed-ui` (AGPL, separate wheel). Dev/test only: `pytest`, `pytest-asyncio`, `hypothesis`, `ruff`, `mypy`, `jsonschema`.
`qed-verify`: `cryptography` only.

**Pins and notes (added week 2, per §23 "no new dependency without a §20.3 update"):**
- `mcp>=2.3,<3`. The 2.0 SDK replaced the decorator-based `lowlevel.Server` with `on_list_tools` / `on_call_tool` callbacks, which `qed/adapters/mcp/proxy.py` uses. A 1.x resolution does not import.
- `jsonschema` is **dev/test only** and validates the OSCAL export against the NIST schema vendored in `tests/oscal/`. §10.8 permits JSON Schema in place of `oscal-cli`; `oscal-cli` would put a JVM in CI for one check. Note that the NIST schema uses ES2018 Unicode property escapes (`\p{L}`), which CPython's `re` cannot compile, so the test supplies `regex` as the pattern engine — see `tests/oscal/__init__.py`.
- `mcp` pulls `httpx2` transitively as of 2.3. It is a transport dependency of the SDK, not a direct import of `qed`, and `httpx` is already permitted above for infra and adapters.


**Week 3 amendment — JOSE library.** §20.3 names `authlib` for JWT/JWKS/OAuth. As of
authlib 1.8 the `authlib.jose` module is deprecated in favour of **`joserfc`** (same
author) and emits `AuthlibDeprecationWarning` on import, which this suite treats as an
error. The allowed set therefore reads `joserfc` where it read `authlib`; this is a
rename of the same capability, not an additional dependency. `authlib` remains the name
to use if OAuth *client* flows are ever needed outside JOSE.

**Token algorithm.** QED-issued tokens are signed `alg: Ed25519`, not `EdDSA`:
RFC 9864 deprecates the generic `EdDSA` JWS identifier in favour of the concrete curve
name, and `joserfc` raises `SecurityWarning` on `EdDSA`. The identifier is baked into
every token QED mints, so it is settled before the first one is issued rather than
after. Evidence signing is unaffected — it is raw Ed25519, not JOSE.

### 20.4 Packaging
PyPI `valqore-qed` (CLI `qed`), `qed-verify`; container `ghcr.io/valqore/qed` (distroless, non-root, cosign); Homebrew tap `valqore/tap` with single-file binary (PyInstaller via `pyoxidizer`/`nuitka` evaluated in week 5; fallback: brew formula depending on python@3.12); Helm OCI chart.

---

## 21. Testing strategy

| Suite | What | QED |
|---|---|---|
| `tests/core/test_no_network.py` | AST scan: no http libs/sockets imported under `qed.core` | CI fail |
| `tests/core/test_no_llm.py` | no `anthropic/openai/llama` imports under `qed.core` | CI fail |
| `tests/policy/golden/*.json` | ≥100 proposals × expected verdict/hits; run twice, shuffle rule order, compare bytes | CI fail |
| `tests/policy/test_lint.py` | all lint error classes | |
| `tests/evidence/test_chain.py` | genesis, linkage, tamper detection (edit/delete/reorder), rotation continuity, purge-then-verify | |
| `tests/evidence/test_merkle.py` | roots, odd leaves, receipts | |
| `tests/evidence/test_oscal_schema.py` | export validates against NIST schema (vendored) | CI fail |
| `tests/masking/` | PII/secret fixtures masked at write | |
| `tests/delegation/` | chain narrowing matrix, expiry/skew, mandate required/within/revoked | |
| `tests/approval/` | state machine, SoD, dedupe, windows, escalation, expiry | |
| `tests/budget/test_concurrency.py` | 50 threads decrementing; exact counts | |
| `tests/adapters/e2e/` | docker-compose: keycloak + postgres + qed + sample MCP server; Claude Code hook simulated via stdin fixtures; HTTP proxy with httpbin | nightly + PR label |
| `tests/perf/` | 1k rps proposals SQLite/Postgres; p95 assertion | nightly |
| `packages/qed-verify/tests` | verifies fixtures produced by kernel; cross-version fixtures | CI fail |

---

## 22. Build order and milestones (v0.3 — early launch)

Two engineers. Repo public from day 1. Weekly tagged release from week 2.

| Week | Deliverable | Exit criterion |
|---|---|---|
| **1** | Repo skeleton, CI (ruff/mypy/pytest/no-network test), `schemas.py`, hashing/signing/merkle, evidence ledger (SQLite), `qed-verify` v0, `keys init`, `policy` loader+lint+engine with 15 baseline rules, golden tests | `qed check proposal.json` → signed chain → `qed-verify` passes; 60 golden tests green |
| **2** | MCP proxy adapter (port from Valqore `mcp/gateway.py`, decisions via kernel, journal removed), API `/proposals`, `/evidence`, shadow mode, `qed serve`, Dockerfile, OSCAL export (baseline-rule control refs only; full packs week 8) + schema test | **`v0.1.0` public**: `qed mcp -- <server>` in shadow against a real MCP server; blog post #1 ("why static skill scanning is not enough") |
| **3** | Delegation: JWKS verify, `/token` exchange, chain narrowing, Keycloak compose, `qed login` device flow, budgets ledger, remaining baseline rules (~50), `policy test/explain` | Okta/Keycloak user → budgeted token → MCP call → verdict; `v0.2.0` |
| **4** | Approval service: state machine, SoD, dedupe, windows, timeouts; CLI + web approval page; Slack channel; `/events` SSE; live UI (3 pages) | Demo: prod-delete → Slack → deny by different human → chain; `v0.3.0`; design partner #1 installed (shadow) |
| **5** | Credential broker (env/file/Vault), enforcing MCP; HTTP forward proxy (host_path); mandates (`sign/list/revoke`, unattended flow); `qed doctor` posture | Unattended SRE-agent demo with mandate + budget exhaustion; `v0.4.0`; brew tap (python-dependent formula) |
| **6** | Claude Code hook + `install`; Codex hook/wrapper; Python SDK + LangGraph/CrewAI examples; `qed check` CI mode; Postgres + chain leader/outbox; Helm | Four adapters e2e; HA test; **Show HN** + blog #2 ("Replit/Supabase/AgentCore: what a qed would have done"); `v0.5.0`; design partner #2 |
| **7** | Checkpoints + publishers (file, S3 object-lock, git); key rotation; retention/purge; masking strict; OCSF SIEM webhook; perf suite | p95 < 50 ms verified; purge-then-verify passes; `v0.6.0` |
| **8** | Compliance packs import + normalization; OSCAL control mapping complete for EU AI Act/NIST AI RMF; assurance classes doc; **auditor session #1** | Written auditor feedback; fixes scheduled; `v0.7.0` |
| **9** | Auditor fixes; ISO 42001/DORA deepening; `qed.remote.packs` (signed) + air-gap import; `qed.remote.anchor` client (server stub) | Auditor "acceptable (with changes)" → changes merged; `v0.8.0` |
| **10** | Hardening: threat model doc, admin self-governance (approval on reload/rotate), rate limits, fuzz on parsers, pip-audit; single-file binary for brew | `v0.9.0`; both design partners in **enforce** on ≥1 upstream |
| **11** | Docs site, onboarding guide, examples polish, SECURITY.md disclosure process, GOVERNANCE.md; YC application draft | Docs complete; ≥1,000 real actions gated across partners |
| **12** | **`v1.0.0`**: freeze evidence format 1.0, publish `docs/evidence-format.md` as spec; landing page; Valqore site banner & copy fixes (§16 of plan v0.2) | 2 partners enforce; 1 auditor written acceptance; ≥300 stars; YC application submitted |

Parallel every week: 2 customer/auditor conversations; weekly changelog; **no competitor research**.

---

## 23. Definition of done (per PR)
- Tests added/updated; `qed.core` coverage unchanged or higher.
- `ruff` + `mypy --strict` clean.
- If `schemas.py` or hashing changed: fixtures regenerated **and** old fixtures still verify (format compatibility) or `schema_version` bumped with ADR.
- Docs touched when behavior changed; CHANGELOG entry.
- No new dependency without §20.3 update.

---

## 24. Open items waiting on business input (do not block weeks 1–3)
1. ~~Final product name and domain~~ → **closed 2026-10-08. The product is "Valqore QED"; `qed` stays the command, the import package and the repository name.** No refactor needed: ADR-0006 already removed the product name from the evidence format. Domain and the PyPI/npm/GHCR/Homebrew/EUIPO/USPTO reservations are a separate, still-open task and qed the first *public* push, not the build.
2. ~~Valqore patent scope (I5)~~ → **closed 2026-10-08: no filings, nothing pending.** The broker+mandate+chain composition practises no claim Valqore holds, so the irrevocable Apache-2.0 §3 grant transfers nothing. Apache-2.0 is now applied (`LICENSE`, `NOTICE`, SPDX `license` in both `pyproject.toml` files).
3. Existing Valqore agent-qed users (I1/B9) → migration note or none.
4. KMS choice for design partner #2 (AWS KMS forces ECDSA P-256 variant).
5. Auditor candidates (3) and design partners (2 of 5) confirmed.

---

---

## 25. Publishing and open-source strategy

### 25.1 Repositories and licenses (three repos, three licenses — fixed from day 1, never narrowed later)
| Repo | License | Contents | Why |
|---|---|---|---|
| `github.com/valqore/qed` | **Apache-2.0** | kernel, adapters, policy language, baseline pack, `qed-verify`, docs, Helm, examples | Trust layer must be readable; enterprise legal accepts Apache without review |
| `github.com/valqore/qed-ui` | **AGPL-3.0** + CLA | live UI, approval pages, SSE client | Prevents a third party from offering a hosted "qed-as-a-service" UI without releasing changes; customers running it internally are unaffected |
| `github.com/valqore/qed-cloud` | proprietary (private) | multi-tenant evidence vault, auditor portal, transparency log (`anchor`), signed pack feed, SSO/RBAC, long retention | The revenue layer; never mixed into the open repos |

Rules: no proprietary code ever enters the Apache repo (git history is irreversible); Valqore-ported modules arrive as one `imported from valqore-engine e7e66a3` commit without private history; `gitleaks` in CI on all repos; DCO (`Signed-off-by`) on `qed`, CLA on `qed-ui`; trademark clause per Apache §6 — forks may not use the product name/logo; register the name (EUIPO + USPTO) and reserve PyPI, npm, Homebrew tap, Docker Hub/GHCR, GitHub org names before the public launch.

### 25.2 Open-core boundary — the five tests (goes into `GOVERNANCE.md`)
A component is **open and local** if any of: (1) it is in the decision path; (2) it carries customer data; (3) auditors must verify it independently. It **may be a remote/optional API** if (4) its value grows with time or network (freshness, external witnessing, shared intel). It is **closed/commercial** if (5) it only makes sense at scale (multi-tenant, multi-auditor, multi-year). Red lines: the kernel alone, offline, produces auditor-acceptable evidence; no commercial feature ever removes or caps an open capability (no "30-day chain in free").

### 25.3 Relationship to Valqore
One-directional: `qed` has zero imports from Valqore. Valqore becomes a consumer in v1.x (`qed.propose(kind="iac")`) and deletes its own `approvals.py`/`mcp/gateway.py` then. Valqore site: top banner + shortened "Govern Autonomous Agents" section linking to qed; ADP page retired or redirected; copy fixes from plan v0.2 §16 (remove "HMAC-signed", "signed delegation", "188 controls", "no competitor ships this"; align the three inconsistent rule counts). Valqore remains the IaC/K8s/FinOps product with its own narrower sentence; qed gets its own domain (`.dev`/`.sh`) and single-sentence landing page.

### 25.4 Distribution channels
PyPI (`valqore-qed`, `qed-verify`); GHCR container (distroless, non-root, cosign keyless, SBOM); Homebrew tap `valqore/tap` (week 5 python-dependent formula → week 10 single-file binary); Linux `curl | sh` + `.deb/.rpm` (week 10); Helm OCI chart; later: AWS/Azure Marketplace listings, Okta Integration Network, official MCP Registry entry, Backstage plugin.

### 25.5 Launch sequence
| When | What | Channel |
|---|---|---|
| Day 1 | Repo public (skeleton + SPEC + GOVERNANCE) — "quiet open" | GitHub only |
| Week 2 | `v0.1.0` MCP proxy in shadow + blog #1 "Static skill scanning is not enough — why runtime policy + signed evidence" | MCP Discord/GitHub discussions, Claude Code community, r/mcp, LinkedIn |
| Week 4 | `v0.3.0` approvals + live UI; 90-second demo video (prod-db-drop) | Same + Twitter/X thread |
| Week 6 | `v0.5.0` four adapters + HA; **Show HN**; blog #2 "Replit, Supabase MCP, AgentCore: what a qed would have done" | Hacker News, Lobsters, newsletters (TLDR Sec, Last Week in AI) |
| Week 8 | Blog #3 "Evidence auditors can verify without trusting us" after auditor session | LinkedIn (CISO/GRC audience), ISACA/IIA groups |
| Week 12 | `v1.0.0` + evidence-format 1.0 spec + landing page + design-partner quotes | All channels; Product Hunt optional |
Weekly: changelog post in GitHub Discussions; respond to every issue within 24 h (this is the moat in months 0–6). No conference travel; no paid ads.

### 25.6 Versioning and compatibility promises
Semver. `schema_version` of `ActionProposal`/`EvidenceRecord` is independent of package version; any change to hashing or record fields bumps it with an ADR and keeps `qed-verify` able to verify all prior versions (cross-version fixtures in CI). Policy language changes are additive within 1.x. Deprecations announced one minor ahead.

---

## 26. Technology stack

| Layer | Choice | Rationale / alternatives considered |
|---|---|---|
| Language | **Python 3.12+** | Team fluency; Valqore modules port directly; `match` allowed (no Cython). Go rewrite of the hot path is a v2 option if p95 target fails under load |
| API | **FastAPI + uvicorn** | Async, Pydantic-native, OpenAPI for free; already in Valqore |
| Schemas | **Pydantic v2** (frozen, `extra="forbid"`) | Determinism and strictness |
| Auth/JWT/OAuth | **authlib** | JWKS, RFC 8693 exchange, device flow, OIDC discovery — replaces Valqore's hand-rolled RS256 |
| Crypto | **cryptography** (Ed25519, SHA-256); JCS canonical JSON (small vendored impl) | Standard library quality; `qed-verify` depends on it alone |
| Storage | **SQLite** (default) / **PostgreSQL** via `psycopg3`; raw SQL, forward-only migrations | Mirrors Valqore (no ORM); SQLite = zero-config laptop; Postgres = HA with advisory-lock leader |
| Secrets/keys | env, file, **HashiCorp Vault** (`hvac`; Transit for Ed25519), AWS KMS (ECDSA P-256 variant), Azure Key Vault (v1.x) | Regulated buyers already run Vault/KMS |
| MCP | official **`mcp` Python SDK** (stdio + Streamable HTTP) | Protocol fidelity; Valqore used fastmcp — proxy needs client+server both, official SDK cleaner |
| HTTP proxy | custom asyncio CONNECT proxy (host/path mode); **mitmproxy addon** as optional MITM mode | Avoid reinventing TLS interception |
| Approvals | **slack-sdk** (Block Kit, signature verification); generic webhook; web via FastAPI | Teams native in v1.x |
| UI | **Preact + htm** (no build step, ~10 KB) or plain HTML + SSE; shipped as the separate `qed-ui` wheel (AGPL), served by the kernel when installed | Two-person team: no frontend toolchain to maintain; license kept out of the Apache wheel |
| CLI | **Typer + Rich** | Same as Valqore |
| Packaging | PyPI wheels; **PyInstaller/Nuitka** single binary for brew (decide week 5); distroless container; Helm | Brew-first install for Mac users |
| CI/CD | **GitHub Actions**: ruff, mypy --strict, pytest (+coverage qed on `qed.core`), no-network/no-LLM AST tests, OSCAL schema validation, gitleaks, pip-audit, Syft SBOM, cosign keyless, SLSA provenance, multi-arch build | Ported from Valqore CI plus lint/type steps it lacked |
| Docs | **mkdocs-material**, versioned; ADRs in `docs/adr/` | |
| Observability | Prometheus client; SSE; OCSF JSON | Customers keep their Grafana/Splunk |
| Testing | pytest, pytest-asyncio, hypothesis (predicates/hashing), docker-compose e2e (Keycloak, Postgres, httpbin, sample MCP server) | |
| Explicitly not used | ORMs (SQLAlchemy), Alembic, OPA/Rego, Cedar, LangChain, any LLM SDK in core, React build chain | Keep the kernel small and auditable |

---

## 27. Roadmap beyond v1.0

### v1.x (months 4–6) — depth and reach
- **Adapters**: TypeScript SDK; Kubernetes admission webhook (port from Valqore); Valqore IaC as consumer; Gemini CLI / Cursor hooks as their hook APIs stabilize; Codex native hook.
- **Identity**: Okta XAA (ID-JAG) and AWS AgentCore OBO reference integrations; SPIFFE/SPIRE SVIDs for unattended agents; Azure Key Vault signing.
- **Approvals**: Microsoft Teams and PagerDuty native channels; mobile-friendly approval page; approval delegation (out-of-office).
- **Evidence**: `qed.remote.anchor` transparency log GA (public, append-only, Rekor-style) with inclusion proofs in `qed-verify`; multi-chain HA (per-replica chains + merged checkpoints) if leader model limits throughput.
- **Compliance**: ISO 42001 and DORA rule-level depth; SOC 2 CC6/CC7 mapping; FedRAMP 20x profile; OSCAL `component-definition` export so customers can drop qed into their SSP.
- **Policy**: `exceptions` concept with expiry and owner (time-boxed, auditable allowlist alternative); policy simulation against historical chain (`qed policy simulate --since 30d`).
- **Ops**: OpenTelemetry traces; `qed doctor --report` bundle for support.

### v2 (months 7–12) — product surface and ecosystem
- **Dashboards (commercial, qed-cloud / enterprise)**: fleet posture (agents × upstreams × enforcement class), approval SLAs and approver load, budget burn-down per team, "no-rule-matched" drift, policy change diffs with blast-radius impact; **auditor portal** where auditors verify chains and download OSCAL without customer system access; multi-tenant evidence vault with 7-year retention.
- **Shared threat intelligence** (opt-in, hashes only): malicious MCP server / skill hash blocklist and tool-pattern risk scores distributed to all installations.
- **Signed policy pack marketplace**: curated regulatory packs (EU AI Act implementing acts, DORA RTS updates) as a subscription; community packs with signatures.
- **Benchmark** (`qed-bench`): public corpus of labeled agent-action proposals (incl. AgentDojo-style attacks) and per-release scores.
- **Standards**: publish `agent-evidence-format/1.0` as an independent spec (OWASP GenAI / IETF draft); conformance test-suite; reference implementations invited.
- **Programmatic onboarding** (deferred from the original idea): MCP CIMD-based agent self-registration against qed; machine-readable service terms with counter-signed receipts once standards exist; outbound RFC 9421 / Web Bot Auth signing.
- **Platform plugins**: Okta Agent Gateway extension, AWS AgentCore Gateway interceptor, Cloudflare Worker variant of the HTTP proxy.
- **Performance**: optional Go/Rust hot-path for the MCP/HTTP proxies if Python p95 is insufficient at >5k rps.

### Explicitly never
Becoming an IdP; executing agent actions ourselves; LLM-made decisions; telemetry without opt-in; license narrowing of the Apache core.

---

## Appendix A — Example end-to-end fixture (`examples/demos/prod-db-drop/`)
`proposal.json` (Claude Code → postgres.execute DROP TABLE on prod), `policies/` (baseline), `expected_verdict.json` (REQUIRE_APPROVAL, hits AG-BLR-003), `approval_deny.json`, `expected_chain.jsonl` (6 records), `run.sh` (starts qed with `--dev`, posts, decides via CLI as a different principal, exports OSCAL, runs qed-verify). This fixture is the README demo and the first golden e2e test.

## Appendix B — Mapping from Valqore (what is ported)
| Valqore | qed | Change |
|---|---|---|
| `approvals.py` chain logic | `core/evidence`, `core/approval` | Ed25519 only, `key_id`, `schema_version`, SoD, timeouts, windows |
| `mcp/gateway.py` | `adapters/mcp` + parts of `core/policy` | decisions via kernel; JSONL journal removed |
| `verify.py` | `packages/qed-verify` | new format; checkpoints; purge-aware |
| `compliance/packs.py`, `oscal.py` | `compliance/`, `core/evidence/export/oscal.py` | normalized frameworks; schema-validated; assurance observations |
| `governance/blast_radius.py` | `core/policy/blast_radius.py` | K8s specifics removed; table documented |
| `governance/agent_budgets.py` | `core/budget` | keyed by `token_jti`; token-bounded |
| the predecessor's rule registry, IaC/K8s parsers, FinOps, carbon, PQC, what-if and AI explainer | **not ported** | — |
