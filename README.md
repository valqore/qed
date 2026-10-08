# gate

A self-hosted policy and evidence kernel for AI-agent actions.

An agent proposes an action. `gate` decides **ALLOW / BLOCK / REQUIRE_APPROVAL**
with deterministic rules. Every step is written to one Ed25519-signed,
hash-chained evidence ledger that a third party can verify without trusting the
instance that produced it.

No LLM in the decision path. No network in the kernel. Runs on your own
hardware, including air-gapped.

> **Name:** `gate` is a placeholder. See `PATENT-AND-LICENCE-GATE.md`.
> **Licence:** deliberately not yet applied. See `PATENT-AND-LICENCE-GATE.md`.
> Do not push this repository to a public remote until that file is resolved.

## Status

**Weeks 1–2 of the §22 build order are complete.** What works today:

| Capability | Entry point |
|---|---|
| Domain model (`ActionProposal`, `Verdict`, `EvidenceRecord`, mandates, budgets) | `gate/core/schemas.py` |
| RFC 8785 (JCS) canonical JSON | `gate/core/jcs.py` |
| Hash chain, Ed25519 signing, Merkle checkpoints | `gate/core/evidence/` |
| Evidence ledger on SQLite | `gate/infra/storage/sqlite.py` |
| Policy loader, linter, predicates, engine | `gate/core/policy/` |
| Deterministic blast-radius score (0–100) | `gate/core/policy/blast_radius.py` |
| Baseline pack, 15 rules | `gate/core/policy/packs/agent-baseline/` |
| Standalone verifier | `packages/gate-verify/` |
| **MCP proxy** (stdio and Streamable HTTP), shadow mode | `gate/adapters/mcp/` |
| **HTTP API**: `/v1/proposals`, `/v1/evidence`, `/healthz`, `/readyz` | `gate/api/` |
| **OSCAL 1.1.2 `assessment-results` export** | `gate/core/evidence/export/oscal.py` |
| **Container**, distroless and non-root | `deploy/Dockerfile` |
| CLI: `keys init`, `check`, `policy lint/explain`, `export`, `verify`, `serve`, `mcp` | `gate/cli.py` |

Not built yet (weeks 3+): delegation and token exchange, budget ledger,
credential broker, approval service, coding-agent hooks, HTTP forward proxy,
compliance packs, live UI.

## Quick start

```bash
python -m venv .venv && . .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -e ".[dev]" -e packages/gate-verify

gate keys init --dir .gate                         # Ed25519 evidence key, 0600
gate check examples/proposals/prod-db-drop.json --dir .gate
gate export --dir .gate --out chain.jsonl
gate-verify chain.jsonl --keys .gate/public
```

`gate check` exit codes: `0` ALLOW, `2` REQUIRE_APPROVAL, `3` BLOCK, `1` error.

### Put it in front of an MCP server

```bash
gate mcp --human you@example.com --env prod \
         --target-template 'db:{env}/{args.table}' \
         -- npx -y @some/mcp-server
```

The default mode is **shadow**: every tool call is decided and recorded, and
nothing is stopped. Point your agent at `gate mcp` instead of the server, work
for a week, then read what would have happened:

```bash
gate export --dir .gate --format oscal --out assessment.json
```

`--human` or `--mandate` is required. See `docs/mcp-proxy.md` for why.

### Run the API

```bash
gate serve --dir .gate --dev          # --dev skips adapter signatures; local only
curl -s localhost:8710/readyz | jq
```

`/readyz` answers 503 until there is a signing key and a way to authenticate
adapters (SPEC §17). Adapters sign each request; see `docs/api.md`.

## Reading order

1. `GATE_SPEC.md` — the implementation specification (v0.3.1). Normative.
   (SPEC §20.1 calls this file `SPEC.md`; it is left under its original name so
   that links from the planning folder keep working.)
2. `DESIGN_DECISIONS.md` — ADR-001…008, accepted.
3. `docs/adr/` — decisions made while implementing, where the spec was silent.
4. `docs/evidence-format.md`, `docs/policy-language.md`, `docs/blast-radius.md`.
5. `docs/mcp-proxy.md`, `docs/api.md`, `docs/oscal.md`, `docs/assurance-classes.md`.

`ARCHITECTURE_PLAN.md` is **superseded**; only its §16 (Valqore site/README
fixes) is still live, and that work belongs to the Valqore repos, not here.

## Invariants (enforced by tests, not by convention)

| Invariant | Test |
|---|---|
| `gate.core` imports no HTTP client and no socket | `tests/core/test_no_network.py` |
| `gate.core` imports no model SDK | `tests/core/test_no_llm.py` |
| Decisions are independent of rule file order | `tests/policy/test_golden.py` |
| Same inputs produce byte-identical verdicts | `tests/policy/test_determinism.py` |
| Tamper, delete, reorder in the chain are all detected | `tests/evidence/test_chain.py` |
| Records verify after their payload is purged | `tests/evidence/test_chain.py` |
| Ed25519 only — no HMAC path exists anywhere | `tests/evidence/test_no_hmac.py` |
| The CLI and `POST /v1/proposals` decide identically | `tests/api/test_proposals.py` |
| Every `/v1` route refuses an unsigned request | `tests/api/test_auth.py` |
| The OSCAL export validates against the NIST schema | `tests/evidence/test_oscal_schema.py` |
| Tool-call classification imports nothing that can fail | `tests/adapters/test_import_boundary.py` |
| A destructive payload under a mild tool name still routes to approval | `tests/policy/test_golden_mcp.py` |

## Development

```bash
ruff check . && ruff format --check .
mypy
pytest
```
