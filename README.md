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

**Week 1 of the §22 build order is complete.** What works today:

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
| CLI: `keys init`, `check`, `policy lint/explain`, `export`, `verify` | `gate/cli.py` |

Not built yet (weeks 2+): MCP proxy, HTTP API, delegation/token exchange,
credential broker, approval service, OSCAL export, compliance packs, live UI.

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

## Reading order

1. `GATE_SPEC.md` — the implementation specification (v0.3.1). Normative.
   (SPEC §20.1 calls this file `SPEC.md`; it is left under its original name so
   that links from the planning folder keep working.)
2. `DESIGN_DECISIONS.md` — ADR-001…008, accepted.
3. `docs/adr/` — decisions made while implementing, where the spec was silent.
4. `docs/evidence-format.md`, `docs/policy-language.md`, `docs/blast-radius.md`.

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

## Development

```bash
ruff check . && ruff format --check .
mypy
pytest
```
