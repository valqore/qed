# Valqore QED

A self-hosted policy and evidence kernel for AI-agent actions.

An agent proposes an action. `qed` decides **ALLOW / BLOCK / REQUIRE_APPROVAL**
with deterministic rules. Every step is written to one Ed25519-signed,
hash-chained evidence ledger that a third party can verify without trusting the
instance that produced it.

No LLM in the decision path. No network in the kernel. Runs on your own
hardware, including air-gapped.

> **Name:** the product is **Valqore QED** — *quod erat demonstrandum*, which
> is the claim: a third party can verify what happened here without trusting
> the instance that recorded it. `qed` is the command, the import package and
> the repository.
>
> It was called `gate` until 2026-10-08. The name changed because "gate" is
> already a commercial product in this exact category, is not registrable for
> the thing it describes, and named the half of the product every competitor
> ships rather than the half that is hard to copy. The rename cost one commit
> and invalidated no evidence, because ADR-0006 had already taken the product
> name out of the hash domain separators in week 1 — which is why `gate`
> still appears in `docs/adr/`, `CHANGELOG.md` and two superseded spec
> literals, and nowhere else.
> **Licence:** Apache-2.0. See `LICENSE` and `NOTICE`.
> **Still not public:** the remote stays private until the name reservations in
> `REPO-AND-PUBLICATION-PLAN.md` §5 are in place. Publishing is distribution,
> and that is the step that cannot be undone.

## Status

**Weeks 1–7 of the §22 build order are complete.** What works today:

| Capability | Entry point |
|---|---|
| Domain model (`ActionProposal`, `Verdict`, `EvidenceRecord`, mandates, budgets) | `qed/core/schemas.py` |
| RFC 8785 (JCS) canonical JSON | `qed/core/jcs.py` |
| Hash chain, Ed25519 signing, Merkle checkpoints | `qed/core/evidence/` |
| Evidence ledger on **SQLite or PostgreSQL**, one implementation | `qed/infra/storage/` |
| Policy loader, linter, predicates, engine | `qed/core/policy/` |
| Deterministic blast-radius score (0–100) | `qed/core/policy/blast_radius.py` |
| Baseline pack, 46 rules | `qed/core/policy/packs/agent-baseline/` |
| Standalone verifier | `packages/qed-verify/` |
| **MCP proxy** (stdio and Streamable HTTP), shadow mode | `qed/adapters/mcp/` |
| **HTTP forward proxy** (`CONNECT` and plain HTTP) | `qed/adapters/http_proxy/` |
| **Claude Code hook** + `qed install` | `qed/adapters/hooks/` |
| **Python SDK** (`@guard`) | `qed/sdk/` |
| **Credential broker** (env, file, Vault) | `qed/core/broker/`, `qed/infra/secrets/` |
| **HTTP API**: `/v1/proposals`, `/v1/evidence`, `/healthz`, `/readyz` | `qed/api/` |
| **OSCAL 1.1.2 `assessment-results` export** | `qed/core/evidence/export/oscal.py` |
| **Web approval page** with OIDC human login | `qed/api/ui.py`, [`valqore/qed-ui`](https://github.com/valqore/qed-ui) |
| **HA**: evidence outbox + one chain leader on Postgres | `qed/infra/chain_drain.py`, `qed/api/leader.py` |
| **`qed check --server`** and `--evidence-out` for CI | `docs/ci.md` |
| **Container**, distroless and non-root | `deploy/Dockerfile` |
| **Helm chart** and a two-replica compose stack | `deploy/helm/qed`, `deploy/docker-compose.yml` |
| **Key rotation** (`qed keys rotate`), verifiable across the change | `qed/infra/keys/rotation.py` |
| **Retention and purge**, with purge-then-verify | `qed/core/evidence/retention.py` |
| **Checkpoint anchors**: file, S3 object-lock, git tag | `qed/infra/publishers/` |
| **Prometheus `/metrics`** and **OCSF SIEM** events | `qed/api/routers/metrics.py`, `qed/infra/siem.py` |
| **Control catalogues** for 10 frameworks, with honest coverage | `qed/compliance/packs/`, `docs/compliance.md` |
| **Signed catalogue import**, air-gap, recorded in the chain | `qed/remote/packs.py`, ADR-0012 |
| **Transparency-log anchor client**, six values and no payload | `qed/remote/anchor.py`, ADR-0013 |
| **Self-governance**: qed's own admin ops behind an approval | `qed/core/admin.py`, ADR-0014 |
| CLI: `keys`, `check`, `policy`, `export`, `verify`, `serve`, `mcp`, `proxy`, `hook`, `install`, `login`, `token`, `mandate`, `approve`, `approvals`, `doctor`, `status`, `checkpoint`, `packs` | `qed/cli.py` |

Not built yet: the Codex hook (its API is unconfirmed, SPEC §12.2),
`mode: mitm` for the HTTP proxy, the `remote.packs` **feed** (the air-gap
import is built; fetching a bundle from a URL is the same verification with a
download in front of it), the anchor **log** itself (the client is built; the
log is `qed-cloud`'s, SPEC §24.2), and SPEC §19's live-stream and budget
pages.

**Measured, not estimated:** p95 decision latency is **4.5 ms** on SQLite and
10.6 ms on PostgreSQL, against SPEC §18's 50 ms target — though that budget is
a claim about the disk, not about Python, and slow storage can blow through it.
Throughput is 250–400 decisions/s per replica, so SPEC §22's "1k rps" is
several replicas rather than one. `docs/performance.md` has the numbers,
including the ones that are less flattering.

## Quick start

```bash
python -m venv .venv && . .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -e ".[dev]" -e packages/qed-verify

qed keys init --dir .qed                         # Ed25519 evidence key, 0600
qed check examples/proposals/prod-db-drop.json --dir .qed
qed export --dir .qed --out chain.jsonl
qed-verify chain.jsonl --keys .qed/public
```

`qed check` exit codes: `0` ALLOW, `2` REQUIRE_APPROVAL, `3` BLOCK, `1` error.

### Put it in front of an MCP server

```bash
qed mcp --human you@example.com --env prod \
         --target-template 'db:{env}/{args.table}' \
         -- npx -y @some/mcp-server
```

The default mode is **shadow**: every tool call is decided and recorded, and
nothing is stopped. Point your agent at `qed mcp` instead of the server, work
for a week, then read what would have happened:

```bash
qed export --dir .qed --format oscal --out assessment.json
```

`--human` or `--mandate` is required. See `docs/mcp-proxy.md` for why.

### Put it in front of your coding agent

```bash
qed install claude-code --human you@example.com
```

Every `Bash`, every file write, every MCP call and every skill then goes
through the same kernel. A refused call comes back as `deny` with the rule ids;
one that needs a person comes back as `ask`, which puts the question to whoever
is at the terminal.

This adapter is **advisory and always will be** — whoever can edit the settings
can delete the entry that calls it, so the chain records it as advisory and
never claims the call could not have happened. `docs/hooks.md` has the
hardening, and why an ALLOW verdict deliberately prints nothing at all.

### Put it in front of your own function

```python
from qed.sdk import Qed, guard

qed = Qed.from_env()


@guard(qed, target=lambda account_id, **_: f"crm:accounts/{account_id}", deletes=True)
def delete_account(account_id: str) -> None: ...
```

For the action that has no front: a function in your own application that
charges a card or deletes a tenant. The decorator proposes before the call,
raises `QedBlocked` or `QedApprovalPending` if the answer was no, runs the
function, and reports what happened. A refused action never runs.

It fails **closed** by default, unlike the hook: an application has no human
watching, so a QED it cannot reach must stop the action rather than wave it
through. `examples/sdk/` has governed LangGraph and CrewAI tools that run
whether or not those frameworks are installed.

### Put it in front of everything else

```bash
qed proxy --human you@example.com --env prod
HTTPS_PROXY=http://127.0.0.1:8888 HTTP_PROXY=http://127.0.0.1:8888 your-agent
```

The MCP proxy governs the tools an agent was given; this governs the rest --
the `curl` in a shell step, the SDK call in a script, the request an agent
makes because something in its context told it to.

Read `docs/http-proxy.md` before relying on it, for one reason: **a `CONNECT`
tunnel is always recorded as advisory.** QED decides whether the
connection may be opened, but the request inside it is encrypted, so it cannot
replace the credential and the agent is using its own. Plain HTTP is fully
visible and fully brokered.

### Run it on Postgres

```yaml
# qed.yaml
evidence:
  store_env: QED_DATABASE_URL     # a URL has a password; name the variable
```

```bash
pip install 'valqore-qed[postgres]'
export QED_DATABASE_URL=postgresql://user:pass@host/qed
qed keys init && qed serve
```

SQLite is the default and runs the whole product on one file. Postgres is for
the case SQLite genuinely cannot serve: **more than one replica sharing a
chain**, with exactly one of them holding `pg_try_advisory_lock` and appending
(SPEC §15).

It is **one store implementation, not two.** Forty repository methods are
written once and run against either backend, because two copies would be two
implementations of the chain's append path and the day they drifted is the day
the chain behaved differently depending on which database somebody deployed.
`tests/evidence/test_cross_backend.py` writes the same records to both and
asserts every hash, signature and payload matches byte for byte — because if
they did not, an export from a Postgres deployment would fail verification
against records written on SQLite, and nobody would notice until an auditor
did.

### Run more than one replica

```bash
helm install qed ./deploy/helm/qed   --set signingKey.existingSecret=qed-signing-key   --set replicaCount=3   --set evidence.backend=postgres   --set evidence.postgres.existingSecret=qed-db
```

Every replica serves the API and decides. The decider writes its record
durably to an outbox and answers immediately; exactly one replica holds
`pg_try_advisory_lock(1734440037)` and turns those records into chain entries
afterwards (ADR-0009). So **decision latency is independent of chain latency**,
and `evidence_ref` may be an outbox id until the leader catches up —
`GET /v1/evidence/by-ref/{ref}` resolves either shape.

Kill the leader and its connection drops, the lock is released, and another
replica takes over on its next tick. Nothing has to notice, announce or hand
over. `deploy/docker-compose.yml` is the same arrangement on a laptop, if you
would rather watch it happen than read about it.

The chart **refuses** `replicaCount > 1` on SQLite. Two writers would read the
same chain tip and either collide on the hash primary key — losing the evidence
for a decision already delivered — or fork the chain, which still verifies
record by record and has simply stopped being a chain. `docs/deployment.md` has
the rest.

### Run the API

```bash
qed serve --dir .qed --dev          # --dev skips adapter signatures; local only
curl -s localhost:8710/readyz | jq
```

`/readyz` answers 503 until there is a signing key and a way to authenticate
adapters (SPEC §17). Adapters sign each request; see `docs/api.md`.

### Put it in your pipeline

```bash
export QED_URL=https://qed.internal
export QED_ADAPTER_ID=adp_ci QED_ADAPTER_SECRET=...
qed check deploy-proposal.json
```

Exit `0` ALLOW, `2` BLOCK, `3` REQUIRE_APPROVAL — and `1` when QED could not
decide at all, which is the distinction a pipeline cannot do without: a runner
that could not reach the instance has not been refused anything, and reading
that as an allow is the failure this whole project exists to prevent.

`--server` keeps the evidence signing key out of CI and the evidence itself
alive after the job. Without an instance, `--evidence-out qed-evidence.jsonl`
leaves the chain behind as an artifact anyone can check with the public key.
`docs/ci.md` has the Actions workflow.

## Reading order

1. `QED_SPEC.md` — the implementation specification (v0.3.1). Normative.
   (SPEC §20.1 calls this file `SPEC.md`; it is left under its original name so
   that links from the planning folder keep working.)
2. `DESIGN_DECISIONS.md` — ADR-001…008, accepted.
3. `docs/adr/` — decisions made while implementing, where the spec was silent.
4. `docs/evidence-format.md`, `docs/policy-language.md`, `docs/blast-radius.md`.
5. `docs/mcp-proxy.md`, `docs/http-proxy.md`, `docs/hooks.md`, `docs/credential-broker.md`,
   `docs/delegation.md`, `docs/approvals.md`, `docs/api.md`, `docs/oscal.md`,
   `docs/assurance-classes.md`, `docs/compliance.md`, `docs/policy-testing.md`.
6. Running it: `docs/deployment.md` (process, container, Helm, HA, releasing),
   `docs/ci.md` (`qed check` in a pipeline), `docs/checkpoints.md` (anchors),
   `docs/siem.md` (OCSF), `docs/performance.md` (what it actually costs) and
   `docs/validation.md` (what a green test suite cannot see).

`ARCHITECTURE_PLAN.md` is **superseded**; only its §16 (Valqore site/README
fixes) is still live, and that work belongs to the Valqore repos, not here.

## Invariants (enforced by tests, not by convention)

| Invariant | Test |
|---|---|
| `qed.core` imports no HTTP client and no socket | `tests/core/test_no_network.py` |
| `qed.core` imports no model SDK | `tests/core/test_no_llm.py` |
| Decisions are independent of rule file order | `tests/policy/test_golden.py` |
| Same inputs produce byte-identical verdicts | `tests/policy/test_determinism.py` |
| Tamper, delete, reorder in the chain are all detected | `tests/evidence/test_chain.py` |
| Records verify after their payload is purged | `tests/evidence/test_chain.py` |
| Ed25519 only — no HMAC path exists anywhere | `tests/evidence/test_no_hmac.py` |
| The CLI and `POST /v1/proposals` decide identically | `tests/api/test_proposals.py` |
| Every `/v1` route refuses an unsigned request | `tests/api/test_auth.py` |
| Masking never rewrites a kernel-generated identifier | `tests/masking/test_masking.py` |
| No package shadows a standard-library module | `tests/test_no_stdlib_shadowing.py` |
| The hook never emits `allow`, and never exits 1 | `tests/adapters/test_claude_code_hook.py` |
| `import qed.sdk` loads no web framework | `tests/sdk/test_sdk_is_light.py` |
| One signing implementation, shared by signer and verifier | `tests/sdk/test_sdk_is_light.py` |
| SQLite and PostgreSQL produce byte-identical chains | `tests/evidence/test_cross_backend.py` |
| No SQL string breaks the `?` → `%s` conversion | `tests/evidence/test_store_dialects.py` |
| An adapter's `execution_result` records the enforcement its proposal did | `tests/adapters/http_proxy/test_proxy_e2e.py` |
| The OSCAL export validates against the NIST schema | `tests/evidence/test_oscal_schema.py` |
| Tool-call classification imports nothing that can fail | `tests/adapters/test_import_boundary.py` |
| A destructive payload under a mild tool name still routes to approval | `tests/policy/test_golden_mcp.py` |

## Development

```bash
ruff check . && ruff format --check .
mypy
pytest
```
