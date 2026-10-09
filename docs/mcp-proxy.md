# The MCP proxy

`qed mcp` sits between an agent and an MCP server. It speaks MCP to the agent
on one side and MCP to the upstream on the other, and asks the kernel about
every `tools/call` in between.

```bash
qed keys init --dir .qed

qed mcp --human you@example.com --env prod \
         --target-template 'db:{env}/{args.table}' \
         -- npx -y @some/mcp-server
```

Then point the agent at `qed mcp ...` instead of at the server. For a remote
server, `--upstream-url https://host/mcp` replaces everything after `--`.

Nothing about the agent changes. `initialize` reports the **upstream's** own
`serverInfo`, and the proxy adds one line to `instructions` rather than renaming
the server — an agent whose tool list suddenly came from `qed-proxy` would have
to be reconfigured to be governed, and the point is that it does not.

## Shadow first

The default mode is `shadow`. Every call is decided, scored and written to the
evidence chain, and then forwarded regardless of the verdict. Nothing is
blocked. That is deliberate and it is the whole onboarding story:

1. Run in shadow for a week. The agent behaves exactly as before.
2. Read what *would* have happened: `qed export --format oscal`, or
   `verdict.would_decision` in the chain.
3. Tune the policy against real traffic instead of against a guess.
4. Switch `mode: enforce` in `qed.yaml` when the answer stops surprising you.

Only step 4 can break anything, and by then you have the evidence to argue
about. Enforcement is week 10 of the build order for this reason.

A shadow record carries `mode: shadow`. It proves the decision *would* have been
made; it does not prove the action was prevented. Both live in the same chain,
distinguished by that one field, so "we have been observing since this date" is
demonstrable rather than claimed.

## Why `--human` or `--mandate` is required

The proxy refuses to start without one. This looks over-strict and is not.

`evaluate` short-circuits to a synthetic `AG-IDN-007` **BLOCK** when a proposal
has neither a human principal nor a mandate — an agent acting on nobody's
authority. That is the right verdict, but it is reached *before* any rule in the
bundle is evaluated. A proxy that left identity unset would write a chain of
identical identity blocks in which no policy rule had ever run — and in shadow
mode nothing would be stopped and nothing would look wrong. You would discover
it in week 10, when enforcement began blocking everything.

So identity is explicit:

- `--human you@example.com` — attended. Hashed with
  `qed.core.evidence.hashing.principal_hash`, the same function week 3's token
  verification will use, so a chain written across both attributes to one
  person rather than two. `--issuer` names the identity provider.
- `--mandate signed.json` — unattended. Passed to the kernel as-is.

**`--human` is the adapter's own assertion.** Nothing has verified it. It is
recorded in `principal.client_fingerprint` as `adapter-asserted:--human:<issuer>`
— a field SPEC §3.1 documents as advisory and spoofable, and which no rule is
allowed to enforce on. Verified identity arrives in week 3 with JWKS and the
token exchange. The proxy says this on stderr every time it starts.

## What the adapter derives, and what the kernel decides

The protocol hands the proxy a tool name and a JSON object. Neither says "this
writes" or "this deletes", so the adapter derives the three hints SPEC §3.1 asks
for and the kernel does the rest.

| Derived by the adapter (`qed/adapters/mcp/intent.py`) | Decided by the kernel |
|---|---|
| `writes`, `deletes` from the verb, in the name *and* in the arguments | the 0–100 blast-radius score |
| `scope`: `single_resource`, `multi_resource`, `account` | which rules match |
| `action.target` from the configured template | ALLOW / BLOCK / REQUIRE_APPROVAL |

The adapter reads the arguments, not just the tool name. This is the specific
trap the week 1 review carried forward: Valqore's MCP gateway scored
`execute_sql` carrying `DROP TABLE orders` as low risk, because `execute` is a
mild verb and the destructive part was in the parameters. Both are deterministic
text the proxy already has, so both are read.

`scope` never returns `global`. A proxy cannot tell from one JSON object that a
call covers an entire estate, and `AG-BLR-001` blocks account-or-global scope in
production at CRITICAL — a hint that guessed would make every wildcard call a
critical block on the adapter's say-so. `account` is the ceiling.

## Target templates

`action.target` is what `target_globs` in a rule matches on. A tool name is not
a target — `execute_sql` says nothing about which database — so you supply a
template per upstream:

```
db:{env}/{args.table}            ->  db:prod/orders
aws:iam:roles/{args.role}        ->  aws:iam:roles/deploy
k8s:{args.filter.namespace}      ->  k8s:kube-system
{server}:{tool}                  ->  orders:execute_sql      (the default)
```

`{args.<path>}` walks dotted paths and list indexes. An argument the call did
not supply becomes `-absent-` rather than raising: one missing argument must not
take the call out of the chain. Substituted values are sanitised, so a tool
argument — which is attacker-influenced input — cannot reshape the target into
something a policy glob was not written for.

A bad template is a startup error, not a surprise halfway through a session with
half the chain written against the wrong target.

## What the agent sees when a call is refused

In enforce mode, a refused call comes back as an MCP tool error, which is what a
client shows to its model:

```
[qed BLOCK] AG-DAT-001: The parameters of this action contain secret material.
Fix: Reference the secret from the credential broker instead of passing it inline.
```

```
[qed APPROVAL PENDING] AG-BLR-003: Destructive change to a production resource.
Fix: Run it against staging first, or request approval with an explicit intent.
No approval route is configured in this build (approvals land in week 4).
```

SPEC §12.1 wants an approval id and an expiry in the second message. The
approval service is week 4; until it exists, saying `id=none expires=never`
would be worse than saying plainly that there is nothing to wait for.

## Resources and prompts

`resources/read` and `prompts/get` are forwarded, recorded, and **never
refused** — SPEC §12.1 promises passthrough for them in v1. The verdict is still
computed and written, so you can see what a rule would do to resource reads
before v2 starts enforcing them, but it is not acted on even in enforce mode. A
block that silently started applying because someone flipped `mode: enforce`
would break that promise.

They appear in the chain as `orders.resources/read` and `orders.prompts/get`.

## Fail mode

`--fail-mode` governs what happens when the *kernel* fails — a locked database,
a full disk, a bug. Not an upstream failure, which is simply reported.

- `closed` (default): the call is refused.
- `open`: the call is forwarded, and an `ungated_window` record is written with
  the reason and the tool name.

Either way the gap is a record, not silence. An auditor reading the chain sees a
window with a reason and a count rather than a quiet day. That is why
`ungated_window` exists (ADR-003), and why
`tests/adapters/test_import_boundary.py` fails the build if any broad `except`
in the proxy neither logs, records nor refuses.

## What is not here yet

- **Tool-list filtering by token scope.** SPEC §12.1 filters `tools/list`
  against the token's `mcp:<server>:<tool>` scopes. There are no tokens until
  week 3, and filtering against a scope set that does not exist would mean
  inventing one. The list is forwarded whole; every call in it is still decided.
- **Credential injection.** On ALLOW, SPEC §12.1 forwards with a broker
  credential when one is configured. The broker is week 5; calls pass through
  with whatever credential the upstream already had.
- **`upstreams.yaml`.** Target templates come from `--target-template` for now.
  The file arrives with the broker, which is what needs the rest of it.
