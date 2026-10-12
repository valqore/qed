# The credential broker

SPEC §7, ADR-001. One sentence: **the agent never holds the credential.**

It asks QED to do something. QED decides. If the answer is yes, the
qed attaches the credential on the way out.

An agent that cannot read a token cannot leak one, cannot be talked into
pasting one into a chat window, and cannot keep using one after its mandate
is revoked. This is also the difference between a gate and a linter: a linter
tells you the action was unwise, a broker means the action was not possible.

## Posture first

Before anything else, ask what this instance can actually enforce:

```
$ qed doctor

instance   : qed-prod  (mode enforce)
signing key: ed25519:7fbb6319282f9912
policy     : 46 rules

UPSTREAM             MODE       INJECT   CREDENTIAL
github               ENFORCING  header   resolved (30 chars)
postgres-prod        ADVISORY   env      unavailable: $PG_URL is not set
internal-wiki        ADVISORY   -        not configured

1 enforcing, 2 advisory
```

**`advisory` is the honest answer when QED does not hold the
credential.** QED still decides and still records, but the agent is
carrying its own token and could bypass QED entirely. An upstream that
claimed to be enforcing while the agent held the credential would make the
evidence a lie, so an upstream with no resolvable credential is downgraded
whatever the config says.

With nothing configured at all, every adapter is advisory and `qed doctor`
says so in those words.

## Configuration

```yaml
# qed.yaml
broker:
  upstreams_file: upstreams.yaml     # relative to this file
  ttl_seconds: 60
```

```yaml
# upstreams.yaml
upstreams:
  - id: github
    kind: mcp
    match: { mcp_server: github }
    credential:
      source: env
      ref: GITHUB_TOKEN
      inject: { type: header, name: Authorization, format: "Bearer {value}" }

  - id: postgres-prod
    kind: mcp
    match: { mcp_server: postgres, environments: [prod] }
    credential:
      source: vault
      ref: "secret/data/qed/postgres-prod#DATABASE_URL"
      inject: { type: env, name: DATABASE_URL }

  - id: aws-prod
    kind: http
    match: { host_globs: ["*.amazonaws.com"], environments: [prod] }
    credential:
      source: vault
      ref: aws/creds/qed-prod            # dynamic STS, short TTL
      inject: { type: sigv4 }
```

### Matching

Every present constraint must hold; an absent one means "any", the same
reading as a rule's `applies_to`.

**First match wins, in file order.** Not "most specific" — specificity
between a host glob and an environment list is not something anyone can rank,
and a resolution order nobody can predict is worse than one they can read top
to bottom. Put the narrow rule above the broad one, the way you already do
with firewall rules.

`host_globs` matches the **host**, not the string: `*.amazonaws.com` does not
match `ec2.amazonaws.com.evil.test`.

### Sources

| `source` | `ref` |
|---|---|
| `env` | the variable name |
| `file` | a path; the trailing newline `echo secret > file` leaves is stripped |
| `vault` | `secret/data/path#field` |

Vault is an optional extra (`pip install valqore-qed[vault]`). Asking for a
`vault:` reference without it says what to install rather than raising a
missing-module traceback — you wrote the config and deserve to be told.

A variable that is set but **empty** is an error, not an empty credential:
that is a deployment slip essentially every time, and failing loudly beats
injecting nothing.

### Caching

A resolved credential is reused for `ttl_seconds` (default 60). Short enough
that a rotation or a revoked Vault lease takes effect within a minute,
long enough that a busy qed is not asking Vault on every action.

## Where a credential is allowed to exist

In memory, for at most its TTL. That is the whole list.

- **Not in the chain.** Evidence records `upstream_id` and nothing else.
- **Not in a log.** The value is wrapped in a `Secret` whose `str`, `repr`,
  f-string, `%`-format and `pprint` renderings are all `<redacted>`, and
  which `json.dumps` refuses outright rather than serialising.
- **Not on disk.** Nothing here writes one.

`Secret.reveal()` is the only way to the real bytes, and it is deliberately
awkward to type — a leak should have to be written on purpose rather than
reached by habit. There are sixteen tests in
`tests/broker/test_secret.py`, each one a different accident: a log line, a
traceback that formats its locals, a value nested in a dict being pretty
printed.

`len(secret)` and `bool(secret)` work, because "set but empty" is a thing a
health check needs to be able to say without printing anything.

## Enforcement is derived, not asserted

Before the broker, an adapter was *told* it was enforcing by a flag. That
claim went into `context.enforcement`, and from there into the evidence. If
the credential was missing the claim was simply wrong, and nothing in the
chain said so.

Now QED is enforcing for a call **if and only if it is holding the
credential for that call**. The adapter does not get asked.

```
$ qed mcp --config qed.yaml -- npx -y @some/mcp-server
...
qed: 4 tool call(s); 4 forwarded, ...
qed: 1 of those call(s) were ADVISORY -- decided and recorded, but QED
      was not holding the credential.
```

The advisory count is printed separately and last, because a session that was
entirely advisory looks identical to an enforcing one in every other number.

With no upstreams configured the adapter keeps whatever the flag says, which
is how every deployment behaved before the broker existed — going silently
advisory on an existing install would be the worse surprise.

## When the credential is attached

| Transport | When | Why |
|---|---|---|
| stdio MCP | at spawn, into the child's environment | A child process receives its environment once. "Resolved per request" is not something the transport can offer, and claiming it would be worse than saying so. |
| HTTP | per request, as a header | Genuinely per request. |

For stdio the TTL cache governs **re-spawns**, not calls. A rotated secret
reaches a long-lived child process when it restarts, not before.

## Stripping comes first

An enforcing adapter removes whatever the agent supplied before attaching
anything:

```
authorization · proxy-authorization · cookie · x-api-key · api-key
x-auth-token · x-access-token · x-amz-security-token · x-goog-api-key
```

Matched case-insensitively, because HTTP header names are and an agent that
capitalised `AUTHORIZATION` would otherwise sail straight through.

This matters more than the attaching. An adapter that added the broker's
header while leaving the agent's in place would be an adapter where the agent
still chooses which credential gets used.

`sigv4` cannot be planned ahead, because the signature covers the request
body. The injection plan says `needs_signing` and the adapter refuses rather
than forwarding unsigned — forwarding unsigned would mean the agent's own
credentials get used after all.

## Still to come

The HTTP forward proxy (`qed proxy`), for agents that make plain HTTP calls
rather than MCP ones. Everything it needs exists.
