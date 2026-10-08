# The credential broker

SPEC §7, ADR-001. One sentence: **the agent never holds the credential.**

It asks the gate to do something. The gate decides. If the answer is yes, the
gate attaches the credential on the way out.

An agent that cannot read a token cannot leak one, cannot be talked into
pasting one into a chat window, and cannot keep using one after its mandate
is revoked. This is also the difference between a gate and a linter: a linter
tells you the action was unwise, a broker means the action was not possible.

## Posture first

Before anything else, ask what this instance can actually enforce:

```
$ gate doctor

instance   : gate-prod  (mode enforce)
signing key: ed25519:7fbb6319282f9912
policy     : 45 rules

UPSTREAM             MODE       INJECT   CREDENTIAL
github               ENFORCING  header   resolved (30 chars)
postgres-prod        ADVISORY   env      unavailable: $PG_URL is not set
internal-wiki        ADVISORY   -        not configured

1 enforcing, 2 advisory
```

**`advisory` is the honest answer when the gate does not hold the
credential.** The gate still decides and still records, but the agent is
carrying its own token and could bypass the gate entirely. An upstream that
claimed to be enforcing while the agent held the credential would make the
evidence a lie, so an upstream with no resolvable credential is downgraded
whatever the config says.

With nothing configured at all, every adapter is advisory and `gate doctor`
says so in those words.

## Configuration

```yaml
# gate.yaml
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
      ref: "secret/data/gate/postgres-prod#DATABASE_URL"
      inject: { type: env, name: DATABASE_URL }

  - id: aws-prod
    kind: http
    match: { host_globs: ["*.amazonaws.com"], environments: [prod] }
    credential:
      source: vault
      ref: aws/creds/gate-prod            # dynamic STS, short TTL
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

Vault is an optional extra (`pip install valqore-gate[vault]`). Asking for a
`vault:` reference without it says what to install rather than raising a
missing-module traceback — you wrote the config and deserve to be told.

A variable that is set but **empty** is an error, not an empty credential:
that is a deployment slip essentially every time, and failing loudly beats
injecting nothing.

### Caching

A resolved credential is reused for `ttl_seconds` (default 60). Short enough
that a rotation or a revoked Vault lease takes effect within a minute,
long enough that a busy gate is not asking Vault on every action.

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

## Still to come

Enforcing MCP and the HTTP forward proxy — the parts that strip an
agent-supplied `Authorization` header and attach the broker's own. The
matching, resolution and posture reporting they need are done.
