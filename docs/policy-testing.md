# Testing a rule set

SPEC §14. `gate policy test` runs cases you write against the rules you have
loaded. It touches nothing: no chain, no store, no network.

```bash
gate policy test cases.yaml --policy ./policies
```

Exit codes: **0** all passed, **1** a case failed or the file is unusable.

## Why bother

Rules are easy to change and hard to change safely. The failure that costs you
is not a rule that stops firing — you notice that. It is a rule you widened
slightly while fixing something else, which now fires on actions it was never
meant to touch, and quietly turns ALLOW into REQUIRE_APPROVAL across a fleet.

A case pins the **exact** set of rule ids a proposal produces, so it fails in
both directions.

## A case file

```yaml
base:                       # a complete proposal; every `patch` merges over it
  schema_version: "1.0"
  id: "01JB0000000000000000000000"
  ts: "2026-10-08T12:00:00.000Z"
  principal:
    token_jti: "01JB000000000000000000JTI0"
    human_hash: "aaaa...64 hex chars..."
    agent_chain: ["claude-code@laptop"]
  action:
    kind: mcp_tool
    name: github.list_issues
    target: "repo:acme/payments"
    params_hash: "0000...64 hex chars..."
  context:
    environment: dev
    adapter: "demo/1.0"
    adapter_id: adp_demo
    enforcement: enforcing
    mode: enforce
    cost_estimate: { tokens: 0, money_cents: 0, known: true }
    blast_radius_hints: { writes: false, deletes: false, scope: single_resource }
    summary: "case base"

mandates:                   # optional, referenced by name from a case
  sre:
    schema_version: "1.0"
    id: md_01
    issued_by_hash: "bbbb...64 hex chars..."
    for_agent: "svc:sre-agent"
    purpose: "night-shift remediation"
    allowed: { kinds: [http], environments: [prod] }
    valid: { from: "2026-01-01T00:00:00.000Z", until: "2026-12-31T23:59:59.000Z" }

cases:
  - id: read-in-dev-is-allowed
    patch: {}
    expect:
      decision: ALLOW
      rules: [AG-DEF-001]

  - id: account-wide-delete-in-prod-is-blocked
    patch:
      context:
        environment: prod
        blast_radius_hints: { writes: true, deletes: true, scope: account }
    expect:
      decision: BLOCK
      rules: [AG-BLR-001, AG-BLR-002, AG-BLR-003, AG-BLR-005]
```

A bare list of cases also works if you pass a base another way; a mapping with
`base:` is the form that stands on its own.

### Fields

| Key | |
|---|---|
| `id` | required, unique; names the case in the output |
| `patch` | deep-merged over `base`. Lists replace, maps merge. |
| `proposal` | a complete proposal instead of `patch`, when a case is easier to read whole |
| `budget` | `BudgetState` fields, for testing the AG-BUD-* rules |
| `mandate` | a name from the `mandates:` block |
| `expect.decision` | required: `ALLOW`, `BLOCK` or `REQUIRE_APPROVAL` |
| `expect.rules` | required: the **exact** sorted set of rule ids |
| `expect.would` | the decision shadow mode would have reached |
| `expect.blast_radius` | the 0–100 score, where it is worth pinning |
| `expect.default_applied` | whether the bundle default decided it |

`expect.rules` is required rather than optional on purpose. A case that checks
only the decision passes when the right answer arrives from the wrong rule,
which is worse than having no case: it reads like coverage.

## What it checks beyond your expectations

Every case is evaluated twice — once against the bundle as loaded, once
against the same rules reshuffled. ADR-002.2 says a decision must not depend
on the order rules happen to load in, and a reshuffled bundle is the only
thing that demonstrates it. You get that check for free on your own rules;
`--no-order-check` turns it off if you are iterating and want the speed.

## Finding rules you never tested

```bash
gate policy test cases.yaml --coverage
```

Lists every loaded rule that no case mentions. A rule nobody has a case for is
a rule nobody has tested.

## Output

```
FAIL  account-wide-delete-is-blocked
        fired unexpectedly: ['AG-BLR-002']
FAIL  a-case-i-got-wrong
        did not fire: ['AG-BLR-001']; fired unexpectedly: ['AG-DEF-001']
        decision: expected BLOCK, got ALLOW
2/3 cases passed
```

`--json` gives the same thing machine-readably, for CI.

A case whose proposal does not validate is reported as a failing case rather
than raising, so one malformed entry does not hide every case after it.

## The same runner as ours

`gate policy test` and the project's own golden suite
(`tests/policy/golden/cases.yaml`, 74 cases) compare results through the same
code, `gate.core.policy.cases`. Two comparison routines would drift, and the
one that drifted would be yours — ours is the one with a CI job behind it.
