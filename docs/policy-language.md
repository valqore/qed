# The policy language

One page. If you need a second page, the language is wrong.

A rule **restricts**. There is no ALLOW rule (ADR-002.3): a rule either says
BLOCK, says REQUIRE_APPROVAL, or stays silent. Allowlist behaviour comes from
narrowing `applies_to`, not from a rule that permits.

## A rule

```yaml
- rule_id: AG-BLR-003          # ^[A-Z]{2,6}(-[A-Z0-9]{2,8})+$, unique in the bundle
  name: Destructive action in production
  severity: HIGH               # LOW|MEDIUM|HIGH|CRITICAL — reporting only, never decides
  mode: enforce                # enforce|shadow
  applies_to:                  # every present axis must hold (AND); absent means any
    kinds: [mcp_tool, http, shell]
    name_globs: ["*"]
    target_globs: ["db:prod/*"]
    environments: [prod]
    adapters: ["mcp-proxy/*"]
  when:                        # predicate tree; absent means "always, given applies_to"
    any:
      - { field: context.blast_radius_hints.deletes, equals: true }
      - { field: action.params_redacted.sql, regex: "(?i)^\\s*drop\\b" }
  verdict: REQUIRE_APPROVAL    # BLOCK | REQUIRE_APPROVAL
  approval:
    approvers: [sre-oncall, dba]
    timeout: 10m
    window_max: 30m
  message: "Destructive change to a production resource."
  fix: "Run it against staging first, or request approval with an explicit intent."
  compliance:
    - { framework: eu_ai_act, control: "Art. 14" }
```

`severity` does not affect the decision. It is there for reporting and for
choosing which rule's `approval` block wins when several ask for approval.

## Predicates

Leaf: `{ field: <dotted path>, <operator>: <value> }`.

| Operator | Notes |
|---|---|
| `equals`, `not_equals` | exact |
| `in`, `not_in` | operand must be a list |
| `glob` | `fnmatch`, case sensitive; operand may be a list (any match) |
| `regex` | evaluated with a timeout; a timeout is an error, not a pass |
| `gt`, `gte`, `lt`, `lte` | numbers only; booleans are not numbers |
| `exists` | operand must be `true` or `false` |
| `contains` | substring for strings, membership for lists |

Composite: `any: [...]`, `all: [...]`, `not: {...}`. Exactly one of these per
node, and nothing else alongside it.

### Absence is falsy

**Every operator except `exists` returns false when the field is not there.**
`{field: action.method, not_equals: GET}` does *not* fire on a proposal that
carries no method at all. The alternative would make a rule's reach depend on
which optional fields an adapter happened to populate. To act on absence, say so:

```yaml
- { field: action.method, exists: false }          # explicit
- not: { field: action.method, equals: "GET" }     # "not GET, including absent"
```

See `docs/adr/0002-predicate-semantics.md`.

### Field paths

Anything in `ActionProposal`, plus:

| Derived field | |
|---|---|
| `derived.blast_radius` | 0–100, see `blast-radius.md` |
| `derived.budget.steps_remaining` / `tokens_remaining` / `seconds_remaining` / `money_remaining_cents` | `null` when that axis is uncapped |
| `derived.budget.steps_pct_used` / `tokens_pct_used` / `money_pct_used` / `seconds_pct_used` | integers 0–100 |
| `derived.budget.money_overrun` | this action costs more than the token has left |
| `derived.mandate.present` / `derived.mandate.within` | |
| `derived.chain_depth` | length of the agent chain |
| `derived.history.calls_24h` / `blocks_24h` | snapshot, collected before the engine runs |

Only `action.params_redacted.*` is free-form. Raw parameters never reach the
engine. List indexing (`tags.0`) is not supported — use `contains`, so that
reordering a list cannot change a decision.

Any other path is a lint error. The accepted set is generated from the models,
so it cannot drift from what the engine can actually resolve.

## Precedence

1. Budget exhausted → `AG-BUD-001` BLOCK, before any rule runs.
2. Unattended with no mandate → `AG-IDN-007` BLOCK.
3. Mandate present and the action is outside it → `AG-IDN-006` BLOCK.
4. `applies_to` filters the candidates; `when` decides which fire.
5. Decision = most restrictive **enforce-mode** hit. `BLOCK` > `REQUIRE_APPROVAL`.
6. No enforce hit → the bundle's `default_verdict` (default `ALLOW`), recorded
   as a synthetic `AG-DEF-001` hit with `default_applied: true`.
7. `would_decision` = most restrictive hit of *all* of them, enforce and shadow.

Every hit is recorded, not only the winning one. The result does not depend on
rule order; a golden test shuffles the bundle and compares bytes.

A rising `no_rule_matched` ratio means the policy has gaps. That is the metric
to watch, not the block count.

## Shadow

`mode: shadow` on a rule means it is evaluated and recorded but does not decide.
`mode: shadow` on the *service* (`qed.yaml`) means nothing is enforced at all.
Both land in the chain, so "we have been observing since this date" is something
you can show rather than claim.

Shipping a rule in shadow is the honest default when it needs site-specific
configuration. `AG-DAT-003` (egress allow list) ships that way: enforcing
somebody else's host list on day one teaches the operator to switch the pack off.

## Overrides and disabling

An override may only **soften** or **narrow**:

```yaml
- rule_id: AG-DAT-007
  override:
    verdict: REQUIRE_APPROVAL              # BLOCK -> approval: allowed
    applies_to: { environments: [staging] } # narrowing: allowed
    mode: shadow                            # enforce -> shadow: allowed
```

Rejected as hardening: `REQUIRE_APPROVAL → BLOCK`, `shadow → enforce`, widening
or dropping an `applies_to` axis, and `verdict: ALLOW`. To turn a rule off you
must say why:

```yaml
- rule_id: AG-SKL-002
  disabled: true
  reason: "We do not use skills; re-enable when the Claude Code rollout starts."
  disabled_by: platform-team
```

The reason goes into the `policy_loaded` record. An auditor sees what was
switched off and who said so.

## Lint

`qed policy lint` reports: `duplicate_rule_id`, `missing_rule_id`,
`invalid_rule`, `invalid_regex`, `unknown_field_path`, `invalid_predicate`,
`allow_rule`, `override_target_missing`, `override_hardening`,
`invalid_override`, `disabled_without_reason` as **errors**;
`approval_without_approvers` and `unknown_framework` as **warnings**.

`qed check` refuses to decide anything against a bundle with errors.

## The bundle hash

`policy_hash = sha256(JCS({default_verdict, rules sorted by rule_id}))`, and it
travels in every verdict.

It covers `default_verdict`, which SPEC §4.6 does not mention, because that
setting decides every proposal matching no rule — a hash that ignored it would
let the effective policy change without the recorded hash changing. It excludes
which file a rule came from, so reorganising policy files is a no-op for the
chain. See `docs/adr/0004-bundle-hash.md`.
