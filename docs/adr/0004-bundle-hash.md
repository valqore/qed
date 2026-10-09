# ADR-0004 — `policy_hash` covers `default_verdict` and ignores file layout

**Status:** accepted · week 1
**Refines:** ADR-002.7, SPEC §4.6.

## Context

ADR-002.7 defines `policy_hash = sha256(canonical_json(sorted rules))`. The hash
exists so that a verdict in the chain pins exactly which policy produced it: if
the policy changes, the hash changes, and an auditor can tell the two eras apart.

Two things fall outside "sorted rules".

**`default_verdict`.** It lives in `qed.yaml`, not in a rule file, and it
decides the outcome of every proposal that matches nothing. Flipping it from
`ALLOW` to `REQUIRE_APPROVAL` changes the behaviour of the whole system while
leaving a rules-only hash identical. That is precisely the situation the hash is
meant to make impossible.

**Which file a rule came from.** A rule's `source` is useful in lint output and
in `policy_loaded`. If it were hashed, moving a rule from `rules.yaml` to
`prod.yaml` would look, in the chain, exactly like changing the policy.

## Decision

```
policy_hash = sha256(JCS({
  "default_verdict": <value>,
  "rules": [ <hashed fields>, ... sorted by rule_id ]
}))
```

Hashed per rule: `rule_id`, `name`, `message`, `verdict`, `severity`, `mode`,
`applies_to`, `when`, `approval`, `fix`, `compliance`, `disabled`, `reason`.

Not hashed: `source`, `disabled_by`, `references`.

`disabled` **is** hashed — switching a rule off changes decisions. `reason` is
hashed because it is the auditor-facing justification and should not be editable
without a trace. `disabled_by` is not, because it is an attribution recorded
separately in `policy_loaded`.

## Consequences

- Changing `default_verdict` produces a new `policy_hash` and a new
  `policy_loaded` record. Replay stays honest.
- Reorganising policy files is a no-op for the chain, so teams can split rules
  by environment or ownership without generating noise.
- Rule order within a file, and across files, is irrelevant: rules are sorted by
  `rule_id` before hashing, and a golden test shuffles the bundle and compares
  verdict bytes.
- This is a deliberate, documented divergence from the literal text of
  ADR-002.7. The `policy_bundles` table stores the hash, so an instance that
  predates this ADR would compute a different hash for the same rules; nothing
  predates it.
