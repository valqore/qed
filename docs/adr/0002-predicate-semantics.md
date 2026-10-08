# ADR-0002 — A missing field is falsy for every operator except `exists`

**Status:** accepted · week 1
**Fills:** a gap in SPEC §4.4 / ADR-002.5.

## Context

SPEC §4.4 lists the operators but does not say what happens when the path does
not resolve. `ActionProposal` has several optional fields (`action.method`,
`action.params_redacted`, `context.intent`) and `params_redacted` is free-form
adapter JSON, so unresolved paths are common, not exceptional.

The question is what `{field: action.method, not_equals: "GET"}` does when the
proposal carries no method.

## Decision

Resolution returns a `MISSING` sentinel, distinct from `None` (an explicit JSON
null resolves to `None` and is a present value).

- `exists` is the only operator that inspects `MISSING`. `exists: false` is true
  when the field is absent *or* explicitly null.
- Every other operator returns **false** on `MISSING`, including the negative
  forms `not_equals` and `not_in`.
- `not: {...}` therefore makes absence expressible:
  `not: {field: action.method, equals: GET}` is true when the method is absent.

List indexing is not supported at all. `context.tags.0` resolves to `MISSING`.
Rules match lists with `contains`.

## Consequences

- A rule's reach does not depend on which optional fields an adapter chose to
  populate. Two adapters that differ only in how much they fill in produce the
  same verdicts — which is the point of determinism.
- `not_equals` is not the logical negation of `equals` when the field is absent.
  Both are false. This is surprising once, in the documentation, rather than
  surprising repeatedly in production.
- Authors who want absence to count write it, and the written form reads
  correctly out loud.
- Reordering a list cannot change a decision, because no rule can address a
  list by index.

## Alternatives rejected

- **`MISSING` behaves like `None`.** Then `not_equals: "GET"` fires on every
  proposal without a method, which means a rule written for HTTP actions quietly
  covers MCP tool calls too.
- **Unresolved path raises at evaluation time.** The linter already rejects
  unknown *schema* paths; the remaining unresolved paths are legitimate
  free-form parameter lookups. Raising would mean any adapter that omits an
  optional key takes the kernel's decision path into an error state, and the
  fail-closed answer to that is to block work that should have been allowed.
- **Three-valued logic (true / false / unknown).** Correct, and nobody writing a
  YAML rule wants it.
