# ADR-0003 — Budget comparisons are precomputed, and "cost unknown" is a field

**Status:** accepted · week 1
**Fills:** SPEC §8 and the AG-BUD-002/003/004 descriptions in SPEC §4.6.

## Context

Three baseline rules in SPEC §4.6 cannot be written in the language SPEC §4.4
defines.

**AG-BUD-002, "≥80% consumed."** The predicate set has no arithmetic and no way
to compare two fields. Only `steps_remaining` is available, so the closest
expressible rule is "two steps or fewer left", which is a different rule and
wrong for a 500-step budget.

**AG-BUD-003, "money budget hit."** Written as
`money_remaining_cents <= 0` it is **dead code**: `BudgetState.exhausted()`
returns true at `money_used >= money_cents`, and SPEC §4.5.6 short-circuits
`AG-BUD-001` before any rule runs. The rule can never fire. The useful rule —
"this action costs more than the token has left" — compares
`context.cost_estimate.money_cents` against `derived.budget.money_remaining_cents`,
which the language cannot express.

**AG-BUD-004, "unknown cost."** SPEC §8 says "missing → 0 and `AG-BUD-004`
unknown_cost shadow hit". But SPEC §3.1 gives `cost_estimate` a default of
`CostEstimate()`, so "missing" and "genuinely zero" are the same value. An
adapter that cannot estimate is indistinguishable from a free action.

## Decision

Add four things rather than weaken the language.

1. `derived.budget.{steps,tokens,money,seconds}_pct_used` — integers 0–100,
   truncated toward zero, `null` when that axis is uncapped. AG-BUD-002 becomes
   `gte: 80` on any of them.
2. `derived.budget.money_overrun` — boolean, `null` when there is no money cap.
   True when `cost_estimate.money_cents > money_remaining_cents`. AG-BUD-003
   uses it and becomes reachable.
3. `CostEstimate.known: bool = True`. An adapter that cannot estimate sets it
   false. AG-BUD-004 reads it directly.
4. A cap of `0` on any budget axis means **uncapped**, and the corresponding
   `_remaining` / `_pct_used` field is `null`. This matches the mandate example
   in SPEC §3.4, which writes `money_cents: 0` to mean "no money budget".

All four are computed in `compute_derived`, which is pure, so none of this moves
I/O into the decision path.

## Consequences

- The predicate language stays arithmetic-free: no expressions, no two-field
  comparisons, no plugins (ADR-002.5 holds).
- Every comparison a baseline rule needs is a named, documented, individually
  testable field. "80 percent" appears once in code rather than once per rule.
- `CostEstimate.known` is an addition to the SPEC §3.1 schema. It is additive
  and defaults to the previous behaviour, so `schema_version` stays `1.0`.
- Adapters that cannot estimate cost become **visible** instead of silently
  scoring zero. AG-BUD-004 ships in shadow mode so the gap is measured rather
  than enforced.
- Adding a derived field means adding a predicate path. The lint path set is
  generated from the models, so no separate registration is needed.

## Alternatives rejected

- **Add arithmetic to the predicate language.** Reopens ADR-002.5, and every
  expression is a new way for two installations to disagree about what a rule
  means.
- **Make `cost_estimate` optional (`CostEstimate | None`).** Expressible via
  `exists`, but it breaks every rule that reads
  `context.cost_estimate.money_cents` whenever an adapter omits the block.
- **Leave AG-BUD-003 as written and accept dead code.** A rule nobody can ever
  trigger in a compliance pack is worse than no rule: it shows up in a control
  mapping as coverage that does not exist.
