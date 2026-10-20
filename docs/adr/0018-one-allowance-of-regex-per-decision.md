# ADR-0018 — One allowance of regex per decision

**Status:** accepted · 2026-10-19
**Bounds:** the loop [ADR-0017](0017-a-regex-timeout-is-retried-before-it-is-believed.md) deliberately left unbounded.

## Context

ADR-0017 made a regex timeout retryable, because the `regex` module's
`timeout=` is wall clock and only a second attempt can tell a pathological
pattern from a descheduled thread. It bounded one call at
`ATTEMPTS * BUDGET` — three seconds — and said plainly that it did not bound
the loop above it:

> one unevaluable pattern now costs 3 s, and the redactor masks each string
> separately while the engine evaluates each rule separately, so a bundle of 46
> bad patterns is 46 × 3 s.

That is 138 seconds, in the request path, from one proposal, against SPEC §18's
50 ms p95. It is reachable only by an operator who authored many unevaluable
patterns, which `qed policy lint` does not catch because a catastrophic pattern
is structurally valid. "Unlikely" is not a bound.

ADR-0017 also recorded why it stopped: bounding the loop touches what a verdict
means, and that needed its own decision rather than being taken in passing.

## Decision

Every regex evaluated while deciding one proposal draws on **one allowance** of
regex time, `POOL` (5 s), established by `_match` and scoped to the context so
concurrent decisions cannot spend each other's.

Three details carry the weight.

**It measures regex time, not wall time.** Nothing else in the loop can spend
it, so the bound is about the thing that is actually unbounded.

**An attempt is funded with a whole `BUDGET` or refused.** Handing out whatever
is left funds an attempt with a sliver — a tenth of a millisecond is not a test
of anything, it times out instantly, and the rule is then blamed for a pattern
that was never fairly tried. It also made the attribution depend on where the
arithmetic happened to land, so the same bundle could name different rules on
two machines. Up to one budget goes unused; exactness is not worth a
misattributed rule. `POOL` is therefore also an attempt count: five.

**A refusal is a distinct failure from a timeout.** `PoolSpent` is raised only
when a call made *no* attempt, and `_regex` turns it into a different message:
*"not evaluated: this decision's regex allowance was already spent"* rather
than *"regex evaluation timed out"*. A call whose own first attempt timed out
and then found the allowance short spent the missing time itself and gets the
ordinary timeout its pattern earned. Without this, one bad pattern makes
forty-four innocent rules report as broken, and an operator reads the chain and
goes to look at the wrong regex.

Everything ADR-0016 decided is unchanged: a rule that cannot be evaluated is
skipped, is not a hit, and is recorded as `AG-PRD-001`.

## Consequences

- **A decision's regex cost is bounded by `POOL` regardless of rule count.**
  138 s becomes 5 s, and adding rules to a bundle no longer raises the ceiling.
- **Which rules are skipped can now depend on `rule_id` order.** This is the
  real cost and it should not be buried: a rule late in the bundle can be
  refused because an earlier rule's pattern spent the allowance, so two
  replicas on differently-loaded hosts can skip different rules.

  Two things keep it from reaching the decision. The decision is a **maximum
  over the hits**, so it does not depend on evaluation order at all — only on
  which rules are in it. And in a bundle with one bad pattern the allowance is
  never reached by the rules behind it, because they need microseconds each:
  the bias exists only in a bundle with several unevaluable patterns, which is
  already an operator defect the verdict reports.

  Non-determinism of this shape was already accepted in ADR-0016 — *"a timeout
  is not reproducible: the same inputs on a quieter machine produce a verdict
  without the `AG-PRD-001` hit"*. This widens its scale, from one rule to a
  tail of them, which is why it is written down here rather than left implied.
- **A bundle whose patterns all work cannot reach this.** Five seconds is
  roughly a hundred thousand times what a real bundle spends.
- Record hashes and the evidence format are untouched; this changes only how
  long the engine is willing to spend before reporting a rule it could not
  evaluate.

## Alternatives rejected

- **A wall-clock deadline across the whole evaluation.** Simpler, and it bounds
  the wrong thing: anything else that ever happens inside `_match` would start
  spending the regex guard, so a future store lookup or a slower host would
  skip rules for reasons that have nothing to do with regex.
- **Refuse the proposal when the allowance is spent.** Loud, and it hands an
  attacker who can influence one rule's pattern a denial of service over every
  action the kernel governs. ADR-0016 rejected this for a single rule and the
  reasoning is unchanged at bundle scale.
- **Give each regex rule an equal share of the allowance.** This removes the
  ordering bias, which is the one real cost above, and reintroduces the bug
  ADR-0017 fixed: 46 rules sharing 5 s is 109 ms each, well under `BUDGET`, so
  a legitimate pattern on a loaded host fails again. Trading a bias that only
  appears in an already-broken bundle for a failure that appears in a working
  one is the wrong direction.
- **Evaluate regex-bearing rules first, or last.** An attempt to shape the bias
  rather than remove it. Rejected because the engine sorts by `rule_id` so that
  evaluation order cannot depend on how a bundle was assembled, and making the
  order depend on predicate type gives that property up for no guarantee.
- **Pool the redactor's loop too.** Consistency would be tidy and the failure
  is per-string, not per-payload: a shared allowance would let one stalled
  string spend what the fields after it need, turning one stall into a record
  full of `[masked:timeout]`. The redactor's worst case is bounded per string
  and left there on purpose.
- **Catch it in `qed policy lint`.** Worth doing and not a substitute. Deciding
  whether a pattern backtracks catastrophically on *some* input is not
  something a linter settles, and a bundle that passed lint on one input can
  still meet the one that defeats it in production.
