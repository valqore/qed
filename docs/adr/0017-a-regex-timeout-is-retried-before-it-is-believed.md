# ADR-0017 — A regex timeout is retried before it is believed

**Status:** accepted · 2026-10-19
**Extends:** [ADR-0016](0016-an-unevaluable-rule-is-skipped-and-recorded.md), whose reasoning covered a caller it was not applied to.

## Context

Two places in the kernel match untrusted text against a fixed pattern set: the
policy engine's `regex` predicate and the evidence redactor. Both guard against
a pattern that will not finish by passing `timeout=` to the `regex` module.

That timeout is **wall clock**, not work. It cannot distinguish the two things
it is asked to:

- a pattern that backtracks catastrophically on this input — a property of the
  pattern and the input, which is what the guard is for; and
- a thread the host descheduled mid-match — a property of the neighbours.

ADR-0016 established this on the predicate side after a runner spent a 100 ms
budget on a pattern matching in 219 microseconds, and raised the budget to one
second. It did not change the mechanism, because a wider budget is the only
lever a single attempt offers.

Two things then happened that this decision answers.

**The reasoning was about the library, so it governed both callers, and was
applied to one.** `core/evidence/masking.py` kept 100 ms. Four days later the
`postgres` job — the only CI job with a service container competing for CPU —
masked `mcp-proxy/0.1.0`, fifteen characters needing about five microseconds,
as `[masked:timeout]` *inside an evidence record*. Twice. The measured
mechanism is GIL handoff: sixteen competing Python threads wait roughly 85 ms
for the interpreter lock, against a 100 ms budget.

**The redactor's failure is worse than the predicate's, and silent.** A skipped
rule is recorded as `AG-PRD-001` and an auditor can see it. Masking runs
*before* `payload_hash`, so a record whose content was replaced hashes
correctly, verifies correctly under `qed-verify`, and is indistinguishable from
a deliberate redaction forever. Nothing re-runs masking and the original string
is never written down, so there is no second chance at it.

Widening the budget was also not free, and not sufficient. It is granted inside
a loop, so sixteen patterns at one second each is a sixteen-second worst case
for one string: `test_concurrency_does_not_collapse_throughput` fell to 0.23x
against a 0.4x gate, where five consecutive runs on `main` had printed 0.5x.
That was fixed by making the budget a deadline for the call. But no budget and
no granularity addresses the original problem, which is that the clock measures
the host.

## Decision

**A timeout is a question, not an answer.** Both callers run their matching
through `qed.core.regex_budget.under_budget`, which retries a `TimeoutError`
`ATTEMPTS` times (3) before re-raising it, each attempt under a whole fresh
`BUDGET` (1 s).

The retry is the only mechanism that separates the two causes, because a
pathological pattern blows every budget it is given and a stall does not recur.
Three attempts rather than two: a stall that happens to recur once looks
exactly like a pattern that always fails, and two answers cannot break a tie.

- **The budget and the retry live in one module**, which both callers import.
  Two numbers meant to be one will drift; a test asserts they have not.
- **Failing closed is kept.** When every attempt times out, the predicate still
  raises `PredicateError` and the redactor still returns `[masked:timeout]`.
  ADR-0016's handling of the former is unchanged.
- **The work must be pure**, since it runs up to three times. Both callers
  build a new string or return a bool; the redactor rebuilds from the original
  text on each attempt, never from a half-masked intermediate.
- **A spent budget raises rather than returning zero.** `regex` reads a
  non-positive timeout as *no* timeout, so returning the exhausted number would
  drop the guard at the one moment it is working, and the failure would be a
  hang rather than a refusal.

## Consequences

- A host stall no longer corrupts an evidence record or costs a rule its
  coverage, unless it recurs three times in a row.
- **The worst case for one unevaluable pattern triples**, from `BUDGET` to
  `ATTEMPTS * BUDGET` — 3 s. That is the price of the discrimination and it is
  paid only by a pattern that genuinely cannot be evaluated, which is an
  operator defect in a rule the kernel reports.
- **That worst case still multiplies by the loop above it**, and this decision
  does not bound that. The redactor masks each string in a payload separately,
  and the engine evaluates each rule in a bundle separately, so a bundle of 46
  rules whose patterns all failed would be 46 × 3 s. The redactor's loop is
  per-string on purpose — a payload-wide deadline would let one stalled string
  corrupt every later field in the same record — and the engine's is left alone
  deliberately: a deadline across one evaluation would make *which* rules get
  skipped depend on timing and rule order, so two replicas could reach
  different decisions on identical input. Bounding it is a separate decision
  and needs to be, because it touches what a verdict means.
- Nothing here makes a timeout impossible, and no document should say it does.
  Three stalls in a row are unlikely, not excluded.
- Record hashes are unaffected. The pattern set has not changed, so every input
  masks to exactly what it masked before; `qed-verify` recomputes from the
  payload as stored and never re-runs masking.

## Alternatives rejected

- **Only widen the budget.** What ADR-0016 did, and it is what a single
  attempt allows. It trades the two failures against each other instead of
  separating them: wide enough to survive a loaded host is also wide enough
  that a pathological pattern is expensive, and the cost lands in the request
  path.
- **Measure CPU time instead of wall clock.** The correct instrument, and the
  `regex` module does not offer it. Implementing it outside the library means
  interrupting a C extension mid-match, which there is no supported way to do.
- **Scale the budget by input length.** Sound in principle, since catastrophic
  backtracking needs length, and it addresses the wrong failure: the string
  that broke this was fifteen characters. Length tells you what a pattern
  *could* cost, not whether the host stole the time.
- **Retry in the redactor only.** The redactor's failure is the worse of the
  two, so this is the tempting scope. Rejected because applying a
  library-level decision to one of its two callers is exactly the mistake this
  ADR exists to correct, and the asymmetry would be invisible again in four
  days.
- **Drop the guard for short strings.** No short input can make this rule set
  take meaningful time — measured at about five microseconds — so the budget
  could apply only above some length. Rejected because the bound is a property
  of *these* patterns, measured once, and the guard would then silently cease
  to cover a pattern added later. A rule set is not a fixed thing.
