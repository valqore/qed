# ADR-0016 — A rule that cannot be evaluated is skipped, and the skip is recorded

**Status:** accepted · 2026-10-15
**Fills:** a gap in SPEC §4.4 / §4.5, left open since week 1.

## Context

`evaluate_predicate` raises `PredicateError` when a predicate cannot be
evaluated. SPEC §4.5 step 2 says "evaluate `when` for each candidate → hits"
and says nothing about a `when` that does neither.

Almost every `PredicateError` is unreachable from the engine: `qed policy lint`
runs `validate_predicate` over every rule and a bundle with a structural fault
never loads. One is not. A `regex` operand is matched under a wall-clock budget
(`REGEX_TIMEOUT`, 1 s) and a pattern that exceeds it raises at evaluation time —
by design for a catastrophic pattern, and by accident for an ordinary one when
the machine is loaded enough to deschedule the matching thread. That accident
happened: in October 2026 a CI runner spent a then-100 ms budget on a pattern
that matches in 219 microseconds.

Until this decision, nothing in `qed/` caught `PredicateError`. It propagated
out of `evaluate`, which is called inside the request path, so the result was
a 500 and no decision at all — the kernel neither allowed nor blocked, and the
adapter's fail-open or fail-closed behaviour decided the action instead. Worse
than the outcome was the silence: nothing in the evidence chain said that a
rule had not run.

## Decision

A `when` that raises `PredicateError` **skips its rule**, and the skip is
recorded in the verdict.

- The rule is not a hit. It does not contribute to `decision` or to
  `would_decision`, and `approval_spec` cannot select it.
- The verdict carries one synthetic hit, `AG-PRD-001`, whose `message` names
  every rule that was skipped and why, clipped to 120 characters per reason
  because a rule's own regex travels into an evidence record.
- That hit is `mode: shadow` with verdict `ALLOW`, and `evaluate` appends it
  **after** the decision is computed. Anything that recomputes the decision
  from the enforce-mode hits — a dashboard, the verifier, a reader of the
  chain — still arrives at the decision the kernel gave.
- `default_applied` is left as computed. When the skipped rule was the only
  candidate, the verdict carries both `AG-DEF-001` and `AG-PRD-001`: no rule
  matched, and one rule never got to say.
- `qed_decisions_rule_skipped_total` counts the decision, and
  `qed policy explain` lists the rules under `rules_skipped` with the reason
  unclipped.

## Consequences

- A catastrophic pattern in one rule costs that rule, not the kernel. The
  blast radius of a bad regex is one rule's coverage for as long as it takes to
  notice, and noticing is a counter rather than an archaeology exercise.
- A verdict can now be short of a rule the bundle contains, and say so. An
  auditor replaying a record sees that this decision was taken with less policy
  than the bundle held, which is the honest reading and was previously
  unavailable at any price.
- `evaluate` stays pure, but a timeout is not reproducible: the same inputs on
  a quieter machine produce a verdict without the `AG-PRD-001` hit. The record
  is the only evidence that the skip happened, which is the argument for
  recording it rather than only counting it.
- `AG-PRD-001` in a chain is an operator defect, not an agent's behaviour. It
  belongs in the same category as `qed_ungated_windows_total`: a report that
  governance was thinner than configured for a known interval.

## Alternatives rejected

- **Treat the failure as a match.** Fail-closed, and tempting for a security
  product. Rejected because the failure mode that actually occurred was machine
  load: it would make a busy runner into a BLOCK of work that policy allows,
  and the first lesson an operator draws from that is to switch the pack off.
  A `BLOCK` rule and an `ALLOW` rule would also behave in opposite directions
  for the same cause.
- **Refuse the proposal.** This is what the code did by accident, with no
  record. As a deliberate choice it gives one bad pattern in one rule the power
  to stop every action the kernel governs, and it hands an attacker who can
  author or influence a rule a denial of service against everything.
- **Skip silently.** The cheapest change and the worst one. A policy kernel
  whose coverage can shrink without anything saying so has given up the only
  claim it makes.
- **A hit per skipped rule.** `hits` is read as the list of rules that fired;
  repeating `AG-PRD-001` would read as one rule firing several times. The
  rule ids are in the one hit's message instead.
