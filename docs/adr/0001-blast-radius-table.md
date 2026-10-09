# ADR-0001 — The blast-radius score is written fresh, not ported

**Status:** accepted · week 1
**Supersedes for implementation purposes:** the porting instruction in SPEC §5
and the `governance/blast_radius.py` row in SPEC Appendix B.

## Context

SPEC §5 says: "Blast radius: deterministic table … ported from Valqore
`governance/blast_radius.py` with the K8s-specific parts removed."

Valqore's module at `e7e66a3` is a Kubernetes dependency-graph analyser. It
resolves Service→Deployment selectors, reads PodDisruptionBudgets,
HorizontalPodAutoscalers and NetworkPolicies, and returns
`blast_radius: int` — a **count of affected resources**.

Two things follow:

1. Removing the Kubernetes-specific parts removes the module. The graph walk is
   the module; there is no environment-agnostic core underneath it.
2. The unit is wrong. qed's `derived.blast_radius` is a 0–100 risk score, and
   ADR-008 gates unattended agents on `blast_radius > 60`. As a resource count,
   "> 60" means "touches more than sixty objects", which is a completely
   different statement and happens to be false for every single-row `DROP TABLE`
   in production.

Also, qed explicitly leaves Kubernetes manifest analysis in Valqore
(SPEC §1.3), so the input this module needs does not exist here.

## Decision

Write `qed/core/policy/blast_radius.py` fresh as an additive table over fields
the proposal already carries: scope, environment, kind, writes, deletes, and two
pattern signals. Clamp at 100. Document the table in `docs/blast-radius.md` and
expose the per-contribution breakdown through `qed policy explain`.

Delete the `governance/blast_radius.py` row from the port list.

Two deliberate differences from a naive reading of the spec:

- **Parameters are scanned, not just the name and target.** Valqore's MCP
  gateway scores from the tool name, so `execute_sql` carrying `DROP TABLE`
  scores low. Scanning is capped at 4 KB.
- **`_` is treated as a word separator** in both pattern sets, because
  `GITHUB_TOKEN` and `terminate_instances` are the normal naming style for the
  resources being scored and `\b` does not match across `_`.

## Consequences

- Nothing in the score depends on Kubernetes, so it works for MCP, HTTP, shell
  and skill actions equally.
- The table is auditable by hand, which matters more here than sophistication:
  an approver who cannot explain why a number is 75 will not trust it.
- Changing the table changes decisions for threshold rules. Procedure for that
  is in `docs/blast-radius.md`.
- Valqore keeps its resource-count metric under its own name. The two numbers
  are never compared.

## Alternatives rejected

- **Port it anyway and keep the count.** Every threshold in the spec and in
  ADR-008 would have to be rewritten, and the number would be unavailable for
  non-Kubernetes actions, which is most of them.
- **Model-scored risk.** Breaks invariant §1.4.1 and makes a decision
  unreplayable.
- **Operator-configurable weights.** Defer. Two installations with different
  weights cannot compare evidence, and nobody has asked yet.
