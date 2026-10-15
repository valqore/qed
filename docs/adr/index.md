# Decisions

`QED_SPEC.md` is normative, and it is also incomplete — as any specification
written before the code is. Where it was silent, or where following it literally
would have been wrong, the choice is recorded here rather than left in the
commit log.

The rule is in [GOVERNANCE.md](../governance.md): *"The spec was silent so I
picked one" is fine; "the spec was silent so nobody knows why it works this way"
is not.*

Each ADR states the context, the decision, the consequences, and the
alternatives that were rejected. They are not revised after the fact — a
decision that turns out wrong gets a new ADR that supersedes it, because the
reasoning that led somewhere wrong is part of the record.

`DESIGN_DECISIONS.md` holds ADR-001…008 from the planning phase, before any
code existed. The numbered files here are the ones made while implementing, and
they are the ones with teeth.

## Four worth reading even if you read nothing else

| ADR | Why |
|---|---|
| [ADR-0011](0011-catalogues-are-authored-and-coverage-refuses-a-percentage.md) | The spec said to import the control catalogues from a proprietary repository into an Apache-2.0 one. It could not be done, and the honest consequence is that coverage refuses to print a percentage it cannot support. |
| [ADR-0012](0012-a-pack-bundle-is-one-signed-envelope.md) | Two individually correct decisions composed into a remote kill switch: an import that could stop the kernel deciding. |
| [ADR-0010](0010-rotation-destroys-the-old-private-key.md) | Rotation that leaves the old private key on disk has rotated nothing. |
| [ADR-0001](0001-blast-radius-table.md) | The spec said to port the blast-radius table from Valqore. It is written fresh, and the ADR says why that is a licensing fact and not a preference. |

## All of them

| ADR | Decision |
|---|---|
| [0001](0001-blast-radius-table.md) | The blast-radius score is written fresh, not ported |
| [0002](0002-predicate-semantics.md) | A missing field is falsy for every operator except `exists` |
| [0003](0003-derived-budget-fields.md) | Budget comparisons are precomputed, and "cost unknown" is a field |
| [0004](0004-bundle-hash.md) | `policy_hash` covers `default_verdict` and ignores file layout |
| [0005](0005-record-encoding.md) | Record encoding details the spec leaves open |
| [0006](0006-format-constants-carry-no-product-name.md) | Hash domain separators carry no product name |
| [0007](0007-status-endpoint-for-the-ui-badge.md) | `GET /v1/status` for the UI badge, and it does not verify |
| [0008](0008-hook-answers-ask-and-never-allow.md) | The hook answers `ask`, never `allow`, and never exits 1 |
| [0009](0009-the-outbox-and-one-chain-leader.md) | Deciding is durable, chaining is deferred to one leader |
| [0010](0010-rotation-destroys-the-old-private-key.md) | Rotation destroys the old private key, and the writer enforces continuity |
| [0011](0011-catalogues-are-authored-and-coverage-refuses-a-percentage.md) | The control catalogues are authored, and coverage refuses a percentage |
| [0012](0012-a-pack-bundle-is-one-signed-envelope.md) | A pack bundle is one signed envelope, and an import cannot stop the kernel |
| [0013](0013-the-anchor-client-sends-six-values.md) | The anchor client sends six values, and the operator names the log |
| [0014](0014-qed-governs-its-own-admin-operations.md) | QED governs its own admin operations, off by default, with a loud break-glass |
| [0015](0015-the-evidence-format-is-frozen-against-a-fixture-not-a-promise.md) | The evidence format is frozen against a committed fixture, not a promise |
| [0016](0016-an-unevaluable-rule-is-skipped-and-recorded.md) | A rule that cannot be evaluated is skipped, and the skip is recorded |
