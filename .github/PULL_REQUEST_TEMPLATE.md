<!--
`CONTRIBUTING.md` has the long version. This is the short list, and the boxes
are the definition of done from SPEC §23 rather than ceremony.

Open an issue first for anything that adds a dependency, changes the evidence
format, adds a rule to the baseline pack, or touches `qed.core`.
-->

## What this changes, and why

<!-- The "why" is the half a reviewer cannot reconstruct from the diff. -->

## How you know it works

<!--
Name the test. "CI is green" is not an answer -- the suite was green through
every bug listed in `docs/validation.md`, including a mandate signature that
nothing verified for eight weeks while its unit tests passed.

If the change is one a passing test cannot detect, say so and say what you ran
by hand instead.
-->

## Checklist

- [ ] Every commit is signed off (`git commit -s`) — DCO, enforced by CI
- [ ] `ruff check .` and `ruff format --check .` pass
- [ ] `python -m mypy` passes
- [ ] `pytest` passes, and there is a test that fails without this change
- [ ] Documentation updated if behaviour or output changed, and `pytest tests/docs` passes
- [ ] `CHANGELOG.md` has an entry under `[Unreleased]`, unless this is internal only

## Things that need saying explicitly

- [ ] **This does not change the evidence format.** If it does: it is additive,
      `schema_version` is handled, `tests/evidence/fixtures/evidence-format-1.0/`
      still verifies byte for byte, and an ADR explains it. The format is frozen
      (ADR-0015) and a record written under 1.0 must verify under every later
      verifier, forever.
- [ ] **This does not make the product claim more than it does.** A new
      capability row, a mitigation, a compliance mapping, or a line of output
      that reads stronger than the code supports is the defect class this
      project cares about most.
- [ ] **No proprietary code, and no commercial planning material.** This
      repository is Apache-2.0 and its history is irreversible.
