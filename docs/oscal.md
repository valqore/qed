# The OSCAL export

For auditors, and for whoever has to answer them.

```bash
qed export --dir .qed --format oscal --out assessment.json
# or
curl -s 'localhost:8710/v1/evidence?format=oscal&from=0&to=999' > assessment.json
```

The output is an OSCAL 1.1.2 `assessment-results` document (SPEC §10.8). It
validates against the published NIST schema in CI, which SPEC §10.8 marks
**MUST pass**.

## What maps to what

| qed | OSCAL |
|---|---|
| one export | one `result` |
| one evidence record | one `observation` |
| the assurance class (ADR-007.1) | the observation `type`, e.g. `assurance-kernel` |
| one rule hit × one control reference | one `finding` |
| the control the rule claims to serve | `finding.target.target-id` |
| public keys, checkpoint roots | `back-matter.resources` |

Each finding links back to the observation it came from through
`related-observations`, so an auditor can walk from a control to the signed
record that justifies the claim.

## Read this part before you quote the document

**The mapping is only as deep as the rules.** Week 2 exports the control
references that the baseline rules carry in their own `compliance:` blocks, and
nothing else. There is no control catalogue, no control titles, and no coverage
claim. Every finding target carries `mapping-scope: rule-declared` and the
document metadata carries
`mapping-scope: baseline-rule-control-references-only` so this is visible in the
file rather than only in this page. The compliance packs, and the complete EU AI
Act and NIST AI RMF mappings, are week 8.

**A finding is about the action, not about qed.** A rule that matched means the
action the agent proposed did not satisfy the control objective, so the status is
`not-satisfied` with reason `fail`. Whether QED then stopped it is a separate
fact, in the `enforced` and `rule-mode` properties. In shadow mode the objective
was equally unsatisfied and nothing was prevented — do not read a shadow finding
as a control that worked.

**A rule hit with no control reference is not a finding.** `finding.target` is
required by the schema, and a hit with no `compliance:` block has no control to
target. Those hits are not dropped quietly: they are named on the observation and
counted in the result properties as `rule-hits-without-control`, with a sentence
in `result.remarks` saying so. Adding a control reference is a policy change, not
an export change.

## Identifiers are derived, not random

Every UUID is a version 5 UUID derived from the thing it names: an observation
from the evidence record's hash, a finding from that hash plus the rule and the
control. Exporting the same range twice gives byte-identical output, and two
auditors working from two copies of the same chain get the same document
identifiers.

OSCAL accepts v4 or v5. v4 would have made every export unreproducible, which
is a poor property for a document whose job is to be checked.

The only value not derived from the chain is `metadata.last-modified`, which the
caller passes in.

## Control ids are tokenised

OSCAL's `target-id` is an NCName: no spaces, no colons, and it may not start
with a digit. Real control ids break all three rules — `Art. 14`, `A.5.34`,
`6.2.4`. So they are tokenised:

| framework | control | `target-id` |
|---|---|---|
| `eu_ai_act` | `Art. 14` | `eu_ai_act.art-14` |
| `soc2` | `CC8.1` | `soc2.cc8.1` |
| `iso_27001` | `A.5.34` | `iso_27001.a.5.34` |
| `nist_ai_rmf` | `MANAGE-2.2` | `nist_ai_rmf.manage-2.2` |

The verbatim framework and control stay on the target as properties, which is
what a human reads. Single separators survive so a control stays recognisable —
`soc2.cc8.1`, not `soc2-cc8-1`.

## Verifying the chain the document describes

`back-matter` embeds each signing public key as a base64 resource, so the
document contains what is needed to check it:

```bash
qed export --dir .qed --out chain.jsonl
qed-verify chain.jsonl --keys .qed/public --instance-id <id>
```

The observations carry `record-hash`, `previous-hash`, `payload-hash` and
`signature`, so the linkage is readable from the OSCAL document alone, though
`qed-verify` on the JSONL export is the supported path.

Checkpoints in the range appear as their own back-matter resources with the
Merkle root and the number of publication receipts attached to the previous
checkpoint (SPEC §10.4).

## `import-ap`

OSCAL requires `import-ap`, a reference to an assessment plan. qed monitors
continuously rather than running a planned assessment, so there is no plan
document. The reference resolves to a back-matter resource that says exactly
that, rather than pointing at a file that does not exist.

## A filtered export is refused

`format=oscal` with a `type` filter is a `400`. An assessment-results document
states what was observed over a period; assembled from a subset it would omit
observations without saying so, and this is the document that goes to an
auditor. Export a sequence range instead.

Purged payloads (SPEC §10.6) are fine: the observation says the payload was
removed under the retention policy and that the hashes and signature are intact.

## How it is checked

`tests/evidence/test_oscal_schema.py` validates the export against
`tests/oscal/oscal_assessment-results_schema.json`, the published NIST v1.1.2
schema, vendored byte for byte and checked by sha256 before use — an export that
validated against a schema somebody adjusted would prove nothing.

Two details worth knowing if you work on that file:

- The suite swaps `jsonschema`'s regex engine for the `regex` module. The NIST
  schema uses ES2018 Unicode property escapes (`\p{L}`), including in the
  `TokenDatatype` that constrains every `target-id`; CPython's `re` raises
  `bad escape \p` on those, so a stock validator cannot read the real schema at
  all. The swap makes the check stricter, not weaker.
- There are negative controls. A validator that accepts everything is worse than
  no validator, and this whole claim rests on one, so the suite also feeds it a
  version-1 UUID, a `target-id` with spaces, a missing required field and an
  empty array, and fails if any of them is accepted.
