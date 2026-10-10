# Control catalogues and coverage

What `eu_ai_act Art. 14` is, which controls this rule set actually maps to, and
which it does not.

```bash
qed packs list            # the table below
qed packs list --json     # the same thing for a pipeline
```

## Why there are catalogues at all

A rule declares what it serves:

```yaml
compliance:
  - { framework: eu_ai_act, control: "Art. 14" }
```

Until week 8 that was the whole story, and the OSCAL export handed an auditor a
list of identifiers with no titles. Two things were missing: what the control
*is*, and whether the mapping was thorough or decorative.

`qed/compliance/packs/<framework>.yaml` answers the first. Each file carries the
framework's controls with a short label, the `source` URL for the standard
itself, and — where the identifiers depend on it — the edition they come from.
The labels travel into every OSCAL finding as `control-label`, and the source as
`catalogue-source`.

**A label is this catalogue's description, not a quotation.** Nothing in these
files claims to reproduce legal or standards text. That is what `source` is for,
and it is attached to every finding so the reader can always get to the words
that matter.

## Coverage

```
FRAMEWORK        DEPTH        MAPPED   COVERAGE  RULES
dora             pack         1/1      partial  1
eu_ai_act        article      4/9        44.4%  28
iso_27001        pack         1/1      partial  1
iso_42001        pack         0/8      partial  0
nist_ai_rmf      category     5/5      partial  26
nist_csf         pack         2/2      partial  2
owasp_agentic    category     7/10       70.0%  27
owasp_llm        category     3/10       30.0%  9
owasp_mcp        category     1/10       10.0%  1
soc2             pack         9/9      partial  27
```

Three deliberate refusals in that table.

**A percentage needs a complete catalogue.** `soc2` is 9 of 9 and prints
`partial`, not 100%. The nine are the Trust Services criteria this rule set maps
to; they are not all of SOC 2. A percentage over a list somebody curated reads
as *complete* and is not, which is the single most common way a compliance
feature lies. Only a catalogue marked `catalogue: complete` — the EU AI Act's
high-risk articles, the three OWASP Top 10s — gets a number.

**An unmapped framework still gets a catalogue.** `iso_42001` is 0 of 8, with
every clause named under the table. Leaving the pack out would have made it look
like a framework nobody had considered; a visible zero is a gap somebody can
close.

**The unmapped controls are listed by name**, because the first question an
auditor asks is not which controls you claim but which you do not. For a partial
catalogue, absence means *not mapped* — never *not applicable*.

### `depth`

SPEC §11's honesty flag: how deep a mapping goes, not how good it is.

| depth | means |
|---|---|
| `article` | mapped to a specific article or clause of the standard |
| `category` | mapped to a named category or subcategory |
| `pack` | mapped at the level of the framework, not a control within it |

An `article` mapping and a `pack` mapping both produce a finding, and they are
not the same evidence. The flag is on every finding as `mapping-depth` so
nobody has to come back here to weigh them.

### Editions

`nist_csf` records `version: 1.1`, because `PR.AC-4` is a 1.1 identifier and
does not exist in CSF 2.0, where that family became `PR.AA`. A mapping to a
retired identifier is one nobody can follow, so the edition is written down
rather than assumed.

## Framework aliases

`EU AI Act`, `eu-ai-act` and `AI Act` all mean `eu_ai_act`. The engine
normalises on read, so a rule written either way decides correctly. What
normalising on read does *not* do is group: two spellings would be two rows in
the table above and two control sets in an OSCAL export, with nothing telling
the reader they are one framework.

```bash
qed policy normalize-frameworks policies/            # rewrite in place
qed policy normalize-frameworks policies/ --check    # exit 1 if anything would change
```

It is a text substitution on the `framework:` value and nothing else. A YAML
round-trip would reformat every comment and quote style in a file somebody wrote
by hand, and the diff would be unreviewable.

## An unknown control is an error

`qed policy lint` fails on a control that no catalogue defines, and
`qed decide` refuses to run against a bundle that has errors.

```
ERROR [unknown_control] skills.yaml AG-SKL-006: owasp_llm has no control 'LLM02'
in its catalogue. Catalogued: LLM01, LLM02, ... Add it to
qed/compliance/packs/owasp_llm.yaml, or fix the mapping -- a control id nothing
defines becomes an untraceable line in an OSCAL export.
```

An error rather than a warning on purpose. A control id that is nearly right
reaches the OSCAL export looking exactly like a real mapping, and the first
person to notice is the auditor who goes looking for the control and finds
nothing.

## Adding a mapping

1. The control must be in `qed/compliance/packs/<framework>.yaml`. If the
   framework's catalogue is `complete`, the control is already there; if it is
   `partial`, add it with a label and keep `scope` honest about what the file
   still leaves out.
2. Add the `compliance:` entry to the rule.
3. `qed policy lint` and `qed packs list` — the coverage moves, or the id is
   wrong.

A new framework also needs an entry in `qed/compliance/frameworks.yaml` (its id,
aliases and mapping depth); a framework the normaliser knows with no catalogue
behind it is a test failure.

## Importing someone else's catalogue

`qed packs import` is week 9, together with the signature verification it needs.
Importing an unsigned catalogue would put control titles in front of an auditor
with nobody vouching for where they came from, so it refuses rather than
accepting one in the meantime.

## See also

- [The OSCAL export](oscal.md) — where the labels, sources and depths end up
- [Assurance classes](assurance-classes.md) — what a finding does and does not
  claim about qed itself
- [Policy language](policy-language.md) — the `compliance:` block
