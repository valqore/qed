# ADR-0011 — The control catalogues are authored, and coverage refuses a percentage

**Status:** accepted · week 8 (2026-10-10)
**Implements:** SPEC §11 (compliance mapping), §10.8 (OSCAL export)
**Relates to:** ADR-0006 (format constants carry no product name)

## Context

SPEC §11 says the packs are "imported from Valqore `compliance/packs.py`,
subset", and gives each one `controls with ids/titles` plus a `depth` honesty
flag. It is silent on two things that turn out to decide whether the feature is
honest: where the titles come from, and what a coverage number means.

## Decision 1 — The catalogues are authored here, not imported

`valqore-engine` is private and proprietary. This repository is Apache-2.0 and
its history is irreversible, so nothing from that repository enters it — the
spec's "imported from" cannot be taken literally regardless of what the
catalogues contain.

That constraint turned out to be the better engineering answer anyway. The
control titles were written against the standards' own published material — the
NIST AI RMF Playbook, the OWASP Agentic / LLM / MCP Top 10 pages, the AICPA
TSC, the regulation texts — rather than transcribed from another codebase or
from memory. Two things came out of doing it that way that an import would have
carried forward silently:

- `ASI01`–`ASI10` are the real OWASP Agentic identifiers. The engine uses an
  `AAI` prefix of its own invention, which would have put identifiers in front
  of an auditor that OWASP has never published.
- `PR.AC-4` is a NIST CSF **1.1** identifier. CSF 2.0 renamed that family to
  `PR.AA`, so the pack records `version: 1.1` instead of implying the mapping
  is current. A mapping to a retired identifier is one nobody can follow.

Each file carries a `source` URL, and **a label is this catalogue's description
and not a quotation**. Nothing here claims to reproduce legal or standards
text; `catalogue-source` travels with every OSCAL finding so the reader can
always reach the words that matter.

## Decision 2 — A percentage requires a complete catalogue

The obvious coverage report prints `mapped / total`. Over a catalogue that
lists only the controls somebody chose to list, that number is a lie with a
decimal point on it: SOC 2 would read **9 of 9, 100%**, when the nine are the
Trust Services criteria this rule set maps to and the full TSC runs to roughly
sixty, most of them about an organisation rather than an agent's actions.

So every pack declares `catalogue: complete | partial`, and `Coverage.percentage`
returns `None` for a partial one. `qed packs list` prints `partial` in that
column and a sentence under the table saying there is no honest percentage to
print. Four frameworks are complete and get a number: the EU AI Act high-risk
articles and the three OWASP Top 10s.

The alternative — a percentage with a footnote — was rejected because the number
is what gets copied into a slide and the footnote is not.

`scope` is required on **every** pack, not only the partial ones, and
`qed packs list` prints it beside the table. For a partial catalogue it says
that absence means *not mapped* and never *not applicable*. For a complete one
it says what the completeness is *of*: the EU AI Act pack prints 44.4%, which
reads as a share of the Regulation and is 4 of the 9 articles this catalogue
covers, out of 113. A number without its scope is the same overclaim as a
percentage over a curated list, one level up.

## Decision 3 — An unmapped framework still ships a catalogue

ISO 42001 maps to nothing: 0 of 8 clauses. The file ships anyway, and
`qed packs list` prints the zero and names all eight.

Omitting it would have been the flattering choice — the report would show only
frameworks with something in them, and a reader would conclude that ISO 42001
was a framework nobody had considered rather than one with a known, measured
gap. A visible zero is a gap somebody can close.

## Decision 4 — An uncatalogued control is an error, not a warning

SPEC §11 makes an unknown *framework* a lint warning, and that stands: it is
usually a typo in a file somebody is still editing, and refusing the whole
bundle would stop them fixing the other twenty rules.

An unknown **control** is different. The framework resolves, the rule loads,
the decision is correct, and the mapping reaches the OSCAL export looking
exactly like a real one — `eu_ai_act Art. 999`, with a target id and a status
and a link back to a signed record. The first person to notice is the auditor
who goes looking for the control and finds it does not exist, and by then the
document has been sent.

So the loader emits an `error`, and `qed decide` refuses to run against a
bundle with errors. The cost is that adding a mapping is now two steps —
catalogue the control, then cite it — which is the right order anyway.

## Decision 5 — Normalisation is a text substitution

Framework aliases normalise on read, so a rule that says `EU AI Act` decides
identically to one that says `eu_ai_act`. What normalising on read does not do
is group: two spellings are two rows in the coverage report and two control
sets in an OSCAL export, with nothing telling the reader they are one
framework.

`qed policy normalize-frameworks` rewrites them in the file. It is a regex
substitution on the `framework:` value and nothing else, deliberately: a YAML
round-trip would reformat every comment, quote style and flow mapping in a rule
file somebody wrote by hand, and the diff would be unreviewable — which means
it would be approved without being read, on a file that decides what agents may
do.

It leaves an unknown framework alone rather than failing, because `policy lint`
already reports that and a rewriter that stopped on the first one would be
useless on the file that needs it most.

## Consequences

- Deepening a mapping is a pack edit plus a rule edit, and `qed packs list`
  moves. Nothing can claim a control the catalogues do not define.
- Four frameworks show a percentage; six show `partial`. Making one of those
  six show a number means completing its catalogue, not changing this code.
- The catalogues are ours to maintain, with no upstream to pull from. Signed
  pack import (`qed packs import`, week 9) is how somebody else's catalogue
  gets in, and it refuses unsigned input rather than accepting it in the
  meantime: control titles an auditor reads need somebody vouching for where
  they came from.
