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

Before the control catalogues existed that was the whole story, and the OSCAL
export handed an auditor a
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
dora             article      3/12       25.0%  16
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

**A percentage is a share of a scope, and the scope prints with it.** Every
catalogue declares what it covers, and `qed packs list` puts that sentence
under the table -- for the complete ones most of all. `eu_ai_act 44.4%` reads
as 44% of the Regulation; it is 4 of the 9 articles this catalogue covers, out
of 113. A `complete` catalogue is complete **for its scope**, never for the
whole standard.

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

**And a deliberate gap says why.** A control can carry a `note`, which prints
under the table:

```
eu_ai_act: not mapped -- Art. 26:
    Not mapped yet, and the likeliest of these five to become a real
    mapping: 26(5)'s monitoring and 26(6)'s log retention are what the
    evidence chain, the retention policy and the checkpoint anchors
    already do. It is unmapped because no rule declares it, not because
    nothing serves it -- the gap is in the rules.
```

A note is a **claim about this kernel** — what it does and does not record —
and never a reading of the standard. "Nothing here records a risk management
process" is checkable; "this article does not apply to us" is a legal opinion
and has no business in a YAML file. A gap with a stated reason is something an
auditor can disagree with; a bare absence is something they can only guess at,
and an unmapped control with no note means exactly "not mapped yet".

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

### A standard that is not published cannot be catalogued

ISO 42001 is 0 of 8 and stays at `depth: pack`, and the reason is in
`qed/compliance/packs/iso_42001.yaml` rather than left for a reader to guess.

The deepening that framework needs is its **Annex A** controls -- the
operational ones, where a policy kernel would have something to say. ISO/IEC
42001 is sold rather than published, and those titles are not available from an
authoritative public source. Writing them from memory would produce the one
thing this project refuses: not a title slightly wrong, but a whole catalogue
that looks verified and is not, attached to real rules, in a document an
auditor reads as authoritative.

Two things unblock it: a licensed copy of the standard read by whoever writes
the mapping, or a design partner who holds one and publishes a signed pack —
which needs no change to this repository at all.

The eight management-system clauses that *are* listed take their titles from
the published ISO harmonised structure, so they are checkable without the 42001
text. They are also the clauses a kernel is least able to serve, and each says
so.

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
   still leaves out. `scope` is required either way, because it is what a
   reader needs beside the number.
2. Add the `compliance:` entry to the rule.
3. `qed policy lint` and `qed packs list` — the coverage moves, or the id is
   wrong.

A new framework also needs an entry in `qed/compliance/frameworks.yaml` (its id,
aliases and mapping depth); a framework the normaliser knows with no catalogue
behind it is a test failure.

## Importing someone else's catalogue

A catalogue decides what the coverage report says and what an OSCAL finding's
`control-label` says. So the question the import is built around is **who
vouches for these control titles**.

```bash
qed packs verify bundle.qedpack.json                        # what is in it
qed packs verify bundle.qedpack.json --public-key pack.pem  # ...and does it verify
qed packs import  bundle.qedpack.json --public-key pack.pem
```

A bundle is one JSON envelope: the catalogues in the same shape as the YAML
files that ship with qed, plus `issuer`, `issued_at`, `key_id`, `alg` and a
`signature`. The signature covers **everything except itself**, `key_id`
included — a signature over the catalogues alone would let anyone restate which
key signed a bundle, or move `issued_at` to defeat the rollback check.

The key is a **pack key**, not the evidence key. The evidence key says what this
instance did; a pack key says what a publisher published. One key doing both
would mean an instance could sign its own catalogue, and the signature would
prove nothing about where the titles came from. There is no default and no key
inside the bundle: `--public-key` has to arrive by some route other than the
bundle, or the signature is checking the bundle against itself.

`verify` is separate from `import` because whether to trust a catalogue is a
decision somebody should make with the contents in front of them, and a command
that showed you the contents by installing them would not be giving you the
choice.

### What an import refuses

**A bundle that would stop the kernel deciding.** An imported catalogue
*replaces* the shipped one for its framework, so a bundle that does not list a
control an installed rule cites leaves that rule citing nothing — which is a
lint error, and the engine refuses to decide against a bundle with errors. The
import is checked against the loaded rules **before anything is written**:

```
  AG-BUD-003 cites dora Art. 8, which this bundle does not define
qed: refusing to import: 1 rule mapping(s) would be left citing a control no
catalogue defines ... Nothing was written.
```

This is not hypothetical. A three-article DORA bundle replaced the shipped
catalogue's one article, and the next `qed check` answered *"the policy bundle
has errors; refusing to decide against a broken bundle"*. The import had
succeeded; the instance governed nothing. `--allow-orphaned-rules` is there for
somebody who intends to fix the rules next and accepts what happens until they
do.

**A rollback.** A bundle issued before the installed one is refused, because
replaying an old bundle is how a control mapping is taken away without anybody
noticing: the import succeeds, the coverage report drops a framework, and
nothing says why. `--allow-rollback` if you mean it.

**A tampered or wrongly-keyed bundle**, obviously — and that check happens
before any file is touched.

### Unsigned is possible and loud

`--unsigned` imports a bundle with no signature. It is allowed because refusing
outright would push people to edit the installed files by hand, where nothing
would record it at all. What it costs: the `admin_action` record says
`unsigned: true`, the command prints `UNSIGNED`, and `policy_loaded` carries
`unsigned: true` from then on (SPEC §11).

### Every import is in the chain

An import appends an `admin_action` record — bundle hash, issuer, `issued_at`,
key id, frameworks, control count, and whether it was signed. A control title
an auditor reads has to be traceable to a moment and a key, and "the catalogue
said so" is not traceable on its own.

The catalogues land in `<state dir>/packs/`, next to a `bundle.json` manifest.
Not beside the ones in the package: a wheel is replaced on upgrade, and an
import that wrote into `site-packages` would vanish with it.

### What is not built

The `remote.packs` **feed** — fetching a bundle from a URL — is the same
verification with a download in front of it, and is not built. So there is no
`remote.packs.public_key` config key either; the key is a command-line
argument. `qed packs import FILE` is the air-gap case, and it reaches no
network at all.

## See also

- [The OSCAL export](oscal.md) — where the labels, sources and depths end up
- [Assurance classes](assurance-classes.md) — what a finding does and does not
  claim about qed itself
- [Policy language](policy-language.md) — the `compliance:` block
