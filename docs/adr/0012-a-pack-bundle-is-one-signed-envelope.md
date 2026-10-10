# ADR-0012 — A pack bundle is one signed envelope, and an import cannot stop the kernel

**Status:** accepted · week 9 (2026-10-10)
**Implements:** SPEC §11 (signed pack updates, `qed packs import`)
**Relates to:** ADR-0005 (record encoding), ADR-0010 (rotation), ADR-0011 (the catalogues)

## Context

SPEC §11 says: *packs carry `signature` by qed's pack key; `qed packs import
file.sig` for air-gap; unsigned packs load with `unsigned: true` in
`policy_loaded`.* That fixes the intent and leaves the shape open.

What is at stake is narrow and sharp. An imported catalogue decides what
`qed packs list` reports and what an OSCAL finding's `control-label` says. It
is the words an auditor reads. So every decision below answers one question:
**who vouches for these control titles, and how would anyone check?**

## Decision 1 — One self-contained JSON envelope, not a detached `.sig`

The spec's `file.sig` suggests a detached signature. A bundle is instead a
single JSON file carrying the catalogues *and* the signature, conventionally
named `*.qedpack.json`.

Two files can be separated, and when they are, the failure is quiet: a
catalogue arrives, its signature does not, and somebody imports it `--unsigned`
because that is the flag that makes the error go away. One file cannot lose
half of itself.

The envelope is JSON rather than YAML because it is signed. The signature
covers `qed/core/jcs.py`'s canonical form, which is the same canonicalisation
the evidence chain uses (ADR-0005) — one canonicaliser in the codebase, not
two. YAML has no canonical form worth signing. The *catalogues inside* keep the
same shape as the YAML files that ship with the package, so one loader reads
both and an operator can diff an imported catalogue against a shipped one.

## Decision 2 — The pack key is not the evidence key

The evidence key says *what this instance did*. A pack key says *what a
publisher published*. They are different claims by different parties.

One key doing both would mean an instance could sign its own catalogue, and the
signature would then prove nothing about where the control titles came from —
it would prove only that the machine which installed them also installed them.

So `qed packs import` takes `--public-key PEM`, there is no default, and the
bundle's own `key_id` is **not** accepted as the answer to which key to use. A
bundle naming its own key is a bundle checking itself. The key has to arrive by
some route other than the bundle; `key_id` is only compared against the key you
supplied, so a mismatch is reported rather than silently accommodated.

## Decision 3 — The signature covers everything except itself

Including `key_id`, `issuer` and `issued_at`.

A signature over the catalogues alone would let anyone restate which key signed
a bundle, change the issuer, or move `issued_at` to defeat the rollback check —
all without breaking anything. Tests tamper with each of those three fields
individually, and each tamper asserts that the value actually changed first: a
"tamper" that set a field to what it already held once produced a verifier that
looked like it was accepting forgeries.

## Decision 4 — An import that would stop the kernel deciding is refused

**This is the one that was found by running it, not by reasoning.**

An imported catalogue replaces the shipped one for its framework. ADR-0011 made
an uncatalogued control a lint *error*, and the engine refuses to decide against
a bundle with errors. Put those together: a bundle that simply does not list a
control some installed rule cites leaves that rule citing nothing, and the
kernel stops deciding.

A three-article DORA bundle replaced the shipped catalogue's one article. The
import succeeded. The next `qed check` answered *"the policy bundle has errors;
refusing to decide against a broken bundle"*. The instance governed nothing,
and the thing that had switched it off was a file from a third party.

So the import checks the bundle against the loaded rules **before anything is
written**, names every rule it would orphan, and refuses. Nothing is touched,
so the instance is exactly as it was.

The alternative — downgrading an unknown control to a warning when the
catalogue was imported — was rejected: it puts the untraceable OSCAL line back,
which is precisely what the error exists to prevent. A catalogue that does not
fit the rules is a mismatch for a person to resolve.
`--allow-orphaned-rules` exists for somebody who intends to fix the rules next
and accepts that the instance decides nothing until they do.

## Decision 5 — A bundle older than the installed one is refused

Replaying an old bundle is how a control mapping is taken away without anybody
noticing: the import succeeds, the coverage report quietly drops a framework,
and nothing says why. Since `issued_at` is inside the signature, comparing it
against the installed manifest is enough. `--allow-rollback` when that is the
intent.

## Decision 6 — Unsigned is allowed, and loud

Refusing outright is the obvious choice and the wrong one. The catalogues are
plain YAML in a directory; an operator blocked by a strict import will put the
files there by hand, and then *nothing* records it. Pushing people outside the
tool to do the risky thing is worse than letting them do it inside the tool
where it leaves a trace.

So `--unsigned` works, and costs: the command prints `UNSIGNED`, the
`admin_action` records `unsigned: true`, and — the part that matters —
`policy_loaded` carries `unsigned: true` with the frameworks named, from then
on. Provenance is read from the manifest the import wrote, never from the
catalogue files: a catalogue cannot be allowed to describe its own provenance,
and YAML dropped in by hand with no manifest beside it counts as unsigned for
the same reason.

## Decision 7 — An import re-issues `policy_loaded`

The honest consequence of Decision 6, and it is not obvious.

**Importing a catalogue does not change the policy hash.** `policy_loaded` is
appended once per hash, so the first implementation of the `unsigned` flag read
correctly and was never re-read: an unsigned import landed, and every
`policy_loaded` after it still said `unsigned: false`. The reading side was
right and the record never moved.

`policy_loaded` is the record every verdict points at. An auditor holding one
verdict has to be able to see that the control labels behind it had nobody
vouching for them, without going looking for an `admin_action` that may be a
year earlier in the chain.

So an import clears the de-duplication marks in `policy_bundles`, and the next
session appends a fresh `policy_loaded` — same `policy_hash`, new catalogue
state. Two records for one policy hash is the honest outcome: the bundle was
loaded twice and meant something different the second time. Nothing in the
chain is rewritten; the earlier record still says what was true when it was
written.

## Decision 8 — `verify` is a separate command

`qed packs verify` shows a bundle's issuer, date, hash, key and catalogues, and
installs nothing.

Whether to trust a catalogue is a decision somebody should be able to make with
the contents in front of them. A command that showed you the contents by
installing them would not be offering a choice. Without `--public-key` it says
plainly that it has not verified anything, rather than reporting the `key_id`
the bundle claims as though that were a result.

## Consequences

- SPEC §11's `file.sig` is not the file name; §11 and §14 are updated, and
  `packs verify` is a third subcommand there.
- The `remote.packs` **feed** is not built. The air-gap import reaches no
  network, so there is no `remote.packs.public_key` config key yet either — the
  key is an argument. `remote` stays in `UNIMPLEMENTED_SECTIONS` because no key
  under it is read, which is the accurate thing for `qed doctor` to report.
- A publisher cannot take a control away from an instance by omission, and
  cannot switch the kernel off at all.
- Deepening ISO 42001 and DORA (SPEC §22 week 9) can now be delivered as signed
  bundles rather than only as package changes — though the catalogues that ship
  with the package stay the default, because those were reviewed in a repository
  an auditor can read.
