# ADR-0015 — Evidence format 1.0 is frozen against a committed fixture, not a promise

**Status:** accepted · week 12 (2026-10-10)
**Implements:** SPEC §22 week 12 (freeze evidence format 1.0, publish it as a spec), SPEC §25.6 (versioning and compatibility promises)
**Relates to:** ADR-0005 (record encoding), ADR-0006 (format constants carry no product name), ADR-0010 (rotation destroys the old private key)

## Context

The product's central claim is that an auditor can verify evidence years later
without trusting the vendor or the customer. That claim has a precondition
nobody checks on day one: the records written today must still be readable by
whatever the verifier becomes.

SPEC §25.6 already said how that would be kept — "any change to hashing or
record fields bumps `schema_version` with an ADR and keeps `qed-verify` able to
verify all prior versions (**cross-version fixtures in CI**)". Through week 11
there were no cross-version fixtures. The suite had something that looked like
one: `tests/evidence/test_chain.py` writes a chain with today's producer and
verifies it with today's verifier, end to end, through the real store and the
real signer. It is a good test and it cannot see the failure that matters,
because a producer and a verifier that change together pass it, while the
records already sitting in a customer's database do not change with them.

That is the same shape as the three findings in `docs/validation.md` that a
green suite shipped anyway: a test that imports the source tree is not a test of
the thing you ship, and a test that regenerates its own input is not a test of
compatibility.

## Decision 1 — The freeze is a committed artefact, produced once

`tests/evidence/fixtures/evidence-format-1.0/` holds a real export, produced by
the kernel on 10 October 2026: fourteen records over five simulated days, with
genesis, `policy_loaded`, three real proposals from `examples/proposals/`
deciding ALLOW / REQUIRE_APPROVAL / BLOCK, an approval decided by a different
human through the real separation-of-duties check, a signing-key rotation, two
Merkle checkpoints, a retention purge that recorded itself, and one proposal
whose payload is gone. Both public keys are committed. No private key is, so the
chain cannot be extended — which is the correct state for a published reference.

`tests/evidence/test_frozen_format.py` checks four things against those bytes,
each catching something the one before it cannot:

1. `qed-verify` verifies the export — the auditor's whole position, in a line.
2. `record_hash`, the **producer's** function as it is today, recomputes the
   hash of every frozen record. (1) proves the verifier can still read 1.0;
   this proves the producer still writes it.
3. `qed.core.jcs` and `qed_verify.jcs` — two deliberately separate
   canonicalisers — agree on every frozen payload.
4. Twelve mutations of the frozen bytes each produce the documented failure
   code, which makes the fixture's README a tested document.

## Decision 2 — The fixture's digest is pinned in the test, not in the fixture

A regeneration would quietly turn every check above into "today's code agrees
with today's code". So `DIGESTS` in the test file holds a sha256 over the
fixture's records, keys and manifest, and a regeneration fails there.

The digest lives in the test and not in the fixture on purpose: a checksum that
the regeneration rewrites alongside the thing it describes verifies nothing.
Refreshing the fixture is therefore a deliberate edit in two files, with a test
whose failure message says why it is almost certainly wrong.

Markdown inside the fixture directory is excluded from the digest. The pin
exists to stop the *records* being refreshed, and a guard that also fires on
every improvement to the prose beside them is a guard people learn to update
without reading.

The generator is committed (`fixtures/generate_1_0.py`) so the records are
explicable rather than taken on trust, and it refuses to run without
`--i-mean-it`.

## Decision 3 — A `schema_version` bump fails CI until it has a fixture

This is the part that makes the freeze a rule rather than a habit.
`schema_version` is a `Literal["1.0"]` in three places in
`qed/core/schemas.py`. Changing it is one edit, and nothing in the repository
would have noticed. Now
`test_every_schema_version_the_code_can_write_has_a_fixture` reads those
literals and asserts each has a fixture directory, so "1.1" is red until 1.1 has
records of its own — and 1.0 goes on being verified beside it, because the test
is parametrised over every directory it finds.

## Decision 4 — Freeze the reading of a record, not its contents

Freezing too much makes a format unimprovable, so the boundary is written into
`docs/evidence-format.md` as two tables.

Inside: the six hash inputs and their order, the `0x1F` separator, the two
domain prefixes, the field names, base64url-without-padding, lowercase hex,
RFC 3339 with three fractional digits, RFC 8785 with integers limited to
±(2⁵³−1), the reserved `_`-prefixed keys, the Merkle construction, and the rule
that `key_rotated` is signed by the old key.

Outside: payload *contents* (a verifier checks the digest, not the fields), the
baseline rule pack, `policy_hash`, `engine_version`, the CSV and OSCAL
renderings — and the masking pattern set.

Masking is the one that changed meaning here, and the previous version of
`docs/evidence-format.md` had it the other way round: it said "the pattern set
is part of the format: changing it changes record hashes for future records".
Both halves are true and the conclusion was wrong. Masking runs before hashing,
so a new pattern changes what future records *contain*; it cannot change a
record already written, and a verifier never re-derives a mask — it hashes the
payload as it finds it. So the pattern set is producer-side policy, and
improving it is not a format change. Getting that wrong in the other direction
would have frozen the secret-detection patterns for the life of the product.

## Decision 5 — Freeze now, before the auditor's written acceptance

Week 9's exit criterion — written auditor acceptance — is not in hand, and
freezing a format an auditor has not signed off on is a real risk taken
knowingly.

Two reasons it is the right way round. An auditor's objections land on what the
evidence *says* — control mappings, which fields a `verdict` carries, how an
OSCAL observation is shaped — and all of that is outside the freeze and
additive. The hash construction, the signature and the chain linkage are
cryptographic mechanics no auditor asks to change. And the alternative is worse:
design partners are being asked to run this in enforce mode now, so the records
accumulating in their chains are already permanent whether or not a document
calls the format frozen. Freezing is the honest description of a commitment
already made in fact.

If an auditor does require a change to the hashed surface, the answer is 1.1
with an ADR and a second fixture — exactly the mechanism Decision 3 installs —
and 1.0 keeps verifying. That is the version of "we were wrong" this format is
built to survive.

## Consequences

- A format change can no longer be made accidentally, only deliberately and
  visibly, in at least three files.
- `docs/evidence-format.md` is normative and carries a conformance section: ten
  MUSTs, three MUST NOTs, and an acceptance test an independent implementer can
  run against committed bytes. The one most often got wrong is called out —
  an unsupplied `key_id` is a **failure**, not a skip, or a verifier reports a
  forged chain as clean.
- The conformance kit is in `tests/`, so it is in the repository and not in the
  wheel. A third party writing a verifier clones the repo; a kit shipped inside
  the package the kit is meant to be independent of would be the wrong place
  for it.
- Nine of eighteen record types appear in the fixture. The others are
  hash-identical in structure — `type` is one string in the hash input — and the
  fixture's README says which are covered rather than implying all are.
