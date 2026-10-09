# ADR-0005 — Record encoding details the spec leaves open

**Status:** accepted · week 1
**Fills:** SPEC §10.2, §10.5.

Five small decisions. Each one is in the hashed bytes, so each one is frozen
once the evidence format is frozen at week 12.

## 1. Reserved payload keys are underscore-prefixed, and collisions are refused

SPEC §10.2 requires `assurance`, `mode`, `enforcement`, `dev` and `key_id` to be
inside the payload (so `payload_hash` covers them) **and** mirrored as columns.
It does not say how they are named inside the payload.

Decision: `_assurance`, `_mode`, `_enforcement`, `_dev`, `_key_id` at the top
level of the payload. A caller payload already containing one of those keys
raises, rather than being silently overwritten — silently overwriting would let
a caller's data decide what the record claims about its own assurance level.

A nested `_meta` object was the alternative. Flat keys keep JCS output shallower
and keep the SQL mirror columns a one-to-one map.

## 2. Signatures are base64url without padding

`sig = base64url_nopad(Ed25519_sign(H))`, over the **32 raw bytes** of the
record hash, not over its hex form and not over the canonical payload.

SPEC §10.2 says "base64url" without stating padding. Unpadded, because the `=`
characters carry no information and padded/unpadded is the kind of difference
that only surfaces when a third-party verifier is written against the format.
`qed-verify` re-pads on read, so either form is accepted on input and only one
is produced.

## 3. `key_id` is derived from the public key

`key_id = "ed25519:" + sha256(raw_public_key)[:16]` (hex).

Consequences: the same key always has the same id, so two copies of a key cannot
be labelled differently; an operator cannot name one key as another; and
`qed-verify` recomputes the id from the key material rather than trusting a
filename, so a renamed PEM cannot make a record appear to verify under the wrong
key.

16 hex characters is 64 bits of the digest — ample for naming within one
instance's key set, and short enough to read aloud.

Public keys are written to `<dir>/public/<key_id with ':' replaced by '_'>.pem`,
because `:` is not a legal filename character on Windows.

## 4. Timestamps serialise identically in both dump modes

`Timestamp` is a Pydantic annotated type with `when_used="always"`, so
`model_dump()` and `model_dump(mode="json")` both produce
`YYYY-MM-DDTHH:MM:SS.sssZ`. Values are required to be timezone-aware,
normalised to UTC, and truncated to milliseconds on the way in.

Without this, a record's bytes would depend on which dump mode the caller
happened to use, and the bug would appear only when a second code path (the API
layer, week 2) wrote records.

## 5. Floats are canonicalised, not rejected

Payloads in practice carry integers and strings — money is cents, tokens are
counts. Rejecting floats outright was tempting and would have removed a class of
cross-implementation mismatch, but rule predicates may legitimately compare
against a fractional threshold, and those values are hashed as part of the
bundle. So JCS implements the full ECMAScript `Number::toString` conversion in
both the producer and the verifier, and
`tests/core/test_jcs_agreement.py` fails the build if the two ever disagree.

Integers outside ±(2⁵³−1) **are** rejected: a number that cannot round-trip
through a double has no business in a hash, and silently rounding it would be
the worst available option.
