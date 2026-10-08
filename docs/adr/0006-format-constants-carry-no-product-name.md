# ADR-0006 — Hash domain separators carry no product name

**Status:** accepted · before the first remote
**Deviates from:** SPEC §10.3 (`genesis.prev_hash = hex(SHA256("gate-genesis:" + instance_id))`), SPEC §10.6 (principal hashing).
**Relates to:** SPEC §24.1 (product name undecided), §25.5 (publication).

## Context

SPEC §24.1 records that `gate` is a placeholder and that the final name is still
open. The review of week 1 repeated the spec's own claim that a rename is "a
single refactor". That claim was not checked. It is false, and the reason is
three strings:

| Where | Value |
|---|---|
| `gate/core/evidence/hashing.py` | `"gate-genesis:" + instance_id`, hashed into the genesis `prev_hash` |
| `gate/core/evidence/hashing.py` | `"gate-principal:"`, hashed into every `principal_hash` |
| `chain_writer.py`, `export/oscal.py` | `"gate-evidence/1.0"`, written into the signed genesis payload |

All three are hash inputs, and the first two are duplicated in `gate-verify`,
which reimplements the format on purpose (SPEC §10.7).

So the product name sat inside the evidence format. Renaming the product would
have meant one of three bad outcomes:

1. **Change the strings.** Chains written before the rename then fail genesis
   verification, and the same human hashes to two different `principal_hash`
   values either side of the rename — so an auditor can no longer tell that the
   same person approved two actions.
2. **Keep the strings.** The shipped format permanently carries a name the
   product no longer uses, in the one file an auditor is most likely to read.
3. **Carry both.** The verifier grows a compatibility table of former product
   names, forever.

Today the cost is zero: no chain exists outside the test suite. The cost becomes
outcome 1, 2 or 3 the first time a design partner runs the kernel — which SPEC
§22 schedules for week 8, long before §24.1 has to be answered.

## Decision

The format constants move to `gate/core/evidence/format.py` and are scoped to
the format and its version, not to the brand:

```
CHAIN_FORMAT     = "evidence-chain/1"
GENESIS_DOMAIN   = "evidence-chain/1:genesis:"
PRINCIPAL_DOMAIN = "evidence-chain/1:principal:"
```

`chain_format` in the genesis payload and `chain-format` in the OSCAL export
both become `CHAIN_FORMAT`. `gate-verify` keeps its own copy of the two strings
it needs — sharing them with the producer would mean a bug in the producer
verifies cleanly — and `tests/evidence/test_format_constants.py` checks the two
copies agree.

The brand stays where it is not hashed: the OSCAL `generator` prop, the CLI name,
the distribution name, the `PROP_NS` URI.

Domain separation only has to be unique among this system's own uses of SHA-256,
which `":genesis:"` and `":principal:"` satisfy. Global uniqueness of the genesis
hash comes from `instance_id`, as before.

## Consequences

- Choosing the final product name is now a packaging change: distribution name,
  CLI name, repo name, docs. It does not touch a single hash input.
- The `/1` is the version to bump for a real breaking change to the record
  construction. A rename is not one.
- `tests/evidence/test_format_constants.py` pins the exact strings and three
  recorded digests, computed outside the package. A test that recomputed them
  from the constants would pass after a rename and still break every existing
  chain, which is the failure this ADR exists to prevent.
- That file also asserts no candidate product name appears in any hash input, so
  the property is enforced rather than remembered.
- `SPEC §10.3`'s literal `"gate-genesis:"` and `DESIGN_DECISIONS.md` §161 are
  superseded by this ADR. Both are kept unedited as the original record.
- Nothing predates this change: the only chains in existence are built by the
  test suite on each run.
