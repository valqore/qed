# Security

**This repository is not published yet** (see `PATENT-AND-LICENCE-GATE.md`), so
there is no public disclosure process to follow. The full process lands with the
public launch (SPEC §22 week 11). Until then, report anything you find directly
to the maintainer.

## What this software is for

gate decides whether an AI agent may perform an action, and writes evidence that
a third party can verify. Two things follow:

- A bug that lets a decision be bypassed is a critical bug.
- A bug that lets a record be forged, altered or removed without detection is a
  critical bug, even if no decision was ever wrong.

## Invariants, and the tests that hold them

| Invariant | Enforced by |
|---|---|
| No LLM in the decision path | `tests/core/test_no_llm.py` |
| No network client in `gate.core` | `tests/core/test_no_network.py` |
| Ed25519 only; no HMAC path exists | `tests/evidence/test_no_hmac.py` |
| No development fallback signing key | `tests/evidence/test_no_hmac.py` |
| Tamper, deletion and reordering are all detected | `tests/evidence/test_chain.py` |
| Records verify after retention purges the payload | `tests/evidence/test_chain.py` |
| A rotation record is signed by the retiring key | `tests/evidence/test_chain.py` |
| Decisions are byte-identical for identical inputs | `tests/policy/test_engine.py` |
| Decisions do not depend on rule order | `tests/policy/test_golden.py` |
| The verifier agrees with the producer on canonical JSON | `tests/core/test_jcs_agreement.py` |

These are not style rules. Each one is something an auditor is entitled to
assume, so each one is a build failure rather than a review comment.

## Keys

- `gate keys init` writes the private key with 0600 where the platform honours
  it. On Windows the POSIX bits are advisory; `gate doctor` will report posture
  rather than imply a guarantee (week 5).
- There is no built-in key, no key generated on first run, and no fallback. A
  missing key is a hard failure.
- `key_id` is derived from the public key, so a key cannot be mislabelled.
- Key rotation keeps the chain continuous by signing the `key_rotated` record
  with the **old** key. Rotation tooling is week 7; the format and the verifier
  check exist now.

## Things that are deliberately not secrets

- The policy bundle. It should be readable, reviewable and in version control.
- The evidence chain's structure, hashes and signatures. Publish them.
- Public keys. Give them to auditors; that is the point.

## Things that never enter the chain

- Raw action parameters. Only `params_redacted`, masked again on write.
- Upstream credentials. Only the `upstream_id` that was used.
- Personal data in the clear. Principals are salted hashes; the mapping lives in
  an erasable table outside the chain (ADR-005).

## Known limits in week 1

Stated plainly because an incomplete system described as complete is itself a
security problem:

- **No authentication anywhere.** There is no HTTP API yet. `gate check` trusts
  whoever can run it.
- **No delegation verification.** `principal.token_jti` is taken as given. JWT
  and JWKS verification, actor-chain narrowing and scope checks are week 3.
- **No approval service.** `REQUIRE_APPROVAL` is a verdict, not yet a workflow.
  Nothing can be approved yet. Week 4.
- **No credential broker.** Every adapter would be advisory. Week 5.
- **Mandate signatures are not verified.** A mandate's time window, revocation
  and `allowed` envelope are checked; its `signature` block is not. Week 3.
- **Single process only.** The Postgres leader/outbox path is week 6.
- **Masking is pattern-based.** It catches the documented set
  (`tests/masking/`). It is a safety net, not a guarantee; adapters should not
  put secrets in parameters in the first place.
