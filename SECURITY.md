# Security

QED decides whether an AI agent may perform an action, and writes evidence a
third party can verify. Two things follow, and they set the bar for what counts
as a critical bug here:

- **A bug that lets a decision be bypassed is critical.**
- **A bug that lets a record be forged, altered or removed without detection is
  critical, even if no decision was ever wrong.** The chain's value is that
  nobody — including whoever runs the instance — can change it quietly.

## Reporting a vulnerability

> **This repository is not public yet.** The licence is applied (Apache-2.0) and
> the remote stays private until the name reservations in SPEC §24.1 are done.
> Until then, report directly to the maintainer. The process below is what takes
> effect on publication.

**Do not open a public issue for a security bug.** Use either:

1. **GitHub private vulnerability reporting** — the "Report a vulnerability"
   button under this repository's Security tab. Preferred: it keeps the report,
   the fix and the advisory in one place.
2. **Email `tunc@valqore.io`** with `[qed security]` in the subject. Encrypt if
   you prefer; ask for a key in a first message that contains no details.

Please include, as far as you have it: the version or commit, what you did,
what happened, and what you expected. A proof of concept helps and is not
required — a clear description of the mechanism is worth more than a working
exploit.

### What to expect

| When | What |
|---|---|
| Within 3 working days | Acknowledgement that a human has read it |
| Within 10 working days | An assessment: whether it is a vulnerability, the severity, and a target date |
| Before any public note | A draft advisory shared with you, with the credit you asked for |
| 90 days | Default maximum before public disclosure, whether or not a fix is ready |

This is a two-person project, so those are commitments about responsiveness
rather than about speed of fixing. If a date is going to slip, you will be told
before it slips rather than after.

**Credit** is given by default, under whatever name or handle you give, and
withheld if you prefer. A report that turns out not to be a vulnerability still
gets an explanation of why.

There is no paid bug bounty.

### Safe harbour

If you make a good-faith effort to follow this policy, we will not pursue or
support legal action against you for your research, and we will say so publicly
if anyone else does. Good faith means: only your own instances or ones you have
written permission to test; no accessing, modifying or exfiltrating data that
is not yours; no denial of service; no social engineering, physical attacks or
spam; and giving us the time above before going public.

This promise is ours to make and does not bind any third party whose systems
you happen to reach.

### In scope

Everything in this repository and in `packages/qed-verify`, including the
Dockerfile, the Helm chart and the policy pack. Specifically wanted:

- A path that gets an action past the kernel without a verdict in the chain.
- Any way to make `qed-verify` accept a chain that was altered, truncated,
  reordered, or signed by a key other than the one it reports.
- Any way to make a decision depend on something other than the proposal, the
  bundle, the budget and the derived context — including rule file order,
  locale, or wall-clock skew.
- Secret or personal data reaching the chain, the logs, or an error message.
- Privilege escalation through the approval system, especially anything that
  defeats separation of duties.

### Out of scope

- The absence of a feature the documentation already says is absent. The
  threat model (`THREAT_MODEL.md`) has eleven numbered limitations and they are
  there to be read, not reported.
- Advisory adapters not stopping an action. That is what "advisory" means, it
  is recorded in every affected record, and
  `docs/assurance-classes.md` explains it.
- Anything requiring the operator's own private key or root on the host. QED
  does not defend against its own operator; see limitation 1.
- Findings from a scanner with no demonstrated impact.
- Denial of service by sending a lot of requests. Rate limits exist; a bypass
  of them is in scope, the existence of load is not.

## Invariants, and the tests that hold them

These are build failures, not review comments. Each is something an auditor is
entitled to assume.

| Invariant | Enforced by |
|---|---|
| No LLM in the decision path | `tests/core/test_no_llm.py` |
| No network client in `qed.core` | `tests/core/test_no_network.py` |
| Ed25519 only; no HMAC path exists | `tests/evidence/test_no_hmac.py` |
| No development fallback signing key | `tests/evidence/test_no_hmac.py` |
| Tamper, deletion and reordering are all detected | `tests/evidence/test_chain.py` |
| Records verify after retention purges the payload | `tests/evidence/test_chain.py` |
| A rotation record is signed by the retiring key | `tests/evidence/test_chain.py` |
| Rotation destroys the old private key | `tests/evidence/test_key_rotation.py` |
| Decisions are byte-identical for identical inputs | `tests/policy/test_engine.py` |
| Decisions do not depend on rule order | `tests/policy/test_golden.py` |
| The verifier agrees with the producer on canonical JSON | `tests/core/test_jcs_agreement.py` |
| A mandate's signature is verified before it authorises anything | `tests/delegation/test_mandate_is_verified_at_runtime.py` |
| Every `/v1` route refuses an unsigned request | `tests/api/test_auth.py` |
| An import cannot stop the kernel deciding | `tests/compliance/test_pack_bundles.py` |
| SQLite and PostgreSQL produce byte-identical chains | `tests/evidence/test_cross_backend.py` |

`tests/docs/test_claims.py` checks that every path named above exists, because
a table of guarantees pointing at a file that was renamed is worse than no
table. It caught one on its first run.

## Keys

- `qed keys init` writes the private key 0600 where the platform honours it. On
  Windows the POSIX bits are advisory, and `qed doctor` reports posture rather
  than implying a guarantee.
- There is no built-in key, no key generated on first run, and no fallback. A
  missing key is a hard failure.
- `key_id` is derived from the public key, so a key cannot be mislabelled.
- Rotation signs the `key_rotated` record with the **old** key, keeping the
  chain continuous, and then destroys the old private key
  (ADR-0010 (`docs/adr/`)).
- `qed keys rotate` can require an approval from somebody else
  (ADR-0014 (`docs/adr/`)). It is off
  by default and `qed doctor` says so in yellow.

## Deliberately not secrets

- **The policy bundle.** It should be readable, reviewable and in version
  control.
- **The chain's structure, hashes and signatures.** Publish them.
- **Public keys.** Give them to auditors; that is the point.

## Never in the chain

- Raw action parameters. Only `params_redacted`, masked again on write.
- Upstream credentials. Only the `upstream_id` that was used.
- Personal data in the clear. Principals are salted hashes, and the mapping
  lives in an erasable table outside the chain (ADR-005).
- The Postgres DSN, which carries a password. It is never echoed in an error
  message or in `qed doctor`.

## Current limitations

The authoritative list is **`THREAT_MODEL.md`**, which has
eleven numbered limitations and a STRIDE table. The shortest summary of the
ones people most often assume away:

- **QED does not defend against its own operator.** Whoever holds the signing
  key can write any record they like. That is what external anchoring is for,
  and `qed doctor` tells you when no anchor is configured — until one is, a
  checkpoint's Merkle root attests to nothing the operator could not recompute.
- **An advisory adapter cannot stop anything.** Three separate dials have to
  point at "enforce" before a `BLOCK` prevents a call; see
  the onboarding guide (`docs/onboarding-shadow-to-enforce.md`).
- **Masking is pattern-based.** It catches the documented set
  (`tests/masking/`). It is a safety net, not a guarantee, and adapters should
  not put secrets in parameters in the first place.
- **`qed.remote.*` is opt-in and outbound-only**, carries hashes and signatures
  but never customer data, and degrades when switched off. Zero bytes leave by
  default.
