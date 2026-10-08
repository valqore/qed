# Governance

## The open-core boundary — five tests (SPEC §25.2)

A component is **open and local** if any of these hold:

1. it is in the decision path;
2. it carries customer data;
3. auditors must be able to verify it independently.

It **may** be a remote or optional API if:

4. its value grows with time or with the network — freshness, external
   witnessing, shared intelligence.

It is **closed and commercial** if:

5. it only makes sense at scale — multi-tenant, multi-auditor, multi-year.

### Red lines

- The kernel alone, offline, produces evidence an auditor will accept. If that
  ever stops being true, the product is broken, not the pricing.
- No commercial feature ever removes or caps an open capability. There is no
  "30-day chain in the free tier".
- Everything under `gate.remote.*` is opt-in, outbound-only, carries hashes and
  signatures but never customer data, and degrades gracefully when switched off.
  Zero bytes leave by default.

## Repository split

| Repo | Contents |
|---|---|
| `gate` (this one) | kernel, adapters, policy language, baseline pack, `gate-verify`, docs, Helm, examples |
| `gate-ui` | live UI, approval pages, SSE client |
| `gate-cloud` | multi-tenant evidence vault, auditor portal, transparency log, signed pack feed, SSO/RBAC, long retention |

No proprietary code ever enters this repository. Git history is irreversible, so
this is a rule about the first commit, not about the current state.

Valqore-ported modules arrive as a single commit labelled
`imported from valqore-engine <sha>`, without private history.

## Licensing

**Currently unresolved and deliberately so.** See `PATENT-AND-LICENCE-GATE.md`.
The intended licence for this repository is Apache-2.0, but the Apache patent
grant is irrevocable on distribution and SPEC §24.2 (Valqore patent scope) is
open. Nothing is published until that closes.

## Relationship to Valqore

One-directional. `gate` has **zero** imports from Valqore. Valqore becomes a
consumer in v1.x (`gate.propose(kind="iac")`) and deletes its own
`approvals.py` and `mcp/gateway.py` at that point.

gate does not do IaC or Kubernetes manifest scanning. That stays in Valqore,
permanently (SPEC §1.3).

## Changing the evidence format

The evidence format is the product's only real promise: a record written today
must verify in seven years. Therefore:

- any change to hashing, to record fields, or to the masking pattern set is a
  `schema_version` bump with an ADR;
- `gate-verify` must keep verifying every prior version, with cross-version
  fixtures in CI;
- `docs/evidence-format.md` is the specification, and it is published.

## Decisions

Anything the spec does not settle gets an ADR in `docs/adr/`, numbered, with
context, the decision, consequences and the alternatives that were rejected.
"The spec was silent so I picked one" is fine; "the spec was silent so nobody
knows why it works this way" is not.
