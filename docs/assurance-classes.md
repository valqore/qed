# Assurance classes — what a record actually proves

For auditors. Every evidence record carries an `assurance` field (ADR-007.1).
It answers one question: **who is vouching for this statement, and could they
have lied?**

An evidence chain that does not distinguish these is overselling itself. A
decision the kernel made and a result an agent reported about itself are not the
same kind of fact, even though both are signed by the same key and sit in the
same chain.

| Class | Written by | What it proves | How it could be wrong |
|---|---|---|---|
| `kernel` | gate itself | The decision was made as recorded, against the recorded policy, for the recorded principal. Replayable from the record alone. | Only if gate's own code or signing key is compromised. |
| `broker` | gate's credential broker | The action was executed through gate, with a credential the agent never held. The agent could not have made this call any other way. | Only if the upstream credential leaked outside the broker. |
| `adapter` | an adapter inside the agent's process | A call was attempted and this was its result. The adapter is in the agent's trust boundary. | A compromised or bypassed adapter can misreport or stay silent. |
| `self` | the agent | The agent's own claim about what it did. | Freely. This is testimony, not evidence. |

## What follows from that

- A `kernel` verdict plus a `broker` execution record is a closed loop: the
  decision and the act are both independently attested, and the agent had no
  path around either.
- A `kernel` verdict plus an `adapter` result tells you the decision was sound
  and the agent *reported* compliance. If the adapter was bypassed, the chain
  shows no record at all — which is why the absence of records matters and why
  `ungated_window` records exist.
- `self` records are useful context and nothing more. Do not build a control
  assertion on them.

## Gaps are recorded, not hidden

When an adapter cannot reach the kernel it fails according to its configured
policy (ADR-003) and writes locally. Those gaps re-enter the chain as
`ungated_window` records with a start, an end, and a call count. A period with
no governance shows up as a record saying so, rather than as silence that looks
like a quiet day.

## Shadow mode

Records carry `mode: shadow` when the decision was evaluated but not enforced.
A shadow record proves the decision *would* have been made. It does not prove
the action was prevented. Both are in the same chain, distinguished by one
field, so "we have been observing since this date" is demonstrable.

## Week 2 status

Three of the four classes are written today.

| Class | Written by | Since |
|---|---|---|
| `kernel` | every proposal, verdict, policy load and checkpoint | week 1 |
| `adapter` | an execution result from an **enforcing** adapter — the MCP proxy, and `POST /v1/proposals/{id}/result` | week 2 |
| `self` | an execution result from an **advisory** adapter | week 2 |
| `broker` | — | week 5, with the credential broker |

The rule for an execution result is the proposal's own `enforcement` field
(SPEC §13, "assurance from adapter enforcement"):

- `enforcement: enforcing` → `assurance: adapter`. The adapter could not have
  been bypassed without leaving a gap in the chain, so its report is evidence
  about the adapter.
- `enforcement: advisory` → `assurance: self`. An advisory adapter — a
  coding-agent hook the user can switch off — is one the agent could have gone
  around, so its report is the agent's own claim.

The same MCP proxy therefore produces `self` results under
`--enforcement advisory` and `adapter` results when enforcing. The difference is
not cosmetic: a control assertion may rest on the second and not on the first.

`broker` is still unwritten because the broker does not exist yet. The field,
the enum and the verifier support all four, so the evidence format does not
change when it arrives.
