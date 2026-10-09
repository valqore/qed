# Approvals

SPEC §9, ADR-006. A `REQUIRE_APPROVAL` verdict is not an answer — it is a
question put to a person. This is what happens between the question and the
answer, and what the answer is allowed to mean.

Two sentences have to stay true:

- **nobody approved their own action**, and
- **an approval covers exactly what was approved, for exactly as long as was
  agreed.**

Everything below exists to make one of them checkable later.

## The flow

```
REQUIRE_APPROVAL
      |
      +-- an open window for this exact action?   -> ALLOW, via_approval set
      +-- a denial in the last 10 minutes?        -> BLOCK
      +-- a pending request for this action?      -> link to it
      +-- otherwise                               -> open a request
```

All four are decided before the verdict is written, so the chain records the
decision that was acted on rather than one a later record quietly revises.

## Separation of duties

Checked at decision time, in this order:

| Condition | Rule |
|---|---|
| The approver is not the principal the action is for | `AG-SOD-001` |
| The approver is a person, not a `svc:` identity | `AG-SOD-002` |
| The approver is in the group the rule named | `AG-SOD-002` |

A refused attempt is **written to the chain**, not merely rejected. Somebody
trying to approve their own production delete is exactly what an auditor
wants to find later, and a refusal that leaves no trace is indistinguishable
from an attempt that never happened.

> This is the control most often *reported* in a compliance export while
> nothing enforces it. Reporting a control that does not exist is worse than
> not having it, because the evidence says somebody checked.

## Deduplication

The key is `sha256(principal | action.name | action.target | params_hash)`.

**Included** — the parameters, because an approval for
`DROP TABLE orders_archive` must not cover `DROP TABLE orders`, and nothing
else distinguishes them.

**Excluded** — the environment and the time, because two identical actions a
minute apart are one question as far as a human is concerned. An approver
should see one request, not forty.

A retrying agent therefore joins the request somebody is already looking at.
After ten minutes the situation is no longer the same one and a fresh request
is opened.

## Decisions

```bash
qed approvals                      # the queue
qed approvals --expire             # run the timeout sweep first
qed approve apr_... --by you@example.com --groups sre-oncall
qed approve apr_... --by you@example.com --groups sre-oncall --window 15m
qed approve apr_... --by you@example.com --groups sre-oncall --deny --reason "..."
```

### `approve_once` versus `--window`

`approve_once` means once. The next identical action is a new question and
the queue asks it again.

`--window 15m` grants every identical action for that period. The window is
keyed on the dedupe key, so it covers *that action*, not that person and not
that rule. **Windows are not extendable** — when one runs out the next action
opens a fresh request, which is the only way the record stays a sentence
somebody can check.

The granted length is the smallest of what was asked for, what the rule
allows (`approval.window_max`), and the service ceiling of 60 minutes. An
approver cannot widen a rule's own bound by asking, which is the entire
reason the rule carries one.

### After a denial

The same action is **blocked** for the next ten minutes rather than asked
again. Without that, an agent told no simply re-asks and the second request
looks exactly like the first to whoever sees it.

## Timeouts

A request expires at the shortest `approval.timeout` among the rules that
fired, defaulting to fifteen minutes. `qed approvals --expire` runs the
sweep and writes one `approval_expired` record per request — a request that
simply vanished from the queue would not be evidence of anything.

The rule's timeout, approver list and window ceiling are copied onto the
request when it is created, not looked up when it is decided. The bundle can
be reloaded in between, and an approver should be bounded by the rule that
was in force when the action was proposed.

Where two rules disagree, the tighter one wins: the shortest timeout, the
smallest window.

## What an approver sees

Stored with the request and shown by the channel: the summary and the agent's
stated intent, the environment, the agent chain, the rules that fired with
their messages, the blast-radius score, when it expires, and the
**already-redacted** parameters the engine itself saw. Never the raw call —
an approval queue should not become a place secrets accumulate.

## In the chain

```
approval_requested     a question was asked, of whom, expiring when
approval_decided       who answered, what they said, and any window
approval_decided       (also written for a refused attempt, with the SoD rule)
approval_expired       nobody answered in time
```

## Channels

A channel does two things and nothing else: it renders a request so somebody
can judge it, and it turns a click back into an **identified person**. The
decision is always `qed.core.approval.model.decide` — a channel that decided
for itself would be a channel where separation of duties worked differently,
and that is the one place a second implementation must not exist.

### HTTP

```
GET  /v1/approvals?status=pending
GET  /v1/approvals/{id}           # includes the approver view stored at request time
POST /v1/approvals/{id}           # {"decision": "approve_once|approve_window|deny", ...}
```

The approver travels in `X-QED-Approver` and `X-QED-Approver-Groups`, **not
in the body**. An endpoint that let the request name its own approver would
make the whole control decorative.

### Slack

```yaml
approvals:
  slack:
    bot_token_env: QED_SLACK_BOT_TOKEN
    signing_secret_env: QED_SLACK_SIGNING_SECRET
    channel: "#approvals"
  groups_by_email:
    priya@example.com: [sre-oncall]
```

Point Slack interactivity at `POST /slack/interactivity`. It sits outside
`/v1` because Slack cannot sign our adapter envelope; it authenticates with
Slack's own `X-Slack-Signature` over the exact bytes received.

**A Slack user id is not an identity.** It says somebody with access to a
workspace pressed a button. It is resolved to an email through `users.info`
and *that* becomes the principal hash in the chain. If the lookup fails the
decision is refused rather than recorded against an unknown person.

The timestamp is checked before the MAC: a signature stays valid forever, so
the five-minute window is the only thing that makes a captured request stop
working.

### Webhook

```yaml
approvals:
  webhook_url: https://hooks.example/qed
```

One-way, for Teams or PagerDuty. It announces; it does not accept decisions,
because a channel that decides needs an identity story and "whoever can POST
to this URL" is not one. Delivery failures are logged and ignored — a
notification channel that is down must not hold up a verdict.

### Live feed

```
GET /v1/events          # text/event-stream, resumable with Last-Event-ID
```

Streams the evidence chain itself rather than a second event bus: a feed
assembled from somewhere else could disagree with the evidence. It polls the
store rather than being pushed to, so a slow reader never ends up on the hot
path of a verdict. Proposal bodies and redacted parameters are dropped — a
live feed reaches more screens than the queue does.

## Not built yet

The web approval page (`/ui/approvals`). Every API it needs exists.
