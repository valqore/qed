# SIEM events (OCSF)

`qed` ships OCSF-shaped JSON so a decision lands in the same dashboard as one
from an identity provider or a cloud audit log.

```yaml
observability:
  siem:
    format: ocsf
    webhook_env: QED_SIEM_WEBHOOK   # a URL with a token in it
    stdout: false                   # one JSON object per line
```

```bash
export QED_SIEM_WEBHOOK='https://splunk.internal:8088/services/collector?token=…'
qed serve
```

`webhook_env` rather than `webhook`, for the same reason the database DSN is
named rather than inlined: a Splunk HEC or Slack webhook URL carries its token
in the path or query, and `qed.yaml` is a file somebody commits. `webhook`
accepts a literal for a URL that genuinely has no secret in it.

## It is a copy, not the record

This matters more than anything else on the page. The **chain** is the
authority; `qed-verify` checks it. A SIEM event is derived, unsigned, and
designed to be dropped when a webhook is down. Nothing here is on the decision
path, nothing is retried into the chain, and a SIEM that never receives an
event changes nothing about what was decided or recorded.

Every event says so, in `unmapped`:

```json
"qed_record_hash": "5f9168e7…",
"qed_key_id": "ed25519:4575180164371e99",
"qed_verify_with": "qed export | qed-verify --keys <public dir>"
```

## The mapping

| Evidence record | OCSF class | Why |
|---|---|---|
| `verdict` | **Authorization (3003)** | the class for "a request was allowed or denied" |
| `approval_decided` | **Authorization (3003)** | an authorization decision made by a person rather than a rule |
| everything else | **API Activity (6003)** | a call that happened, with the operation named |

Approvals are deliberately *not* an Account Change or Entity Management class.
Splitting "who allowed this?" across two dashboards is the outcome worth
avoiding.

### Authorization

```json
{
  "class_uid": 3003, "class_name": "Authorization",
  "activity_id": 1, "activity_name": "Assign Privileges",
  "action": "ALLOW",
  "severity_id": 1,
  "actor": {"user": {"uid": "<principal hash>"}},
  "authorizations": [
    {"decision": "ALLOW", "policy": {"uid": "AG-DEF-001", "name": "No rule matched…"}}
  ],
  "metadata": {"labels": ["policy_hash:95e66abd…"]}
}
```

`activity_id` is OCSF's: **1** allowed, **2** denied, **0** unknown.
`REQUIRE_APPROVAL` is 0 — OCSF has no third value, and forcing it to Allow
would report a grant that has not happened. The real decision is always in
`action`, verbatim.

`authorizations` carries the rules that decided it. Absent, not empty, when no
rule matched: an OCSF consumer reads an empty list as "we looked and there were
none", which is not what a default-verdict decision means.

### Severity comes from what the decision did

| | enforce | shadow |
|---|---|---|
| `BLOCK` | 4 High | 3 Medium |
| `REQUIRE_APPROVAL` | 3 Medium | 2 Low |
| `ALLOW` | 1 Informational | 1 Informational |

Not from the rule's own severity. A CRITICAL rule that fired in shadow mode
stopped nothing, and paging on it would train people to ignore the channel.

`ungated_window` is the one API Activity record that is 4 High: an adapter
proceeded without a verdict.

## What never leaves

The chain's own discipline holds here too, because a SIEM is a system with
different access controls:

* **principals only as hashes** — `actor.user.uid` is the `human_hash`, with no
  name, email or IP. Resolving it is your job, in your systems, with data `qed`
  never held;
* **no target** — `api.operation` is the verb (`postgres.execute_sql`), never
  `db:prod/orders`. A target is the half of an action that names somebody's
  data;
* **no payload** — not the redacted parameters, not the SQL, nothing.

`tests/evidence/test_ocsf.py` asserts each of those against a payload
containing exactly the things that must not appear.

## Correlating

Three keys, in increasing order of usefulness:

```json
"observables": [{"name": "record.hash", "type_id": 10, "value": "5f9168e7…"}],
"raw_data": "qed:qed-prod:4821",
"unmapped": {"qed_proposal_id": "01JBPROPOSAL…", "qed_seq": 4821}
```

`qed_proposal_id` is the join: a verdict event carries no action name — the
proposal event has it — and putting the two together is what a SIEM is good at.

```
index=qed qed_type=verdict action=BLOCK
| join qed_proposal_id [search index=qed qed_type=proposal]
| table _time actor.user.uid api.operation action authorizations{}.policy.uid
```

`record.hash` with `type_id: 10` (Fingerprint) is how somebody gets from an
alert back to the evidence entry:

```bash
qed export --dir /var/lib/qed | grep 5f9168e7
```

## Delivery

A bounded queue and one background thread:

* `send` appends and returns. It never blocks, never retries inline, never
  raises;
* when the queue is full (10,000 events, about a minute of a busy instance) the
  **oldest** is dropped. Dropping the newest would mean a burst hid itself;
* one worker, so events arrive roughly in order and a slow endpoint cannot open
  fifty connections;
* failures are counted and logged, not retried forever.

That last choice is deliberate. A webhook down for an hour has lost an hour of
events, and an operator needs to know that — which a count says and an infinite
retry queue does not. `qed doctor` reports `sent`, `failed` and `dropped`, with
the URL reduced to scheme, host and port because that output ends up in support
tickets.

## Testing it without a SIEM

```yaml
observability:
  siem:
    stdout: true
```

```bash
qed serve 2>/dev/null | jq -c '{class_name, action, actor: .actor.user.uid}'
```

One JSON object per line, which is what every log collector reads — and what
`docker logs | jq` reads too.
