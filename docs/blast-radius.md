# The blast-radius score

A number from 0 to 100 describing **how much damage this action could do**. It
is not a probability, not a count of resources, and not a severity. ADR-008
gates unattended agents on `> 60`; `AG-BLR-005` uses the same threshold.

It is a pure function of the proposal. No cluster lookups, no network, no clock.
Two runs on the same proposal give the same number, this year and in three
years, which is what makes a recorded decision replayable.

## The table

Read top to bottom and add up. Implementation: `gate/core/policy/blast_radius.py`.

| Contribution | Points |
|---|---|
| **scope** `single_resource` | 10 |
| **scope** `multi_resource` | 30 |
| **scope** `account` | 60 |
| **scope** `global` | 80 |
| **environment** `dev` | 0 |
| **environment** `staging` | +5 |
| **environment** `prod` | +15 |
| **kind** `shell` | +10 |
| **kind** `skill` | +5 |
| **kind** `mcp_tool` / `http` / `custom` | 0 |
| `writes: true` | +10 |
| `deletes: true` | +25 |
| touches identity / secrets / audit surface | +15 |
| destructive verb | +15 |

Total clamped to 100. `gate policy explain` prints the contributions for a
specific proposal.

## The two pattern signals

**Identity, secrets and audit surface:** `iam`, `secret(s)`, `credential(s)`,
`password`, `kms`, `keyring`, `policy`/`policies`, `role(s)`, `rolebinding`,
`serviceaccount`, `token`, `mfa`, `sso`, `audit`, `cloudtrail`, `logging`,
`billing`.

**Destructive verbs:** `drop`, `truncate`, `delete`, `destroy`, `terminate`,
`purge`, `wipe`, `revoke`, `disable`, `detach`, `remove`, `kill`, plus
`force-push` and `rm -rf`.

Both are matched against `action.name`, `action.target` **and the string values
of `action.params_redacted`** — see below. Each signal counts once, whichever
place it was found, so a verb appearing in both the name and the parameters does
not score twice.

### Why `_` counts as a word separator

`\btoken\b` does not match `GITHUB_TOKEN`, and `\bterminate\b` does not match
`terminate_instances`, because `_` is a word character. Those two are the normal
naming style for exactly the resources this score is about, so the patterns use
`(?:\b|_)word(?=\b|_)`. The trailing lookahead keeps `dropbox` from matching
`drop`.

### Why the parameters are read

Looking only at the tool name is the trap. Valqore's MCP gateway scores blast
radius from the tool name, so a tool called `execute_sql` carrying
`DROP TABLE orders` scores low and stops routing to approval. The redacted
parameters are deterministic data the kernel already holds; the score reads them.

Scanning is capped at 4 KB of parameter text so a large body cannot make scoring
the slowest part of a decision. Policy rules still read the field directly and
in full — only the score is capped.

## Worked examples

| Proposal | Sum | Score |
|---|---|---|
| `github.list_issues` on `repo:acme/payments`, dev | 10 | **10** |
| the same in prod | 10 + 15 | **25** |
| `postgres.execute_sql` in prod, `sql: DROP TABLE orders_archive`, writes + deletes | 10 + 15 + 10 + 25 + 15 | **75** |
| `ec2.terminate_instances` in prod, single resource | 10 + 15 + 15 | **40** |
| `aws.put_role_policy` on `aws:iam:role/admin`, dev, writes | 10 + 10 + 15 | **35** |
| `aws.delete_account_roles` on `aws:iam:*`, prod, account, writes + deletes | 60 + 15 + 10 + 25 + 15 + 15 = 140 | **100** |

## Why this is not ported from Valqore

SPEC §5 says to port `governance/blast_radius.py` "with the K8s-specific parts
removed". Two problems with that:

1. That module **is** the Kubernetes part. It walks a dependency graph —
   Service→Deployment selectors, PodDisruptionBudgets, HorizontalPodAutoscalers,
   NetworkPolicies. Remove the Kubernetes parts and nothing is left.
2. Its `blast_radius` is an `int` **count of affected resources**. This one is a
   risk score on a fixed 0–100 scale. Same name, different unit — and ADR-008
   thresholds on 60, which is meaningless as a resource count.

Written fresh instead. See `docs/adr/0001-blast-radius-table.md`.

## Changing the table

Any change moves scores, and therefore moves decisions for rules that compare
against a threshold. So: bump `BLAST_TABLE_VERSION`, update this page, update
the golden cases, and write an ADR. Replaying an old proposal against a new
table will not reproduce the old verdict, which is why the verdict records the
`policy_hash` and the engine version alongside the score.
