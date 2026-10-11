# Shadow to enforce

The install path, in the order that keeps you able to roll back at every step.

Nobody puts a gate in front of a working agent on day one. The sequence below
is the one that gets you from "QED is watching" to "QED is stopping things"
without a week where your agents are broken and nobody knows which rule did it.

Every command on this page was run to write it, and the output is quoted rather
than invented.

!!! note "One `--config` for every command"
    The chain's genesis record is bound to `instance_id`, so a command run
    without the config that created the chain is refused:

    ```
    qed: this chain was started as 'acme-onboarding'; the genesis hash is bound
    to that identity and cannot be reused as 'qed-local'
    ```

    That is the guard working. Pass `--config qed.yaml` to `check`, `export`,
    `status`, `doctor` and `checkpoint` alike, or set `QED_CONFIG`.

## The three dials

This is the part worth reading twice, because people turn the wrong one and
conclude QED does not work.

| Dial | Where | What it does |
|---|---|---|
| **Instance mode** | `mode:` in `qed.yaml` | `shadow` makes every effective decision ALLOW and every exit code 0. The real verdict is still computed and still written to the chain. This is the global brake. |
| **Rule mode** | `mode:` on each rule | A rule in `shadow` does not contribute to `decision`. It does contribute to `would_decision`. Rules default to `enforce`; 16 of the 46 shipped rules are deliberately `shadow`. |
| **Adapter enforcement** | `broker.upstreams_file` | Whether the adapter *can* stop the call at all. With no broker, the agent holds its own credentials, so every adapter is **advisory** — QED decides and records, and the agent could go around it. |

All three must point at "enforce" before a `BLOCK` stops anything. Flipping the
instance to `mode: enforce` while the broker is unconfigured gets you a chain
full of enforcing verdicts and an agent that was never actually gated — which
is the single most common way to believe you are protected and not be.

`qed doctor` exists to tell you which dials are still off:

```console
$ qed doctor --dir ./state --config qed.yaml --offline
instance   : acme-onboarding  (mode shadow)
signing key: ed25519:ad3567ac84409264
policy     : 46 rules
retention  : payloads forever
anchors    : none -- a checkpoint's Merkle root lives only in the chain it summarises,
             so it attests to nothing an operator who could rewrite the chain could not
             recompute. Configure `evidence.checkpoint.publishers`.
self-gov   : off -- `qed keys rotate` and `qed packs import` need nobody's agreement.
             The operator is the one actor no rule constrains. Set `admin.self_governed`
             with `admin.approvers` to change that (SPEC 17).

upstreams  : none configured, so every adapter is ADVISORY -- QED decides and records, but the agent holds its own credentials and could go around it.
```

Read `doctor` at every stage below. It is written to describe what is *not*
protecting you, which is the only useful direction for a posture command.

---

## Stage 0 — decide one proposal by hand

Before anything is in front of anything, confirm the kernel works and the chain
verifies. Five minutes, no integration.

```bash
pip install valqore-qed
qed keys init --dir ./state
```

```console
key_id : ed25519:ad3567ac84409264
private: state/evidence-key.pem  (keep this; 0600)
public : state/public  (give this to auditors)
```

Write the smallest config there is:

```yaml title="qed.yaml"
instance_id: acme-onboarding
mode: shadow
```

Then decide the example proposal and verify the chain it produced:

```bash
qed check examples/proposals/prod-db-drop.json --dir ./state --config qed.yaml
qed export --dir ./state --config qed.yaml > chain.jsonl
qed-verify chain.jsonl --keys ./state/public --instance-id qed-local
```

```console
records   : 7 (seq 0..6)
keys      : ed25519:ad3567ac84409264
checkpoint: 0
purged    : 0 payload(s) removed under retention
bound to  : instance 'qed-local'
result    : OK -- chain is contiguous, unmodified, signed, and bound to the instance id supplied
```

That last command is the one that matters, and it is the one to show an
auditor. It reads a file and a public key, it does not contact the instance
that wrote them, and it is a separate package with `cryptography` as its only
dependency — written as an independent reimplementation so that agreement
between producer and verifier means something.

Drop `--instance-id` and the last two lines become `bound to : NOTHING` and a
result that names the check which did not run. That is not pedantry: the genesis
binding is the only check here that distinguishes this chain from one generated
on any laptop with any key, so a pass without it is a pass about internal
consistency alone. When you are the operator the id is in your own config. When
you are the auditor it has to arrive from outside the export, and so do the keys.

**Exit criterion:** `qed-verify` exits 0 and prints `result : OK`. If it prints
`OK SO FAR`, a check was skipped — read which one before you treat it as a pass.

---

## Stage 1 — shadow in front of something real

Pick the *noisiest* integration you have, not the most dangerous one. The point
of this stage is to collect decisions, and you want volume.

=== "An MCP server"

    ```bash
    qed mcp --dir ./state --config qed.yaml -- npx -y @modelcontextprotocol/server-postgres
    ```

    Every tool call is decided and recorded; none is stopped.

=== "A coding agent"

    ```bash
    qed install claude-code
    ```

    The hook answers `ask`, never `allow`, and never exits 1
    ([ADR-0008](adr/0008-hook-answers-ask-and-never-allow.md)) — a hook that
    crashes must not be a hook that blocks your agent.

=== "Outbound HTTP"

    ```bash
    qed proxy --dir ./state --config qed.yaml --port 8080
    ```

=== "A pipeline"

    ```bash
    qed check plan.json --dir ./state --config qed.yaml
    ```

    In shadow the exit code is always 0, so a pipeline cannot fail on a shadow
    verdict. That is deliberate: a shadow mode that broke builds would not be
    one anybody left running long enough to learn from.

**Exit criterion:** a week of real traffic in the chain, and `qed status`
showing `records` climbing. Do not tune anything yet. A rule set tuned against
three days of traffic is tuned against three days of traffic.

---

## Stage 2 — read the gap

This is the stage that has a number in it, and the number is the whole reason
shadow mode exists.

Every verdict carries two decisions:

- `decision` — what QED did. In shadow, always effectively ALLOW.
- `would_decision` — what QED *would* have decided if every matching rule were
  enforcing.

Where they differ, you are looking at exactly the work between you and enforce.
The CLI shows it inline, and marks each rule with `!` for enforcing and `~` for
shadow:

```console
$ qed check skill-install.json --dir ./state --config qed.yaml
ALLOW
  (shadow mode: recorded, not enforced -- would be above)
  blast radius : 15/100
  would decide : REQUIRE_APPROVAL
  policy hash  : 7618895d28d35b79...
  evidence seq : 5, 6
  ! AG-DEF-001 [LOW] No rule matched this action; the bundle default was applied.
      fix: If this class of action should be governed, add a rule for it.
  ~ AG-SKL-003 [MEDIUM] This skill does not declare which tools it may use.
      fix: Add an allowed-tools manifest to the skill.
```

`ALLOW` now, `REQUIRE_APPROVAL` if `AG-SKL-003` were promoted. Over a whole
chain, `examples/onboarding/gap_report.py` counts them:

```console
$ qed export --dir ./state --config qed.yaml | python examples/onboarding/gap_report.py
2 verdict(s); 1 would have decided differently under enforce

 COUNT  RULE             WOULD MOVE
     1  AG-SKL-003       ALLOW -> REQUIRE_APPROVAL

To enforce one of these, write your own rule with your own id:
an override may only soften or narrow (ADR-002.4). See
docs/onboarding-shadow-to-enforce.md, stage 3.
```

Each line is a rule and a number that says how often promoting it would have
changed an outcome. Work the list from the top. `--json` gives the same thing
for a dashboard.

The script is stdlib-only and reads an **export**, not the instance — the same
file you would hand an auditor, with no access to the database that wrote it.

!!! warning "An empty report is not a green light"
    No gaps can also mean the chain is too short, or that nothing has exercised
    the shadow rules yet. The script says so rather than congratulating you.
    Check the record count in `qed status` before concluding anything.

**Exit criterion:** you can name, for every rule in that list, which of the
three things in Stage 3 you are going to do about it.

---

## Stage 3 — close the gap

For each rule in the list, exactly one of three things is true. Say which, in
the policy file, where an auditor can read it.

### It is right, and you want it enforcing

The shipped rule stays shadow — **an override may only soften or narrow**
(ADR-002.4), so you cannot flip `mode: shadow` to `mode: enforce` on a rule you
did not write. Both of the obvious attempts are lint errors:

```yaml
# Both of these are refused.
- rule_id: AG-BUD-002
  override: { mode: enforce }     # error: an override may only soften or narrow
- rule_id: AG-BUD-002             # error: duplicate_rule_id, already defined in budget.yaml
  mode: enforce
  ...
```

That is the design, not a bug: an overlay file that could silently *tighten*
central policy is a file that can break production from a directory nobody
reviews. **To harden, write your own rule** (ADR-002.4: *"for hardening, a new
rule is written, not an override"*). Copy the shipped rule's `when` block, give
it your own id, and set the mode you want:

```yaml title="policy/acme-budget.yaml"
rules:
  - rule_id: ACME-BUD-001
    name: Budget at or past 80 percent consumed (enforced)
    severity: LOW
    mode: enforce
    when:
      any:
        - { field: derived.budget.steps_pct_used, gte: 80 }
        - { field: derived.budget.tokens_pct_used, gte: 80 }
        - { field: derived.budget.money_pct_used, gte: 80 }
    verdict: REQUIRE_APPROVAL
    approval: { approvers: [agent-owners], timeout: 10m }
    message: "This agent has used 80% of its budget."
    fix: "Raise the budget or let the window reset."
```

Your rule and the shipped one now both match. That is fine and it is visible:
the shipped one contributes `~` to `would_decision`, yours contributes `!` to
`decision`, and the chain records both.

### It is right, but too strict for you

Soften it with an override. This direction is always allowed, and it is
recorded in the `policy_loaded` record where an auditor sees it:

```yaml
rules:
  - rule_id: AG-DAT-007
    override:
      verdict: REQUIRE_APPROVAL              # BLOCK -> approval
      applies_to: { environments: [prod] }   # narrower than the original
```

### It does not apply to you

Disable it, **with a reason**. The reason is mandatory, and it goes into the
chain:

```yaml
rules:
  - rule_id: AG-SKL-002
    disabled: true
    reason: "We do not use skills; re-enable when the Claude Code rollout starts."
    disabled_by: "platform-team"
```

A disabled rule with no reason is a lint error. "Approve forever" does not
exist anywhere in QED: a permanent exception is a policy change, not an
approval, and an auditor must be able to tell the two apart.

Then lint and test before anything loads it:

```bash
qed policy lint --policy ./policy
qed policy test ./policy/cases.yaml --policy ./policy --coverage
```

The case file is a positional argument, not a flag. `--coverage` lists the
rules no case mentions, which is the check that catches a rule you wrote and
never exercised — see [Testing a rule set](policy-testing.md).

**Exit criterion:** `qed policy lint` is clean, and the gap list from Stage 2
contains nothing you have not decided about.

---

## Stage 4 — become enforcing

**This is the step people skip, and skipping it is why a `BLOCK` sometimes
stops nothing.**

Up to here QED has been advisory: it decided and recorded, and the agent held
its own credentials. An advisory `BLOCK` means the agent was *told* no. An
enforcing `BLOCK` means the call did not happen. Both are real and they are not
the same claim — the difference is written into every record, and
[Assurance classes](assurance-classes.md) is the page that explains what each
one proves.

To make an adapter enforcing, QED has to hold the credential the agent needs:

```yaml title="qed.yaml"
broker:
  upstreams_file: ./upstreams.yaml
```

```yaml title="upstreams.yaml"
upstreams:
  - id: postgres-prod
    kind: mcp
    match: { mcp_server: postgres, environments: [prod] }
    credential:
      source: env                     # or vault, or file
      ref: PROD_DATABASE_URL
      inject: { type: env, name: DATABASE_URL }
```

Then take the credential away from the agent. That last sentence is the whole
step; everything else is configuration. If the agent still has a working
connection string in its own environment, QED is still advisory no matter what
the config says.

`qed doctor` ends with a table and a count:

```console
$ qed doctor --dir ./state --config qed.yaml
UPSTREAM             MODE       INJECT   CREDENTIAL
postgres-prod        ENFORCING  env      resolved (14 chars)

1 enforcing, 0 advisory
```

It prints the length and never the value, here and in every other command.

An upstream whose credential cannot be resolved does not fail — it **degrades
to advisory and says which one and why**:

```console
UPSTREAM             MODE       INJECT   CREDENTIAL
postgres-prod        ADVISORY   env      unavailable: $PROD_DATABASE_URL is not set, so this upstream has no credential to inject

0 enforcing, 1 advisory
```

That line is the trap this stage exists to avoid. Configuring a broker is not
the same as having one, and `0 enforcing` is the number to read — not the
presence of the config block.

See [The credential broker](credential-broker.md) for Vault, file and env
sources.

**Exit criterion:** `qed doctor` ends with `1 enforcing` or better, and the
agent's own copy of that credential is gone.

---

## Stage 5 — flip the instance

Now, and only now:

```yaml title="qed.yaml"
mode: enforce
```

Reload. If `admin.self_governed` is on, this needs an approval, which is the
point ([ADR-0014](adr/0014-qed-governs-its-own-admin-operations.md)).

What changes: `effective_decision` stops being forced to ALLOW, and exit codes
become meaningful — `0` ALLOW, `2` BLOCK, `3` REQUIRE_APPROVAL. Nothing about
the recorded verdicts changes, because they were always the real ones.

**Exit criterion:** a deliberate `BLOCK` that actually fails. Drive the thing
you gated into a rule you know will block it, and watch it not work. A gate
that has never refused anything is a gate nobody has tested.

---

## Rolling back

One line, and it takes effect on reload:

```yaml
mode: shadow
```

Everything keeps being decided and recorded; nothing is stopped. The chain is
continuous across the flip — `mode` is a field on every record, so "we were
enforcing from the 3rd to the 11th" is a question the chain answers.

This is why the instance dial exists separately from the rule dials. Rolling
back by editing rules means editing rules under pressure. Rolling back by
flipping one word does not.

## A realistic schedule

| Week | Stage | What you have at the end |
|---|---|---|
| 1 | 0–1 | Chain verifies; shadow in front of one integration |
| 2–3 | 1 | Two weeks of real traffic, untouched |
| 4 | 2–3 | Gap list triaged; your own rules written, linted and tested |
| 5 | 4 | One upstream enforcing; the agent's credential revoked |
| 6 | 5 | `mode: enforce`, and a `BLOCK` you watched fail |

Six weeks is not slow. Stage 1 is almost all of it and it is unattended.

## Before you call it done

- [ ] `qed-verify` passes on an export, run from a machine that is not the instance
- [ ] `qed doctor` ends with `1 enforcing` or better — not merely a `broker:` block in the config
- [ ] A `BLOCK` has been observed to actually stop something
- [ ] `qed policy lint` is clean and every rule you wrote has a test case
- [ ] Anchors are configured — `doctor` stops saying `anchors : none`. Until it does, a checkpoint's Merkle root lives only in the chain it summarises, so it attests to nothing an operator who could rewrite the chain could not recompute ([Checkpoints and anchors](checkpoints.md))
- [ ] `admin.self_governed` is on, or you have written down why the operator is the one actor no rule constrains
- [ ] Somebody other than the person who installed it has verified a chain

The last one is the only item on the list that tests the thing QED is for.
