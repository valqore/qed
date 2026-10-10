# Examples

Everything here runs. Each file is either executed by the test suite or quoted
in a document whose commands were run to write it — `docs/validation.md` is the
page about why that distinction matters in this repository.

## Proposals

`proposals/*.json` are complete `ActionProposal` documents you can decide
without integrating anything:

```bash
qed keys init --dir ./state
qed check examples/proposals/prod-db-drop.json --dir ./state
```

| File | What it exercises |
|---|---|
| `prod-db-drop.json` | `DROP TABLE` on a production database. Trips the blast-radius rules; the demo in SPEC §25.5. |
| `open-ingress.json` | Opening a security group to the world. |
| `github-read.json` | A benign read, so that ALLOW is in the chain too. |

A chain of nothing but refusals is not a chain anybody believes. Decide the
read one as well.

## Onboarding

`onboarding/gap_report.py` answers "how far is this instance from
`mode: enforce`?" by counting, per shadow rule, how often promoting it would
have changed an outcome:

```bash
qed export --dir ./state --config qed.yaml | python examples/onboarding/gap_report.py
```

Stdlib only, and it reads an **export** rather than the instance — the same
file an auditor is handed. `--json` gives the same report for a dashboard. See
[docs/onboarding-shadow-to-enforce.md](../docs/onboarding-shadow-to-enforce.md),
stage 2.

## Policy

`policy-cases.yaml` is a case file for `qed policy test`:

```bash
qed policy test examples/policy-cases.yaml
```

The case file is a positional argument, not a flag. Add `--coverage` to list
the rules no case mentions, which is the check that catches a rule somebody
wrote and never exercised.

## Mandates

`mandates/sre-agent.json` is a mandate for an unattended agent — the envelope
that lets something act with no human in the loop, bounded by a time window, a
budget and an `allowed` set:

```bash
qed mandate sign examples/mandates/sre-agent.json --dir ./state
```

## SDK

`sdk/langgraph_tool.py` and `sdk/crewai_tool.py` put a verdict in front of a
tool call in two agent frameworks. **Both run without either framework
installed** — they import them if present and otherwise call the same function
directly, because what is being demonstrated is not the framework. See
[sdk/README.md](sdk/README.md).

## Identity providers

`deploy/keycloak/` holds a complete local Keycloak realm plus `demo.sh`, which
drives a real device-code login through to a budgeted token:

```bash
cd deploy/keycloak && docker compose up -d && ./demo.sh
```

That is in `deploy/` rather than here because it is a compose stack, not a
file to read.

## What is deliberately not here

- **An Okta or AWS AgentCore example.** SPEC §24 lists both. Writing one that
  has never been run against the real service would be a configuration file
  presented as a tested integration, and this repository has a documented
  history of that exact class of bug. They land when there is an account to run
  them against.
- **Anything that needs a secret to work.** An example that cannot run is not
  an example.
