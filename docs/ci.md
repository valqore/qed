# QED in CI

`qed check` is the pipeline-shaped entry point: one proposal in, one verdict
out, and an exit code the build can act on (SPEC §12.5).

```bash
qed check proposal.json --server https://qed.internal --adapter-id adp_ci
```

## Exit codes

| Code | Meaning | What a pipeline usually does |
|---|---|---|
| `0` | `ALLOW` | continue |
| `2` | `BLOCK` | fail |
| `3` | `REQUIRE_APPROVAL` | fail, or wait for a human |
| `1` | QED could not decide | fail, and page somebody |

`1` is separate on purpose, and it is the distinction worth building the
pipeline around. A runner with no signing key, an unreadable proposal or an
unreachable instance has not been *refused* anything. Reading that as a `BLOCK`
reports a policy violation no policy produced; reading it as `0` lets a
misconfigured runner look exactly like a policy that allows everything.

In **shadow mode** the exit code is always `0`. The decision is still recorded,
and the output says so. A pipeline that failed in shadow mode would make shadow
mode useless for its one purpose — finding out what a policy would do before
anybody depends on it.

```bash
qed check proposal.json --server "$QED_URL" --adapter-id "$QED_ADAPTER_ID"
case $? in
  0) echo "allowed" ;;
  2) echo "blocked by policy"; exit 1 ;;
  3) echo "waiting for a human"; exit 1 ;;
  *) echo "QED could not decide"; exit 1 ;;
esac
```

## Two modes, and why `--server` is the better one

### `--server` — the team's instance decides

```bash
export QED_URL=https://qed.internal
export QED_ADAPTER_ID=adp_ci
export QED_ADAPTER_SECRET=...          # from your CI secret store
qed check proposal.json
```

The request is HMAC-signed the way every other adapter signs (SPEC §13), the
instance decides against the policy bundle *it* has loaded, and the evidence is
appended to *its* chain. The reference comes back on stdout:

```
ALLOW
  decided by   : https://qed.internal
  evidence ref : 4821
```

Three things follow from this, and they are the reason to prefer it:

**No signing key in CI.** A runner holding an evidence signing key is a runner
that can mint evidence, and the chain's value rests entirely on that not being
something anybody can do casually. `--server` needs an adapter secret, which
grants the ability to *ask*.

**The evidence outlives the build.** A chain in `$GITHUB_WORKSPACE` is deleted
with the job. The decision that gated a production deploy should not have a
six-minute lifetime.

**One policy bundle.** The rules that gate CI are the rules that gate
everything else, and `policy_hash` in the evidence names them.

Register the adapter on the instance first (SPEC §12.6); an unknown adapter is
refused with `AG-IDN-005`, not quietly allowed.

### Local, with an artifact

No instance to reach? Decide locally and leave the chain behind as a build
artifact:

```bash
qed keys init --dir .qed
qed check proposal.json --dir .qed --evidence-out qed-evidence.jsonl
qed-verify qed-evidence.jsonl --keys .qed/public --instance-id qed-local --require-complete
```

`--require-complete` belongs in a pipeline specifically because a pipeline reads
the exit code and nobody reads the summary. Without `--instance-id` the genesis
binding does not run, and the verifier exits 0 with a pass that is narrower than
it looks; with `--require-complete` a missing id fails the build instead.

`--evidence-out` writes the **whole chain**, not just this verdict.
`qed-verify` walks linkage from genesis, so a file holding the last two records
is a file that cannot be verified. A CI chain is short by nature — it starts at
genesis in a fresh workspace — so there is nothing to trim.

Upload it as an artifact and the build is self-evidencing: anyone with the
public key can check what was decided, without the runner, the repository or
QED itself.

## GitHub Actions

```yaml
name: governed deploy
on: [pull_request]

jobs:
  gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # Pin it. A gate that silently changes which rules it enforces
      # between one deploy and the next is not a gate, and `qed check`'s
      # exit codes are what this job branches on.
      - name: Install qed
        run: pip install valqore-qed==1.0.0

      - name: Ask QED whether this may deploy
        env:
          QED_URL: ${{ vars.QED_URL }}
          QED_ADAPTER_ID: ${{ vars.QED_ADAPTER_ID }}
          QED_ADAPTER_SECRET: ${{ secrets.QED_ADAPTER_SECRET }}
        run: |
          qed check .qed/deploy-proposal.json --json | tee verdict.json

      - name: Keep the verdict with the run
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: qed-verdict
          path: verdict.json
```

`--json` prints the instance's own response document, which is the thing to
keep: the verdict, the rules that fired, `policy_hash`, and `evidence_ref`.

To wait on an approval rather than fail, branch on `3` and poll
`GET /v1/approvals/{id}` — the SDK's `Qed.wait()` does exactly that
(`docs/api.md`).

## Writing the proposal

A proposal is a JSON document describing one action (SPEC §3). `examples/proposals/`
has three; the fields that matter most in a pipeline are:

```json
{
  "action": {"kind": "deploy", "name": "helm.upgrade", "target": "k8s:prod/payments"},
  "context": {
    "environment": "prod",
    "intent": "release 2026.10.3",
    "blast_radius_hints": {"writes": true, "scope": "service"}
  },
  "principal": {"human_hash": "...", "token_jti": "ci"}
}
```

`context.intent` is worth filling in even though nothing requires it: several
baseline rules route a production write with no stated intent to approval,
because an approver with no reason in front of them has nothing to judge.

## In this repository's own CI

`.github/workflows/ci.yml` runs the week-1 and week-2 exit criteria as shell
steps rather than only as pytest: `qed check` → `qed export` → `qed-verify`,
then the same again with a tampered record to prove the verifier still refuses
it. The `postgres` job repeats the end-to-end run against a real PostgreSQL,
the `anchors` job publishes a checkpoint to a real S3 server and then tries to
delete it, and the `deploy` job builds the container, renders the Helm chart
and runs `qed demo` inside the frozen binary. Those steps are the closest thing
in the repo to a worked example of this page.
