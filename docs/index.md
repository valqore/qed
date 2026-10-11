# Valqore QED

**QED decides whether an AI agent may perform an action, and writes evidence a
third party can verify without trusting the party that produced it.**

It is one self-hosted process. No bytes leave it by default. The decision path
contains no model: a verdict is a function of a proposal, a signed policy
bundle, a budget and a derived context, and the same inputs produce the same
bytes. The evidence is an Ed25519 hash-chained ledger, and the verifier that
checks it — `qed-verify` — is a separate package with `cryptography` as its only
dependency, written as an independent reimplementation so that agreement
between the two means something.

## Thirty seconds

```bash
pip install valqore-qed
qed keys init --dir ./state
qed check proposal.json --dir ./state     # 0 ALLOW · 2 BLOCK · 3 REQUIRE_APPROVAL
qed export --dir ./state > chain.jsonl
qed-verify chain.jsonl --keys ./state/public --instance-id qed-local
```

The last command is the one that matters. It reads a file and a public key, and
it never contacts the instance that wrote them.

`--instance-id` is the only check in it that ties the export to a particular
instance, and it is the only one that can be skipped. Leave it out and the
verifier reports `bound to : NOTHING` and names the check that did not run,
because the alternative — printing an unqualified `OK` — would be the verifier
overstating its own result.

## Where to go next

<div class="grid cards" markdown>

- :material-stairs-up: **[Shadow to enforce](onboarding-shadow-to-enforce.md)**

    The install path, in the order that keeps you able to roll back. Start here
    if you are putting this in front of something real.

- :material-alert-outline: **[Threat model](threat-model.md)**

    STRIDE, and twelve things QED does not protect against. Read the
    limitations before the mitigations.

- :material-file-code-outline: **[Policy language](policy-language.md)**

    What a rule is, what a predicate means, and why a missing field is falsy
    for every operator except `exists`.

- :material-seal: **[Evidence format](evidence-format.md)**

    The record, the chain, the checkpoint, and the promise that a record
    written today verifies in seven years.

</div>

## What this is not

- **Not a scanner.** It does not read your Terraform or your Kubernetes
  manifests. That is a different product.
- **Not a model.** There is no LLM in the decision path, and
  `tests/core/test_no_llm.py` fails the build if one appears.
- **Not a SaaS.** The kernel runs where your agents run, and produces
  auditor-acceptable evidence while completely offline. Anything under
  `qed.remote.*` is opt-in, outbound-only, and carries hashes and signatures
  but never customer data.
- **Not finished.** See [the changelog](changelog.md) for what is released and
  the [threat model](threat-model.md) for what is not covered.

## Honesty about assurance

A record proves different things depending on what produced it, and the
difference is recorded in the record rather than in the brochure. An
**enforcing** adapter holds the credential, so a `BLOCK` means the call did not
happen. An **advisory** adapter can only ask, so a `BLOCK` means the agent was
told no. Both are useful and they are not the same claim.
[Assurance classes](assurance-classes.md) is the page that says which is which.
