# valqore-qed

**This package installs nothing.** It holds the name `valqore-qed` on npm so
that nobody else can publish something under it that looks like Valqore QED.

QED is a **Python** program: a self-hosted policy-and-evidence kernel for
AI-agent actions. A JavaScript client has never existed. If one is ever
written, it will be published here and this README will stop saying so.

## What you probably want

- **The kernel:** `pip install valqore-qed` (Python 3.12+), or
  `brew install valqore/tap/qed` for a single-file binary with no interpreter
  on the machine.
- **The verifier**, which is the piece an auditor runs and the only one that
  needs to be trusted: `pip install qed-verify`.
- **The container:** `ghcr.io/valqore/qed`, signed and with an SBOM attested.
- **The source and the documentation:** <https://github.com/valqore/qed>.

## Why the version is `0.0.0`

Deliberately, and it is not tracking the kernel's version. A reservation is
not a release, and a stub that advertised the real version number would read
as a usable client that happens to be empty. `0.0.0` is the honest answer to
"what does this do", and the repository's own tests assert it stays that way.

Apache-2.0, same as the kernel.
