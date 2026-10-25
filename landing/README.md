# The landing page

One file, `index.html`. No build step, no dependency, no external request.

That is a constraint and not a preference. The product's first claim is that
zero bytes leave by default, and a landing page that pulls a font from one CDN
and an analytics script from another contradicts it above the fold. So the CSS
is inline, there are no images, and the only outbound links are to the
repository and to `valqore.io`.

## Deploying it

Any static host. It is a single file with no routing, so:

```console
# GitHub Pages, Cloudflare Pages, S3, Netlify -- all the same shape
cp landing/index.html <wherever>/index.html
```

This page is not hosted anywhere yet, and nothing in `.github/workflows/`
deploys it. The documentation site is separate (`mkdocs.yml` →
`qed.valqore.io`); this file is the one-page pitch, and it does not hardcode a
hostname, so it works at whatever one it lands on.

## The pre-launch notice was re-pointed, not removed

What the notice used to say: that QED was unpublished and that
`pip install valqore-qed` did not work yet. **That instruction — "remove the
notice in the same commit that sets `PUBLISH_PYPI=true`" — is how it went
wrong.** Publication did not happen in a commit. It happened by setting a
repository variable on 2026-10-19, which touched no file here, so there was no
commit to remove the notice in; the banner then told readers for five days that
three live install channels did not work.

So the notice now carries what publication did **not** close: the binaries are
not notarised, one maintainer has read this code, no design partner is in
enforce mode and no auditor has accepted the evidence format. Those are claims
about this repository rather than about an index, which means they expire when
somebody here does something, not when something happens elsewhere.

`tests/docs/test_landing.py` enforces it from both ends: the four phrases the
old banner used are **forbidden**, the three published install commands must be
**shown**, and the two remaining caveats must be **named**. It no longer asserts
that `release.yml` still gates publishing — `tests/docs/test_claims.py` owns
that check, and two copies of one assertion is two places for it to disagree.

## Launch checklist

In order. Each line is a thing that is false until it is done.

1. Reserve the names. **Done 2026-10-17** — PyPI, npm and the Homebrew tap,
   each holding `valqore-qed`, `qed-verify` and `valqore` at a `0.0.0` stub.
   **Published 2026-10-19**: PyPI and GHCR now serve 1.0.0, the tap is public,
   and the container carries a cosign signature and an SBOM attestation. npm
   still serves the stub on purpose — QED is a Python program and a JavaScript
   client has never existed. Still to do: filing the trademark (SPEC §25.1),
   and code-signing the macOS binaries.
2. Enable GitHub private vulnerability reporting. `SECURITY.md` points at
   `tunc@valqore.io`, which is a deliberate choice for launch and not an
   oversight: a maintainer address that is read beats a role alias that
   forwards nowhere, and `GOVERNANCE.md` already says there is one maintainer.
   Move to a `security@` alias when there is a second person to receive it —
   and change `SECURITY.md` in the same commit, because a disclosure address
   that bounces is worse than a personal one.
3. Flip the repository public. The banner on `valqore.io` links here, so it
   cannot go up before this.
4. Set `PUBLISH_GHCR=true` and `PUBLISH_PYPI=true`, tag `v1.0.0`, and check the
   release summary says both published.
5. Remove the pre-launch notice from `index.html` and deploy.
6. Turn on docs-site versioning (`mike`), which `mkdocs.yml` explains was
   deferred precisely until there was a published site to version.
