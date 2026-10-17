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

The domain is not chosen yet (SPEC §24.1 is still open, with the EUIPO/USPTO
registration and the PyPI, Homebrew and GHCR name reservations). The page does
not hardcode one, so it works at whatever hostname it lands on.

## The pre-launch notice comes off deliberately

The top of the page says, in so many words, that QED is unpublished and that
`pip install valqore-qed` does not work yet. That is true today: the names are
unreserved and `release.yml` has publishing gated behind the `PUBLISH_GHCR` and
`PUBLISH_PYPI` repository variables.

**Remove the notice in the same commit that sets those variables to `true`.**
Not before — a landing page offering an install command that fails is the exact
genre of small dishonesty this repository spends a test suite avoiding — and not
long after, either, because once the package exists the notice is itself the
false statement.

`tests/docs/test_landing.py` checks what it can check without reading CI
variables: that every command shown on the page is a command the CLI actually
has, that the measured numbers match their sources in the repository, and that
nothing from a short deny-list (star counts, customer names, certifications,
compliance percentages) has appeared.

## Launch checklist

In order. Each line is a thing that is false until it is done.

1. Reserve the names. **Done 2026-10-17** for PyPI (`valqore-qed`,
   `qed-verify` and `valqore`, each a `0.0.0` placeholder that installs
   nothing) and for the Homebrew tap (`valqore/homebrew-tap`, private, holding
   the rendered formula). **npm done the same day** — `valqore-qed`,
   `qed-verify` and `valqore`, each currently serving the `0.0.0-stage`
   placeholder npm publishes for a staged name; approving the staged `0.0.0`
   in npm's Staged Packages tab replaces it with ours and is cosmetic, because
   the name is held either way. Still to do: making `ghcr.io/valqore/qed`
   public, and filing the trademark (SPEC §25.1). Note what reserving changed:
   `pip install valqore-qed` and `npm install valqore-qed` both used to fail
   and now succeed, so the pre-launch notice in `index.html` is doing more work
   than before, not less.
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
