# Contributing

Thank you for considering it. This page is about what a change has to satisfy
before it can be merged, and most of it is unusual only because of what this
software is for.

> **Written down before anybody needed it.** What follows is the process the
> maintainers already hold themselves to, so that it is not invented under
> pressure later — and it applies to their own commits: `main.json` in
> `.github/rulesets/` grants no bypass actors, so once those rules are
> installed a maintainer's change reaches `main` through a pull request like
> anybody else's. That directory's `README.md` says what is and is not in force
> today.

## Before a large change

**Open an issue first** for anything that adds a dependency, changes the
evidence format, adds a rule to the baseline pack, or touches `qed.core`. Not
bureaucracy: several of those have consequences that are easy to miss, and it
is kinder to say so before you have written the code than after.

Small fixes — a bug, a docstring, a test that was missing — need no issue. Send
the pull request.

## Developer Certificate of Origin

Every commit must be signed off (SPEC §25.1). This is the
[DCO](https://developercertificate.org/), not a CLA: you keep your copyright,
and you assert that you have the right to contribute the code under
Apache-2.0.

```bash
git commit -s -m "your message"
```

which appends:

```
Signed-off-by: Your Name <your@email>
```

Use your real name and a real address. `git config --global user.name` and
`user.email` once, and `-s` does the rest. The `dco` CI job checks every commit
a pull request adds, and a missing line is fixable with
`git rebase --signoff <base>`.

The check runs on pull requests only, which is what a DCO is for:
contributions from people who are not the maintainer. The requirement predated
the check by sixty-four commits, none of which carried the line. There is no
cutoff now — the pre-publication history rewrite signed off every commit,
because a governance document that documents its own exception is the shape of
failure this project exists to remove.

(`qed-ui` is AGPL-3.0 and uses a CLA instead. Different repository, different
rule.)

## What a change has to pass

```bash
ruff check . && ruff format --check .
mypy
pytest
```

All three, on your machine, before you push. CI runs the same things on Linux
and Windows across Python 3.12 and 3.13, plus PostgreSQL, the container on two
architectures, `pip-audit`, `gitleaks`, and a strict docs build.

### The definition of done (SPEC §23)

- **Tests, not just code.** A fix needs a test that fails without it. A
  feature needs the test that would have caught its absence.
- **`mypy --strict` clean**, and no `Any` in `qed.core`.
- **Docstrings that say why.** The house style is to explain the reasoning a
  reader cannot reconstruct from the code — especially a decision that looks
  arbitrary. If a line exists because of a bug, name the bug.
- **A `CHANGELOG.md` entry** for anything a user would notice.
- **An ADR in `docs/adr/`** for anything the spec does not settle. "The spec
  was silent so I picked one" is fine; "the spec was silent so nobody knows why
  it works this way" is not.
- **No new dependency without a spec update.** Amend SPEC §20.3 in the same
  pull request.

## Things that will be refused

Not to be unwelcoming — each of these is load-bearing, and it is better to know
in advance.

| Change | Why |
|---|---|
| An LLM, or any model SDK, in the decision path | A verdict must be a deterministic function of its inputs. `tests/core/test_no_llm.py` fails the build. |
| A network client, socket, or `asyncio` import in `qed.core` | The kernel decides offline; adapters and `qed.remote` do I/O. AST-checked. |
| An HMAC or symmetric signing path | A verifier must not need a secret the producer holds. Ed25519 only. |
| A development fallback signing key | A missing key is a hard failure, always. |
| Making a decision depend on rule file order, locale or clock skew | Determinism is the product. |
| Proprietary code, or code ported from `valqore-engine` with its history | Git history is irreversible; see `GOVERNANCE.md`. |
| An ORM, Alembic, OPA/Rego, Cedar, or a React build chain | SPEC §26 lists these as explicitly not used. |
| A change to hashing or record fields without a `schema_version` bump | A record written today must verify in seven years. |

## Writing a rule for the baseline pack

The pack ships in front of other people's agents, so a rule that is wrong
costs an operator their trust in the whole thing.

- **Ship a noisy rule in `mode: shadow`.** A rule that blocks real traffic on
  day one is the first one an operator turns off, and then they turn off the
  pack.
- **A `fix:` an operator can actually follow.** "Narrow the scope" is not one.
- **`compliance:` mappings only where the control genuinely covers it.** An
  invented mapping becomes an untraceable line in somebody's OSCAL export.
  A control id nothing defines is a lint error.
- **A golden case per rule**, in `tests/policy/golden/cases.yaml`. Run
  `qed policy test <cases> --coverage` to see what you missed.
- **Watch the verb boundaries.** `\b` does not work the way you expect on
  `snake_case` tool names, and a `BLOCK` with no approval path gets disabled.

## Documentation

- Commands in a document must have been **run**. `docs/validation.md` is the
  page about why: this project has a documented history of green builds
  shipping broken artifacts, and a quoted command that was never executed is
  the same category of claim.
- Cite a test by path when you claim something is enforced.
  `tests/docs/test_claims.py` checks those paths resolve.
- A new page goes in `mkdocs.yml`'s nav in the same commit.
  `tests/docs/test_site.py` fails otherwise, because a page nobody links is a
  page nobody reads.

## Commit messages

Conventional commits for the subject (`fix:`, `feat:`, `docs:`). The body
should explain **why**, and it can be long — the repository's history is part
of its documentation, and a commit that says what the diff already says is a
wasted opportunity. If the change came from a bug, describe the bug and how it
got past whatever should have caught it.

## Reporting a security bug

Not here. `SECURITY.md` has the private channels, and a security
bug in a public issue is a disclosure.

## Code of conduct

Be civil and assume good faith. Technical disagreement is welcome and personal
remarks are not. The maintainers will remove comments and, if necessary,
contributors; that decision is theirs and is not up for debate in the thread it
concerns.

`CODE_OF_CONDUCT.md` is the full version: what the rule means in practice, where
to report a problem, and what happens when the report concerns a maintainer.
