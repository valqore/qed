# Why there is no LICENSE file in this repository yet

**Status: open. Owner: business (founder). Blocks: first public push, first PyPI
upload, first container push.**

`SPEC.md` §25.1 fixes **Apache-2.0** for this repository. That decision is not
being changed here. It is being *sequenced*.

`SPEC.md` §24.2 lists "Valqore patent scope — confirm no conflict with the
broker + mandate + chain composition" as an open business item, and §22 defers
it to after week 3. §25.5 publishes this repository on day 1.

Those two cannot both happen in that order:

- Apache-2.0 §3 grants every recipient a perpetual, worldwide, **irrevocable**,
  royalty-free patent licence to the patent claims the contributor owns that the
  contribution necessarily infringes.
- The grant attaches on distribution. Making the repository public is
  distribution.
- Deleting the repository afterwards does not withdraw the grant from anyone who
  already received it.

So the Apache-2.0 patent grant, applied to code that implements the
broker + mandate + chain composition, must not be made before §24.2 is answered.

## What is withheld until §24.2 closes

1. No `LICENSE` file.
2. No `license` field in `pyproject.toml`.
3. `Private :: Do Not Upload` in the classifiers — PyPI rejects any upload that
   carries it.
4. No public remote, no public container image, no tag.

None of this restricts local development. Week 1 is fully buildable and testable
in this state.

## What must happen to lift it

1. Answer §24.2: does Valqore hold or has it filed any claim that the gate
   kernel practises? If yes, decide deliberately whether to grant it under
   Apache-2.0 or to restructure.
2. Answer §24.1 at the same time: final name. `gate` is a generic English noun;
   registrability is a real question, not a preference. Once a PyPI name and a
   GitHub URL are live, "rename is a single refactor" stops being true.
3. Then, in one commit: add `LICENSE` (Apache-2.0), set `license` in
   `pyproject.toml`, drop the `Private :: Do Not Upload` classifier, add
   `NOTICE`, and delete this file.

Until then the repository is "all rights reserved" by default, which is the
correct state for something not yet distributed.
