"""The one place the version is written (SPEC §25.6).

It was in eight places and they disagreed: `pyproject.toml` said `0.1.0`,
`qed/__init__.py` said `0.1.0.dev1`, the Dockerfile's label and
`docs/deployment.md` said `0.5.0`, the Helm chart's `appVersion` said `0.5.0`
while its own `version` said `0.1.0`, and `ENGINE_VERSION` — which goes into
**every verdict record** — still said `0.1.0` after seven weeks of releases.

That last one is why this file exists rather than a note asking people to be
careful. An auditor reading a verdict and asking "which engine decided this?"
gets an answer that is wrong by six releases, and nothing in the chain is
available to correct it afterwards: the record is immutable.

So: one literal here, imported everywhere else. The four places that cannot
import Python — `pyproject.toml`, the Helm chart, the Dockerfile label and the
docs — are checked against it by `tests/test_version.py`, and the release
workflow refuses a tag that does not match.

**Not derived from installed metadata.** `importlib.metadata.version()` would
remove this literal, and it reads the filesystem — which `qed.core` is
AST-scanned to forbid, for good reasons that have nothing to do with versions.
A constant is the smaller thing.

`schema_version` on `ActionProposal` and `EvidenceRecord` is deliberately
**not** here. SPEC §25.6 keeps it independent of the package version: it
changes only when the record format does, and `qed-verify` must verify every
version of it that was ever written.
"""

from __future__ import annotations

from typing import Final

__all__ = ["VERSION"]

VERSION: Final = "1.0.0"
