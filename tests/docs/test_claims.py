"""The documents that cite tests cite tests that exist (SPEC §22 week 11).

`README.md` and `SECURITY.md` both carry a table of invariants with the test
that enforces each one, under the heading "enforced by tests, not by
convention". That claim is worth exactly as much as the references are accurate,
and a reference is the easiest thing in a repository to break: the test gets
renamed, split or merged by somebody who never opens the README.

`tests/test_threat_model.py` already makes this argument for `THREAT_MODEL.md`.
This makes it for the other two, and for every path any document names.

It found one on its first run. `README.md` promised
`tests/policy/test_determinism.py`, for the invariant "same inputs produce
byte-identical verdicts". No such file exists -- the test is
`tests/policy/test_engine.py::TestDeterminism`, and had been for weeks. The
invariant was enforced; the sentence claiming so pointed at nothing.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]

#: Documents whose cited paths must resolve. Deliberately not every Markdown
#: file: `QED_SPEC.md` and `CHANGELOG.md` describe intent and history, and both
#: legitimately name files that do not exist yet or no longer do.
DOCUMENTS = (
    "README.md",
    "SECURITY.md",
    "GOVERNANCE.md",
    "CONTRIBUTING.md",
    "THREAT_MODEL.md",
    "docs/onboarding-shadow-to-enforce.md",
    "docs/validation.md",
    "examples/README.md",
)

#: A backtick-quoted repository path: `tests/...py`, `qed/...py`, `examples/...`.
#: Anchored on the directories that exist, so prose like `--config qed.yaml`
#: and shell like `pip install -e .` are not mistaken for paths.
CITED = re.compile(
    r"`((?:tests|qed|packages|examples|deploy|docs)/[A-Za-z0-9_./*-]+\.(?:py|yaml|yml|md|json|rb|template))`"
)

#: Paths a document may name although they are not in the repository, each with
#: the reason. Anything not listed here must exist.
ALLOWED_ABSENT = {
    # Written by the operator, not shipped.
    "qed.yaml",
    "upstreams.yaml",
    # The tap is a separate repository and is not published (SPEC §24.1).
    "deploy/homebrew/qed.rb",
    # `docs/validation.md` names this one precisely *because* it does not
    # exist: the row records that `README.md` cited it for eight weeks while
    # the test lived in `test_engine.py`. A document describing a dangling
    # reference has to be able to quote it, which is the same false positive
    # the relative-link guard in `test_site.py` hit on the CHANGELOG entry
    # explaining its own rule.
    "tests/policy/test_determinism.py",
}


def documents() -> list[tuple[str, str]]:
    found = []
    for name in DOCUMENTS:
        path = ROOT / name
        if path.exists():
            found.append((name, path.read_text(encoding="utf-8")))
    return found


@pytest.mark.parametrize("name", DOCUMENTS)
def test_the_document_exists(name: str) -> None:
    """A document in this list that vanished would otherwise be skipped."""
    assert (ROOT / name).exists(), f"{name} is in DOCUMENTS and not in the repository"


def test_every_cited_path_resolves() -> None:
    """The check that caught `tests/policy/test_determinism.py`."""
    broken: list[str] = []
    for name, text in documents():
        for cited in sorted(set(CITED.findall(text))):
            if cited in ALLOWED_ABSENT:
                continue
            if not (ROOT / cited).exists():
                broken.append(f"{name} cites {cited}, which does not exist")
    assert not broken, "\n".join(broken)


def test_the_regex_finds_something() -> None:
    """A guard that matches nothing passes for the wrong reason.

    This is the failure mode of every "assert the list is right" test: the
    packaging guard in `tests/test_packaging.py` was written in `fnmatch` and
    appeared to cover ten files it did not match at all.
    """
    total = sum(len(set(CITED.findall(text))) for _, text in documents())
    assert total > 25, f"only {total} cited paths found; the pattern is probably wrong"


def test_the_invariant_tables_name_a_test_each() -> None:
    """Every row of an invariant table ends in a path, not prose.

    A row reading "enforced by review" in a table headed "enforced by tests" is
    the sentence this whole file exists to prevent.
    """
    for name in ("README.md", "SECURITY.md"):
        text = (ROOT / name).read_text(encoding="utf-8")
        rows = [
            line
            for line in text.splitlines()
            if line.startswith("|") and "`tests/" in line and "---" not in line
        ]
        assert rows, f"{name} has no invariant table rows; has it been restructured?"
        for row in rows:
            cells = [cell.strip() for cell in row.strip("|").split("|")]
            assert CITED.fullmatch(cells[-1]), f"{name}: row does not end in a test path: {row}"
