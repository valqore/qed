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
    # The rendered formula lives in `valqore/homebrew-tap` (reserved
    # 2026-10-17, private until the flip), not here. Here there is only the
    # template it is rendered from, by `deploy/homebrew/render.sh`.
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


def invariant_section(text: str) -> list[str]:
    """The lines under the "Invariants" heading, up to the next one.

    Scoped rather than scanning the whole document, which is how this was
    written first. `README.md` also has a *capability* table, and a row of it
    that cited `tests/evidence/fixtures/` as well as the module it describes
    was read as an invariant row with prose in its last cell. The guard was
    right that the row did not end in a test path and wrong that it was
    supposed to -- a guard that cannot tell one table from another, which is
    the recurring shape in `docs/validation.md`.
    """
    lines = text.splitlines()
    starts = [i for i, line in enumerate(lines) if line.startswith("## ") and "Invariant" in line]
    if not starts:
        return []
    start = starts[0]
    rest = lines[start + 1 :]
    end = next((i for i, line in enumerate(rest) if line.startswith("## ")), len(rest))
    return rest[:end]


def test_the_invariant_tables_name_a_test_each() -> None:
    """Every row of an invariant table ends in a path, not prose.

    A row reading "enforced by review" in a table headed "enforced by tests" is
    the sentence this whole file exists to prevent.
    """
    for name in ("README.md", "SECURITY.md"):
        text = (ROOT / name).read_text(encoding="utf-8")
        section = invariant_section(text)
        assert section, f"{name} has no Invariants section; has it been restructured?"
        rows = [
            line
            for line in section
            if line.startswith("|") and "`tests/" in line and "---" not in line
        ]
        assert rows, f"{name} has no invariant table rows; has it been restructured?"
        for row in rows:
            cells = [cell.strip() for cell in row.strip("|").split("|")]
            assert CITED.fullmatch(cells[-1]), f"{name}: row does not end in a test path: {row}"


# --------------------------------------------------------------------------
# Commands a reader is told to run
# --------------------------------------------------------------------------

#: What a reader meets first on each page that tells them to install from a
#: registry. `release.yml` holds both names behind `PUBLISH_PYPI` and
#: `PUBLISH_GHCR` until SPEC §24.1's reservations are done, so every one of
#: these commands fails today with "No matching distribution found".
RELEASE = ROOT / ".github" / "workflows" / "release.yml"

# Markers are matched case-insensitively: one of these pages carries the
# caveat as a YAML comment inside a workflow sample, where a sentence starts
# with a capital.
#: Each unavailable install command, the phrase a page must carry if it tells
#: a reader to run it, and the repository variable still gating that publish.
#:
#: The pip marker used to be "not on pypi yet", and that sentence **became
#: false on 2026-10-17** without becoming true: the name was reserved, so
#: `pip install valqore-qed` resolves and installs a `0.0.0` package holding
#: one README. A page saying "not on PyPI yet" was then wrong in the one
#: direction that costs a reader something -- they would run it, see a clean
#: exit, and believe the page had been pessimistic. So the marker names what
#: the command *does* rather than what the index contains, which is the shape
#: of claim that survived five launch steps in two days while every
#: state-of-the-world sentence around it died.
INSTALL_COMMANDS = {
    "pip install valqore-qed": ("installs a placeholder", "PUBLISH_PYPI"),
    "docker run ghcr.io/valqore/qed": ("not on ghcr yet", "PUBLISH_GHCR"),
}


def install_command_on(line: str) -> str | None:
    """The unavailable install command this line tells a reader to run, if any.

    Quotes come out before matching, which is the fix for the line that got
    past this guard: `README.md`'s Postgres section said
    `pip install 'valqore-qed[postgres]'`, and the quote after `pip install`
    was enough for `startswith` to see a different string. So the guard read
    five other pages, found each one's caveat, and passed while the README told
    a reader to fetch a package that does not exist -- a quoting detail
    deciding whether a page is checked at all.
    """
    stripped = line.strip().removeprefix("run: ").removeprefix("$ ")
    stripped = stripped.replace("'", "").replace('"', "")
    for command in INSTALL_COMMANDS:
        if stripped.startswith(command):
            return command
    return None


def pages_telling_a_reader_to_install() -> list[tuple[Path, str, str]]:
    """Every page where an unavailable install command is a line to be run.

    A line inside a fenced block, or a step's `run:` in a workflow sample --
    something a reader copies. An inline mention in prose is excluded:
    `docs/credential-broker.md` naming the `[vault]` extra is describing a
    package, not asking anybody to fetch one.
    """
    found: list[tuple[Path, str, str]] = []
    for page in [*sorted((ROOT / "docs").rglob("*.md")), ROOT / "README.md"]:
        text = page.read_text(encoding="utf-8")
        for line in text.splitlines():
            command = install_command_on(line)
            if command is not None:
                found.append((page, command, INSTALL_COMMANDS[command][0]))
    return found


@pytest.mark.parametrize(
    "line",
    [
        "pip install valqore-qed",
        "pip install valqore-qed[postgres]",
        "pip install 'valqore-qed[postgres]'",
        '        run: pip install "valqore-qed[vault]"',
        "$ pip install valqore-qed",
    ],
)
def test_every_spelling_of_the_install_command_is_recognised(line: str) -> None:
    """Including the quoted one, which is how the README evaded the check.

    A guard tested only against the form the author had in mind is a guard
    tested against nothing: the forms it misses are exactly the ones that reach
    a reader.
    """
    assert install_command_on(line) == "pip install valqore-qed"


@pytest.mark.parametrize(
    "line",
    [
        "Vault is an optional extra (`pip install valqore-qed[vault]`). Asking for a",
        "pip install -e '.[postgres]'",
        'pip install -e ".[dev]" -e packages/qed-verify',
        "# pip install valqore-qed is not how this repository is installed",
    ],
)
def test_prose_and_working_commands_are_not_flagged(line: str) -> None:
    """The other half: stripping quotes must not turn a sentence, a comment or
    the install that actually works into an instruction to fetch a package."""
    assert install_command_on(line) is None


def test_the_pages_that_say_to_install_are_found() -> None:
    """If this ever returns nothing, the test below passes by vacancy."""
    assert pages_telling_a_reader_to_install(), "no install commands found at all"


@pytest.mark.parametrize(("command", "gate"), [(c, g) for c, (_, g) in INSTALL_COMMANDS.items()])
def test_the_publication_gate_is_still_closed(command: str, gate: str) -> None:
    """The condition the test below depends on.

    When the name is reserved and `release.yml` stops gating that publish, this
    fails -- and the warnings the other test demands become false statements to
    delete. That is the point: a caveat nobody removes is the next overclaim,
    just pointing the other way.
    """
    workflow = RELEASE.read_text(encoding="utf-8")
    assert f"vars.{gate}" in workflow or f"{gate}=true" in workflow, (
        f"release.yml no longer gates {gate}, so `{command}` may now work: "
        "delete the 'not yet published' warnings the docs carry and this test"
    )


def test_an_install_command_that_cannot_work_says_so_where_it_is_written() -> None:
    """Not 140 lines further down, which is where it said so before.

    `docs/deployment.md` explained the publication gate under "Releasing", at
    the bottom of the page, while the two commands at the top told a reader to
    `pip install valqore-qed` and `docker run ghcr.io/valqore/qed:1.0.0`. Both
    fail. The same shape as the exit-code table in `README.md` that was correct
    140 lines below the quick start that got it wrong: a document can be
    accurate as a whole and wrong at the only place anybody reads.
    """
    offenders: list[str] = []
    for page, command, marker in pages_telling_a_reader_to_install():
        text = page.read_text(encoding="utf-8").lower()
        # Each command's own marker, and nothing else. There used to be an
        # `or "not on pypi yet" in text` here, which meant a page warning
        # about PyPI satisfied the guard for a Docker command it also carried.
        if marker not in text:
            offenders.append(f"{page.relative_to(ROOT).as_posix()} says `{command}`")
    assert not offenders, (
        "these pages tell a reader to run a command that cannot work and do not "
        "say so on the page: " + "; ".join(offenders)
    )
