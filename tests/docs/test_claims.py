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

#: Each install command that now works, and the repository variable that gates
#: that publish.
#:
#: The marker that used to live here has been inverted twice and then moved
#: out of this mapping entirely, which is the history worth keeping.
#:
#: First it was "not on pypi yet", which became false when the name was
#: reserved -- `pip install valqore-qed` then resolved and installed a `0.0.0`
#: placeholder, so the page was pessimistic in the one direction that costs a
#: reader something. It was changed to name what the command *did* ("installs
#: a placeholder") on the reasoning that a claim about mechanism outlives a
#: claim about state. It did not: on 2026-10-19 both projects published 1.0.0
#: and "installs a placeholder" became the false statement, in the same costly
#: direction, since a reader was told to clone a repository to get something
#: one command now installs.
#:
#: So the guard stopped demanding a caveat and started forbidding the spent
#: ones -- and on 2026-10-25 **that still was not enough**, because a forbidden
#: phrase is only looked for on a page the guard decided to read. See
#: `SPENT_BESIDE_THE_COMMAND` below for what the third reading changed.
INSTALL_COMMANDS = {
    "pip install valqore-qed": "PUBLISH_PYPI",
    "docker run ghcr.io/valqore/qed": "PUBLISH_GHCR",
}

#: Claims about a channel that is now published, keyed by the command they are
#: attached to, matched case-insensitively inside the **sentence** that names
#: that command.
#:
#: Sentence-scoped rather than page-scoped because these words are not false in
#: themselves. `npm install valqore-qed` really does serve a `0.0.0` stub that
#: holds a name and nothing else, and the README says so one sentence away from
#: the pip line. A page-wide ban on "placeholder" would forbid the true
#: sentence to catch the false one.
SPENT_BESIDE_THE_COMMAND = {
    "pip install valqore-qed": (
        "placeholder",
        "installs nothing",
        "install from a clone",
        "is not a release",
        "not on pypi",
        "once it is on pypi",
        "does not work yet",
    ),
    "docker run ghcr.io/valqore/qed": (
        "not on ghcr",
        "no public ghcr image",
        "does not work yet",
    ),
}

#: Negative claims about the published state that are false whoever writes
#: them, forbidden anywhere on a checked page.
#:
#: This list exists because of how the 2026-10-19 guard failed. It read only
#: pages carrying a line a reader would copy, and the sentence that survived
#: five hours past publication was `README.md`'s "There is no public GHCR
#: image" -- prose in a blockquote, naming no command, telling a reader *not*
#: to run one. A guard that finds a page by the instruction it gives cannot see
#: the page that gives none.
SPENT_ANYWHERE = (
    "no public ghcr image",
    "not on ghcr yet",
    "not on pypi yet",
    "nothing is released yet",
    "nothing is published anywhere",
)


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


#: Every page a reader of this repository is pointed at. `QED_SPEC.md` and
#: `CHANGELOG.md` stay out: both describe history on purpose, and a changelog
#: entry recording that a name was once a placeholder is a fact about the past.
CHECKED_PAGES = [*sorted((ROOT / "docs").rglob("*.md")), ROOT / "README.md"]


def pages_telling_a_reader_to_install() -> list[tuple[Path, str]]:
    """Every page where an install command is a line to be run.

    A line inside a fenced block, or a step's `run:` in a workflow sample --
    something a reader copies. An inline mention in prose is excluded:
    `docs/credential-broker.md` naming the `[vault]` extra is describing a
    package, not asking anybody to fetch one.

    This is **no longer** what selects pages for the spent-claim check below,
    which is the fix for how that check went blind. It still answers a
    different question: which pages hand a reader a command at all.
    """
    found: list[tuple[Path, str]] = []
    for page in CHECKED_PAGES:
        text = page.read_text(encoding="utf-8")
        for line in text.splitlines():
            command = install_command_on(line)
            if command is not None:
                found.append((page, command))
    return found


def sentences_on(page: Path) -> list[str]:
    """The page as lowercase sentences, with the markup that hid one removed.

    Three things come out before splitting, each one a way the stale sentence
    stayed invisible: the blockquote markers (it was inside a `>` block), the
    backticks (it wrote the command as code), and the line wrapping (it ran
    across three lines, so no single line held both the command and the claim).
    """
    text = page.read_text(encoding="utf-8").lower()
    unquoted = re.sub(r"(?m)^\s*>\s?", "", text)
    flat = re.sub(r"\s+", " ", unquoted.replace("`", "").replace("*", ""))
    # Only a full stop ends a sentence here. Splitting on `:` and `;` as well
    # would let `pip install valqore-qed resolves; it installs a placeholder`
    # fall into two fragments and pass, which is the failure this guard is for.
    return re.split(r"(?<=[.!?])\s+", flat)


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


@pytest.mark.parametrize(("command", "gate"), list(INSTALL_COMMANDS.items()))
def test_the_publication_gate_still_exists(command: str, gate: str) -> None:
    """The gate survives publication, and this is why it is not the trigger.

    This test used to be called `..._is_still_closed` and was written as the
    self-destruct for the caveats: when `release.yml` stopped gating a publish
    it would fail, and the warnings would be deleted in the same commit.

    **It did not fire.** Publishing v1.0.0 on 2026-10-19 did not touch
    `release.yml` -- it set the repository *variable* `PUBLISH_PYPI` to true.
    The gate is still in the file, so the assertion still passed, while four
    pages went on telling readers that `pip install valqore-qed` installs a
    placeholder. A guard keyed on the mechanism cannot see a change of state,
    and `vars.X` in a workflow is the mechanism; the value of X is not in the
    repository at all.

    So the trigger moved to the pages themselves, below. What is left here is
    worth keeping for its own sake: the gate must not be *deleted*, because
    without it every future tag publishes whether or not anybody meant it to.
    """
    workflow = RELEASE.read_text(encoding="utf-8")
    assert f"vars.{gate}" in workflow, (
        f"release.yml no longer gates {gate}, so every `v*` tag would publish "
        f"`{command}` whether or not that was intended"
    )


#: The paragraph that stood on `README.md` for five days after v1.0.0 reached
#: PyPI and GHCR. Kept verbatim because the guard below was written twice
#: without it and passed both times; a guard tested only against text the
#: author invented is tested against nothing.
THE_PARAGRAPH_THAT_GOT_THROUGH = """\
> `pip install valqore-qed` resolves, and what it installs is a `0.0.0`
> placeholder whose own description says it installs nothing — the name was
> reserved on 2026-10-17 so that nobody else could take it, and a reserved
> name is not a release. `npm install valqore-qed` resolves to the same kind
> of placeholder — QED is a Python program and there has never been a
> JavaScript client. There is no public GHCR image. For the Python package,
> install from a clone, as the quick start below does.
"""


def test_the_guard_catches_the_paragraph_that_defeated_it(tmp_path: Path) -> None:
    """Both halves, on the real text: the false sentence and the true one.

    The paragraph said two things about PyPI that publication had made false
    and one true thing about npm, in consecutive sentences, inside a
    blockquote, with every command in backticks. A guard that flags the npm
    sentence to catch the pip sentence would be unusable, and one that reads
    the page as a single blob cannot tell them apart.
    """
    page = tmp_path / "README.md"
    page.write_text(THE_PARAGRAPH_THAT_GOT_THROUGH, encoding="utf-8")
    sentences = sentences_on(page)

    assert any("no public ghcr image" in s for s in sentences), (
        "the bare negative that named no command is what survived; it must be caught without one"
    )
    about_pip = [s for s in sentences if "pip install valqore-qed" in s]
    assert about_pip, "stripping `>` and backticks is what finds this sentence at all"
    assert any("placeholder" in s for s in about_pip)

    about_npm = [s for s in sentences if "npm install valqore-qed" in s]
    assert about_npm, "the true sentence has to be found too, to prove it is left alone"
    assert not any("pip install valqore-qed" in s for s in about_npm), (
        "npm really does serve a stub; flagging that sentence would make the "
        "guard demand a false correction"
    )


def test_a_spent_caveat_is_not_still_on_the_page() -> None:
    """The caveats are spent, and a spent caveat is the next overclaim.

    `docs/deployment.md` explained the publication gate under "Releasing", at
    the bottom of the page, while the two commands at the top told a reader to
    `pip install valqore-qed` and `docker run ghcr.io/valqore/qed:1.0.0`. Both
    fail. The same shape as the exit-code table in `README.md` that was correct
    140 lines below the quick start that got it wrong: a document can be
    accurate as a whole and wrong at the only place anybody reads.

    **This test passed for five days while `README.md` was wrong**, and the
    reason is the lesson. Its first version read only the pages returned by
    `pages_telling_a_reader_to_install()` -- pages carrying a line a reader
    copies -- so the repository's front page was never opened, because what it
    carried was a paragraph telling a reader *not* to copy one. It then looked
    for one exact phrase, "installs a placeholder", while the paragraph said
    "what it installs is a `0.0.0` placeholder". Two independent misses, each
    enough on its own.

    So selection is by **mention** now, not by instruction, and the claims are
    matched per sentence and per page rather than as one literal string. A
    guard for a false sentence cannot be keyed to the way the author happened
    to phrase the true one.
    """
    offenders: list[str] = []
    for page in CHECKED_PAGES:
        name = page.relative_to(ROOT).as_posix()
        sentences = sentences_on(page)
        for claim in SPENT_ANYWHERE:
            if any(claim in sentence for sentence in sentences):
                offenders.append(f"{name} still says {claim!r}")
        for command, claims in SPENT_BESIDE_THE_COMMAND.items():
            for sentence in sentences:
                if command not in sentence:
                    continue
                offenders += [
                    f"{name} says `{command}` and still claims {claim!r} in the same sentence"
                    for claim in claims
                    if claim in sentence
                ]
    assert not offenders, (
        "v1.0.0 is on PyPI and GHCR, so these pages carry a caveat that is now "
        "false in the direction that costs a reader something -- they are told to "
        "clone a repository to get what one command installs: " + "; ".join(offenders)
    )
