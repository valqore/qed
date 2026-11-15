"""Every ADR number a file cites must resolve to a decision that exists.

`ci.yml` explained a raised dependency floor by saying "ADR-0019 chose Ed25519
per RFC 9864". There is no ADR-0019. The decision is real and the sentence is
true -- it is settled in `QED_SPEC.md` §20.3 -- but the citation pointed a reader
at nothing, and a reader who goes looking and finds nothing has no way to tell
a typo from a decision that was quietly dropped. Prose cannot be checked by
hand at 425 files, so the numbers are checked instead.

This guard's own first green run was an accident worth recording: the file was
still untracked, so `git ls-files` never showed it to itself, and its docstring
cites `ADR-0019` four times. It would have failed the moment it was committed.
A guard that has only ever passed is a guess.

There are **two numbering spaces**, and that is the trap this guard exists to
survive rather than the one it was written for:

* **Four digits** (`ADR-0001` .. `ADR-0018`) are the accepted ADRs, one file
  each in `docs/adr/`.
* **Three digits** (`ADR-001` .. `ADR-008`) are the proposals in
  `DESIGN_DECISIONS.md`, which says so itself: accepted ones enter the
  repository as `docs/adr/NNNN-*.md`. They are a different set of decisions,
  not the same ones with a zero missing -- `ADR-001` is the credential broker,
  `docs/adr/0001` is the blast-radius table.

So a guard that resolved every citation against `docs/adr/` would fail on
about forty legitimate references in `QED_SPEC.md`, `DESIGN_DECISIONS.md` and
the changelog, and the fix for that failure would be to pad the numbers --
silently merging two decision sets. Each space is therefore checked against
its own source, and the digit count is what selects between them.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
ADR_DIR = ROOT / "docs" / "adr"
INDEX = ADR_DIR / "index.md"
PROPOSALS = ROOT / "DESIGN_DECISIONS.md"

#: `ADR-` then three or four digits, and not a fifth -- so `ADR-00199` is not
#: read as a reference to `ADR-0019`.
CITATION = re.compile(r"ADR[-\s]?(\d{3,4})(?!\d)")

#: Proposal headings in `DESIGN_DECISIONS.md`: `## ADR-001 -- ...`.
HEADING = re.compile(r"^##\s+ADR-(\d{3})\b", re.MULTILINE)

#: This file names the dead citation it was written to prevent -- four times,
#: so the next reader learns what the bug was -- and is therefore excluded from
#: its own walk. `test_no_stale_promises.py` carries the same exemption for the
#: same reason: quoting a dead reference in order to forbid it is the opposite
#: of making one. Excluded by path rather than by spelling the number around
#: the regex, because a guard that cannot say what it guards against is worth
#: less than one line of exclusion costs.
SELF = Path(__file__).resolve()

#: Lines that name a dead ADR number in order to say it is dead. The changelog
#: has to be able to report that `ADR-0019` was cited and never existed, and a
#: reader of that sentence is informed rather than misled -- quoting a dead
#: reference in order to correct it is the opposite of making one, which is the
#: same exemption `test_no_stale_promises.py` carries for the stale sentence it
#: forbids. Each fragment is long enough that it cannot license a future
#: citation by accident, and `test_every_exemption_is_still_needed` deletes the
#: list's ability to rot: an entry that stops matching fails the build.
ALLOWED = (
    "`ADR-0019` has never existed.",
    "still credited ADR-0019 with choosing",
    "`ADR-0019` four times, so it should have failed itself",
)

#: Text the guard reads. Binaries and lockfiles cite nothing.
TEXT_SUFFIXES = frozenset(
    {".py", ".md", ".yml", ".yaml", ".toml", ".sh", ".json", ".cfg", ".txt", ".ini"}
)


def tracked_text_files() -> list[Path]:
    """Every tracked text file. `git ls-files` so an untracked scratch file
    cannot fail the build and a vendored dependency cannot either."""
    out = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    return [
        ROOT / name
        for name in out.split("\0")
        if name
        and Path(name).suffix in TEXT_SUFFIXES
        and (ROOT / name).is_file()
        and (ROOT / name).resolve() != SELF
    ]


def citations() -> list[tuple[Path, int, str]]:
    """(file, line number, digits) for every ADR citation in the repository."""
    found: list[tuple[Path, int, str]] = []
    for path in tracked_text_files():
        text = path.read_text(encoding="utf-8", errors="replace")
        for lineno, line in enumerate(text.splitlines(), start=1):
            if any(fragment in line for fragment in ALLOWED):
                continue
            for match in CITATION.finditer(line):
                found.append((path, lineno, match.group(1)))
    return found


def accepted() -> set[str]:
    """The four-digit numbers that have a file in `docs/adr/`."""
    return {p.name[:4] for p in ADR_DIR.glob("[0-9][0-9][0-9][0-9]-*.md")}


def proposed() -> set[str]:
    """The three-digit numbers that have a heading in `DESIGN_DECISIONS.md`."""
    return set(HEADING.findall(PROPOSALS.read_text(encoding="utf-8")))


def test_there_are_adrs_to_check() -> None:
    """A guard whose inputs came back empty would pass on everything.

    Both sets are read off disk, so a renamed directory or a reformatted
    heading would empty one of them and every assertion below would hold
    vacuously. This is the assertion that notices.
    """
    assert len(accepted()) >= 18, f"found only {sorted(accepted())} in {ADR_DIR}"
    assert len(proposed()) >= 8, f"found only {sorted(proposed())} in {PROPOSALS.name}"
    assert len(citations()) >= 50, "the citation regex matched almost nothing"


def test_four_digit_citations_resolve_to_an_adr_file() -> None:
    """`ADR-0019` has to be either a file or not written."""
    have = accepted()
    dangling = [
        f"{path.relative_to(ROOT).as_posix()}:{lineno} cites ADR-{digits}"
        for path, lineno, digits in citations()
        if len(digits) == 4 and digits not in have
    ]
    assert not dangling, (
        "ADR citations that resolve to no file in docs/adr/:\n  "
        + "\n  ".join(dangling)
        + f"\n\naccepted ADRs are {', '.join(sorted(have))}."
        "\nEither write the ADR, or cite where the decision actually lives."
    )


def test_three_digit_citations_resolve_to_a_proposal() -> None:
    """The `DESIGN_DECISIONS.md` space, checked against its own headings."""
    have = proposed()
    dangling = [
        f"{path.relative_to(ROOT).as_posix()}:{lineno} cites ADR-{digits}"
        for path, lineno, digits in citations()
        if len(digits) == 3 and digits not in have
    ]
    assert not dangling, (
        "ADR citations that resolve to no heading in DESIGN_DECISIONS.md:\n  "
        + "\n  ".join(dangling)
        + f"\n\nproposals are {', '.join(sorted(have))}."
        "\n\nNote the two numbering spaces: a four-digit ADR-0003 is"
        " docs/adr/0003, a three-digit ADR-003 is a DESIGN_DECISIONS proposal."
        " They are different decisions. Do not pad the number to make this pass."
    )


def test_the_index_lists_every_adr_and_only_real_ones() -> None:
    """The index is the reader's map, so a missing row hides an ADR."""
    text = INDEX.read_text(encoding="utf-8")
    listed = {d for d in CITATION.findall(text) if len(d) == 4}
    listed |= {m[:4] for m in re.findall(r"\((\d{4}-[^)]+\.md)\)", text)}
    have = accepted()
    assert not have - listed, f"ADRs with no row in index.md: {sorted(have - listed)}"
    assert not listed - have, f"index.md lists ADRs with no file: {sorted(listed - have)}"


@pytest.mark.parametrize("link", sorted(set(re.findall(
    r"\(([0-9][0-9][0-9][0-9]-[^)]+\.md)\)", INDEX.read_text(encoding="utf-8")
))))
def test_index_links_resolve(link: str) -> None:
    """A row can name the right ADR and still link to a filename that moved."""
    assert (ADR_DIR / link).is_file(), f"index.md links to missing {link}"


def test_every_exemption_is_still_needed() -> None:
    """An exemption whose line was reworded is a hole nobody is watching."""
    seen: set[str] = set()
    for path in tracked_text_files():
        text = path.read_text(encoding="utf-8", errors="replace")
        seen.update(fragment for fragment in ALLOWED if fragment in text)
    dead = [fragment for fragment in ALLOWED if fragment not in seen]
    assert not dead, (
        "ALLOWED entries that no longer match anything, so they only widen"
        f" the guard: {dead}. Delete them."
    )
