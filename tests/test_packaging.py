"""The wheel carries everything `qed` reads at runtime (SPEC §20.4, §24).

This exists because of a bug it would have caught. `qed/compliance/frameworks.yaml`
was not in `package-data`, so it was absent from the wheel, so the container --
which is built from the wheel -- started, imported, bound its port, and died
on the first request with a `FileNotFoundError` pointing at a path inside
site-packages. Every test passed throughout: the repo checkout has the file.

So the list is checked against the filesystem rather than trusted. A new data
file is a one-line change to `pyproject.toml`, and forgetting it should fail
here instead of in somebody's cluster.

Week 8 found the second half of the same bug: this file used to match with
`fnmatch`, whose ``*`` happily crosses a path separator, so `compliance/*.yaml`
looked as though it covered `compliance/packs/eu_ai_act.yaml`. setuptools uses
real glob semantics, where it does not -- so ten catalogue files were absent
from the wheel while this test stayed green, and the container started, loaded
its rules, found no catalogue for any control they cite and refused to decide.
The matcher segments the way setuptools does now.
"""

from __future__ import annotations

import tomllib
from pathlib import Path, PurePosixPath

import pytest

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "qed"

#: Extensions that are source, not data. Everything else under `qed/` is a file
#: the package reads at runtime and therefore has to ship.
SOURCE_SUFFIXES = {".py", ".pyc", ".pyi", ".pyo"}


def patterns() -> list[str]:
    with (ROOT / "pyproject.toml").open("rb") as handle:
        config = tomllib.load(handle)
    return list(config["tool"]["setuptools"]["package-data"]["qed"])


def covers(relative: str, pattern: str) -> bool:
    """Does `pattern` in `package-data` ship `relative`?

    `PurePosixPath.match`, not `fnmatch`: setuptools expands these patterns with
    the `glob` module, where ``*`` matches within one path segment. `fnmatch`
    has no notion of segments at all, which is how a nested directory of data
    files passed this test and shipped in no wheel.
    """
    return PurePosixPath(relative).match(pattern)


def data_files() -> list[str]:
    """Every runtime data file under `qed/`, as a package-relative path."""
    found = []
    for path in PACKAGE.rglob("*"):
        if not path.is_file() or path.suffix in SOURCE_SUFFIXES:
            continue
        if "__pycache__" in path.parts or ".egg-info" in str(path):
            continue
        found.append(path.relative_to(PACKAGE).as_posix())
    return sorted(found)


@pytest.mark.parametrize("relative", data_files())
def test_every_data_file_is_covered_by_a_package_data_pattern(relative: str) -> None:
    """A file here and not in `package-data` is a file the wheel will not have.

    The failure it causes is remote from its cause: an installed `qed` raises
    `FileNotFoundError` on a path under site-packages, which reads like a
    corrupted install rather than a packaging list that is one line short.
    """
    assert any(covers(relative, pattern) for pattern in patterns()), (
        f"{relative} is not matched by any package-data pattern in pyproject.toml. "
        f"Add it, or the wheel -- and so the container -- will not contain it."
    )


def test_the_patterns_all_still_match_something() -> None:
    """A pattern that matches nothing is a file that moved and a list that was
    not updated with it."""
    files = data_files()
    unused = [
        pattern
        for pattern in patterns()
        if not any(covers(relative, pattern) for relative in files)
    ]
    assert not unused, f"package-data patterns match nothing: {unused}"


def test_the_known_data_files_are_still_the_ones_we_think_they_are() -> None:
    """A deliberate inventory. Adding a data file should be a decision, not
    something that happens to work because a glob was wide enough."""
    found = data_files()
    assert "compliance/frameworks.yaml" in found
    assert any(name.startswith("core/policy/packs/") for name in found)
    assert any(name.startswith("infra/storage/migrations/") for name in found)
    assert any(name.startswith("compliance/packs/") for name in found)
    # No stray binaries, archives or credentials have crept into the package.
    assert not [
        name
        for name in found
        if Path(name).suffix not in {".yaml", ".yml", ".sql", ".json", ".txt", ".md"}
    ], found
