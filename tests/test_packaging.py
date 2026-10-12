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

import subprocess
import sys
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


# --------------------------------------------------------------------------
# The commands the wheel installs
# --------------------------------------------------------------------------


def declared_scripts() -> dict[str, str]:
    with (ROOT / "pyproject.toml").open("rb") as handle:
        return dict(tomllib.load(handle)["project"]["scripts"])


def installed_script(name: str) -> Path:
    """The console script as installed, found beside the running interpreter.

    Not through `PATH`: a developer's shell may not have the virtualenv's
    script directory on it, and a test that silently skips because of that
    proves nothing. `sys.executable`'s directory is where `pip` writes console
    scripts for this environment, on Windows (`Scripts/name.exe`) and on POSIX
    (`bin/name`) alike.
    """
    directory = Path(sys.executable).parent
    for candidate in (directory / f"{name}.exe", directory / name):
        if candidate.exists():
            return candidate
    raise AssertionError(
        f"`{name}` is declared in pyproject.toml but not installed in {directory}. "
        "Console scripts are generated at install time, so an editable install "
        "made before this entry was added will not have it: `pip install -e .`"
    )


class TestTheInstalledCommands:
    """`qed`, and `vqed` as an alias for it.

    The alias exists for a machine where `qed` is taken or ambiguous -- it is
    also the name of a Unix text editor, the ancestor of `ed`, which nothing
    current ships but which a reader may know. It is deliberately not a
    rename: `qed` remains the documented command, the import package and the
    repository, and the product name is frozen into `qed-pack-bundle/1`, the
    RFC 9457 type base and the OSCAL property namespace, none of which can
    follow a rename now that evidence format 1.0 is fixed (ADR-0015).
    """

    def test_both_names_point_at_one_entry_point(self) -> None:
        """An alias, not a second implementation. Two targets would be two
        code paths to keep in step, and the second would be the one nobody
        runs."""
        scripts = declared_scripts()
        assert scripts["qed"] == "qed.cli:main"
        assert scripts["vqed"] == scripts["qed"]

    def test_there_are_no_other_commands(self) -> None:
        """`qed-verify` is installed by its own project, in `packages/`, and
        must stay there: an auditor installs the verifier without installing
        the thing it verifies."""
        assert set(declared_scripts()) == {"qed", "vqed"}

    @pytest.mark.parametrize("name", ["qed", "vqed"])
    def test_each_name_runs_and_calls_itself_by_the_name_invoked(self, name: str) -> None:
        """Executed, not inferred from metadata.

        Typer takes the program name from `argv[0]`, so the help text follows
        whichever name was typed with no code change -- and this is the test
        that says so, because an alias whose help told the reader to run a
        different command would be a worse answer than no alias.
        """
        result = subprocess.run(
            [str(installed_script(name)), "--help"],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        assert f"Usage: {name} " in result.stdout, result.stdout
