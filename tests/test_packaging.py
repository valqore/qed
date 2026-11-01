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

import os
import re
import shutil
import subprocess
import sys
import sysconfig
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

#: A CSI escape sequence, which is all `rich` emits here.
ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")

#: The usage line of a real `qed --help`, exactly as a GitHub Actions runner
#: produced it. `rich` counts the runner as a terminal, so the line arrives in
#: two styled spans -- `Usage: ` bold yellow, the rest bold -- and the literal
#: string `"Usage: qed "` does not occur in it anywhere.
#:
#: The first version of the test below looked for that literal. It passed on a
#: Windows developer machine, where nothing was styled, and failed in all four
#: `check` cells and in `postgres`. The bytes are kept as a fixture because an
#: invented escape sequence would prove only that the regex matches what its
#: author imagined.
CI_HELP_LINE = (
    "\x1b[1m \x1b[0m\x1b[1;33mUsage: \x1b[0m\x1b[1mqed [OPTIONS] COMMAND [ARGS]...\x1b[0m"
)


def plain(text: str) -> str:
    """`text` with terminal styling removed."""
    return ANSI.sub("", text)


def declared_scripts() -> dict[str, str]:
    with (ROOT / "pyproject.toml").open("rb") as handle:
        return dict(tomllib.load(handle)["project"]["scripts"])


def installed_script(name: str) -> Path:
    """The console script as installed in this environment.

    `sysconfig.get_path("scripts")` is where `pip` writes console scripts for
    the interpreter running the test: a virtualenv's `Scripts` or `bin`, and
    for a Windows installation that is not a virtualenv, `Scripts` beside the
    interpreter's own directory rather than inside it. That last case is why
    this does not simply look next to `sys.executable`. In a virtualenv on
    Windows the interpreter and the scripts share one directory, so "beside the
    interpreter" passed locally and failed on the CI runner, where the
    interpreter is `.../x64/python.exe` and its scripts are in
    `.../x64/Scripts/`.

    `PATH` is the last resort rather than the first: a developer's shell may
    not carry the environment's script directory, and a test that skips for
    that reason proves nothing.
    """
    directories = [Path(sysconfig.get_path("scripts")), Path(sys.executable).parent]
    for directory in directories:
        for candidate in (directory / f"{name}.exe", directory / name):
            if candidate.exists():
                return candidate
    on_path = shutil.which(name)
    if on_path:
        return Path(on_path)
    raise AssertionError(
        f"`{name}` is declared in pyproject.toml but is not installed in any of "
        f"{[str(directory) for directory in directories]} and is not on PATH. "
        "Console scripts are generated at install time, so an editable install "
        "made before this entry was added will not have it: `pip install -e .`"
    )


def test_the_normaliser_handles_the_output_ci_actually_produced() -> None:
    """The guard for the guard below.

    Both halves are asserted: that the styled line really does not contain the
    plain string, so the fixture still reproduces the failure, and that it does
    once the styling is stripped.
    """
    assert "Usage: qed [OPTIONS]" not in CI_HELP_LINE
    assert "Usage: qed [OPTIONS]" in plain(CI_HELP_LINE)


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
        assert scripts.get("vqed") == scripts["qed"]

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

        The environment is set rather than inherited. `rich` counts a GitHub
        Actions runner as a terminal, which means it both styles the output and
        folds it at the terminal width, so the width is pinned wide enough that
        the usage line is not wrapped and whatever styling survives `NO_COLOR`
        is stripped before the text is read.
        """
        environment = {
            **os.environ,
            "NO_COLOR": "1",
            "TERM": "dumb",
            "COLUMNS": "200",
        }
        result = subprocess.run(
            [str(installed_script(name)), "--help"],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
            env=environment,
        )
        assert result.returncode == 0, result.stderr
        assert f"Usage: {name} " in plain(result.stdout), result.stdout


# --------------------------------------------------------------------------
# What the package index shows a reader
# --------------------------------------------------------------------------


def pyproject(path: Path) -> dict[str, object]:
    with path.open("rb") as handle:
        return tomllib.load(handle)


#: The two distributions this repository publishes, and the directory each is
#: built from. `readme` and `license-files` both resolve inside that directory,
#: which is why the verifier has its own copies rather than references upwards.
DISTRIBUTIONS = {
    "valqore-qed": ROOT,
    "qed-verify": ROOT / "packages" / "qed-verify",
}

#: Keys PyPI renders as the project page sidebar. `Security` is here because
#: this project asks readers to report vulnerabilities privately and a reader
#: who found one should not have to guess where.
REQUIRED_URLS = ("Homepage", "Documentation", "Source", "Changelog", "Issues", "Security")

#: Hosts a URL in this metadata may point at. A project whose claim is "verify
#: this yourself" should not route a reader through anybody else.
ALLOWED_URL_PREFIXES = (
    "https://github.com/valqore/qed",
    "https://qed.valqore.io",
)


class TestTheProjectPageIsNotBlank:
    """Both PyPI pages were blank through v1.0.0.

    Neither `pyproject.toml` declared `readme`, and neither declared
    `[project.urls]`. So `pypi.org/project/valqore-qed` -- the page a reader
    reaches by searching the name they were told to install -- carried a
    one-line summary, no description and no link back to the source, the
    documentation or the disclosure policy, while `README.md` in this
    repository was the most carefully checked document in the project.

    This is the same shape as the README bug of 2026-10-19: the repository was
    right and the surface a reader actually lands on was not, because nothing
    connected the two. The connection is two keys, and this is the test that
    says they are still there.
    """

    @pytest.mark.parametrize("name", sorted(DISTRIBUTIONS))
    def test_a_readme_is_declared_and_present(self, name: str) -> None:
        directory = DISTRIBUTIONS[name]
        config = pyproject(directory / "pyproject.toml")["project"]
        readme = config.get("readme")  # type: ignore[union-attr]
        assert readme, (
            f"{name} declares no `readme`, so its PyPI page has no body at all. "
            "That page is where a reader who was told to install this arrives."
        )
        path = directory / str(readme)
        assert path.exists(), f"{name} declares readme={readme!r} and the file is not there"
        assert len(path.read_text(encoding="utf-8").strip()) > 400, (
            f"{name}'s readme is too short to tell a reader what this is"
        )

    @pytest.mark.parametrize("name", sorted(DISTRIBUTIONS))
    def test_the_readme_has_no_relative_link(self, name: str) -> None:
        """A README is two documents: a page on GitHub and the body of a page on
        PyPI. A relative link works on the first and 404s on the second.

        `README.md` had fourteen of them -- `SECURITY.md`, `THREAT_MODEL.md`,
        `docs/validation.md`, the license -- so the moment it became the PyPI
        page body it became a page whose every internal link was broken. They
        are absolute now, which is correct on both surfaces; in-page anchors and
        `mailto:` are left alone because they work on both.
        """
        directory = DISTRIBUTIONS[name]
        config = pyproject(directory / "pyproject.toml")["project"]
        readme = directory / str(config["readme"])  # type: ignore[index]
        relative = sorted(
            {
                target
                for target in re.findall(r"\]\(([^)]+)\)", readme.read_text(encoding="utf-8"))
                if not target.startswith(("http://", "https://", "#", "mailto:"))
            }
        )
        assert not relative, (
            f"{name}'s readme links to {relative} relatively. It is the body of the "
            "PyPI project page, where a relative link resolves against pypi.org "
            "and 404s. Use the full https://github.com/valqore/qed/blob/main/... URL."
        )

    @pytest.mark.parametrize("name", sorted(DISTRIBUTIONS))
    def test_every_repository_link_in_the_readme_names_a_file_that_exists(self, name: str) -> None:
        """Absolute links fix the 404 on PyPI and introduce a second way to rot:
        a file renamed here, and a link to `blob/main/` still pointing at the old
        name. This is the check that makes the first fix safe."""
        directory = DISTRIBUTIONS[name]
        config = pyproject(directory / "pyproject.toml")["project"]
        readme = directory / str(config["readme"])  # type: ignore[index]
        missing = []
        for target in re.findall(
            r"https://github\.com/valqore/qed/(?:blob|tree)/main/([^)#\s]+)",
            readme.read_text(encoding="utf-8"),
        ):
            if not (ROOT / target).exists():
                missing.append(target)
        assert not missing, (
            f"{name}'s readme links to files that are not here: {sorted(set(missing))}"
        )

    @pytest.mark.parametrize("name", sorted(DISTRIBUTIONS))
    def test_the_urls_are_declared(self, name: str) -> None:
        config = pyproject(DISTRIBUTIONS[name] / "pyproject.toml")["project"]
        urls = config.get("urls") or {}  # type: ignore[union-attr]
        missing = [key for key in REQUIRED_URLS if key not in urls]
        assert not missing, f"{name} has no {missing} in [project.urls]"

    @pytest.mark.parametrize("name", sorted(DISTRIBUTIONS))
    def test_every_url_points_somewhere_we_own(self, name: str) -> None:
        urls = pyproject(DISTRIBUTIONS[name] / "pyproject.toml")["project"]["urls"]  # type: ignore[index]
        stray = sorted(
            f"{key}={value}"
            for key, value in dict(urls).items()
            if not str(value).startswith(ALLOWED_URL_PREFIXES)
        )
        assert not stray, f"{name} metadata links outside valqore: {stray}"

    @pytest.mark.parametrize("name", sorted(DISTRIBUTIONS))
    def test_every_url_into_this_repository_names_a_file_that_exists(self, name: str) -> None:
        """A `blob/main/SECURITY.md` link survives the file being renamed, as a
        404 on the one page a reader with a vulnerability is reading."""
        urls = pyproject(DISTRIBUTIONS[name] / "pyproject.toml")["project"]["urls"]  # type: ignore[index]
        for key, value in dict(urls).items():
            match = re.fullmatch(
                r"https://github\.com/valqore/qed/(?:blob|tree)/main/(.+)", str(value)
            )
            if match is None:
                continue
            target = ROOT / match.group(1)
            assert target.exists(), f"{name}'s {key} points at {match.group(1)}, which is not here"
