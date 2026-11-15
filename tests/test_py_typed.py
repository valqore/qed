"""Both wheels carry PEP 561's marker, checked in the built artifact.

`qed` is fully annotated and `mypy --strict` passes over it in this
repository. None of that reaches a consumer: without a `py.typed` file *inside
the wheel*, a project that installs `valqore-qed` and runs `mypy --strict`
gets ``error: Skipping analyzing "qed.core.jcs": module is installed, but
missing library stubs or py.typed marker`` on every import, and its only
recourse is a blanket ignore that also hides its own mistakes.

Found by `valqore-attest`, the first real downstream consumer: it imports
`qed.core.jcs` for RFC 8785 canonicalisation so the two tools cannot disagree
about what a digest covers, and that one import was the whole untyped surface
of a strict codebase. Nothing in this repository could have noticed, because
every check here reads the source tree, where the annotations are present and
the marker is irrelevant.

Which is why this test **builds the wheels and looks inside them**. The lesson
it is written against is one this project has already paid for twice: a
repository guard cannot see a property of the artefact. `package-data` was
checked against the filesystem for eight weeks while ten catalogue files were
absent from the wheel, because `fnmatch`'s ``*`` crosses a path separator and
setuptools' does not. A declaration in `pyproject.toml` is a claim about the
wheel, not the wheel.

`tests/test_packaging.py` still checks the declaration, and it earned its keep
here: it failed the moment `qed/py.typed` existed and was not yet declared.
The two tests are different questions -- *is it declared* and *is it in the
artefact* -- and only the second is what a consumer experiences.

One correction worth recording, because it was measured rather than assumed.
The `package-data` entry turns out **not** to be what makes the marker ship: a
build from a completely clean tree with the entry removed still puts
`qed/py.typed` in the wheel, because setuptools defaults
`include-package-data` to true for a pyproject-configured project and its file
finder reaches inside the package directory. The entry is kept anyway, since
this repository's convention is that every shipped data file is declared, and
`test_packaging.py` enforces that. But the honest mutation for *this* test is
deleting the file, not the declaration -- and the first version of this test
was mutation-tested the wrong way round, passing twice while proving nothing.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

#: (project directory, the import package inside the wheel).
DISTRIBUTIONS = (
    (ROOT, "qed"),
    (ROOT / "packages" / "qed-verify", "qed_verify"),
)


def build_wheel(project: Path, into: Path) -> Path:
    """Build one wheel and return its path.

    `--no-isolation` keeps this to seconds: the build dependencies are already
    in the test environment, and downloading setuptools into a fresh venv twice
    would make an otherwise trivial check the slowest thing in the suite.

    **`build/lib` is cleared first, and that is not tidiness.** setuptools
    stages files into `<project>/build/lib` and reuses what is already there, so
    a wheel built after an earlier build inherits the earlier build's staged
    files. The first version of this test passed both of its mutations because
    of exactly that: `py.typed` was removed from `package-data`, the wheel was
    rebuilt, and the marker was still in it -- staged by the previous, correct
    build. A guard reading contaminated state is worse than no guard, because
    it reports the answer you were hoping for.
    """
    # Two caches, not one. `build/lib` stages the files that go into the
    # wheel, and `*.egg-info/SOURCES.txt` is what `include-package-data`
    # consults -- which is on by default for a pyproject-configured project.
    # Leaving either in place makes this test report the previous build.
    for stale in (project / "build" / "lib", *project.glob("*.egg-info")):
        if stale.exists():
            shutil.rmtree(stale)

    subprocess.run(
        [
            sys.executable,
            "-m",
            "build",
            "--wheel",
            "--no-isolation",
            "--outdir",
            str(into),
            str(project),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    wheels = sorted(into.glob("*.whl"))
    assert len(wheels) == 1, f"expected one wheel in {into}, got {wheels}"
    return wheels[0]


@pytest.mark.parametrize(
    ("project", "package"),
    DISTRIBUTIONS,
    ids=[package for _, package in DISTRIBUTIONS],
)
def test_the_built_wheel_contains_the_marker(project: Path, package: str, tmp_path: Path) -> None:
    """The assertion a consumer's type checker actually depends on."""
    wheel = build_wheel(project, tmp_path / package)
    with zipfile.ZipFile(wheel) as archive:
        names = set(archive.namelist())

    marker = f"{package}/py.typed"
    assert marker in names, (
        f"{wheel.name} does not contain {marker}, so `mypy --strict` in any"
        f" project installing it reports import-untyped on every {package}"
        f" import. What makes it ship is the file existing in the package"
        f" directory; the package-data entry is this repository's own"
        f" explicitness convention, enforced separately by"
        f" tests/test_packaging.py. This is the check that sees the artefact."
    )


@pytest.mark.parametrize(
    ("project", "package"),
    DISTRIBUTIONS,
    ids=[package for _, package in DISTRIBUTIONS],
)
def test_the_marker_is_in_the_source_tree_too(project: Path, package: str) -> None:
    """A wheel is built from the tree, so the tree is where it has to exist."""
    assert (project / package / "py.typed").is_file()


def test_the_marker_is_empty() -> None:
    """PEP 561 defines `py.typed` as a marker, not a file with contents.

    A partial-stub package writes `partial\\n` into it, which changes how a
    checker treats missing submodules. This package is not partial, so the file
    is empty and that is asserted rather than assumed -- an editor saving a
    stray byte here would quietly change what consumers resolve.
    """
    for project, package in DISTRIBUTIONS:
        assert (project / package / "py.typed").read_bytes() == b""
