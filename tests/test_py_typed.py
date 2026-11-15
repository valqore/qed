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


#: The files a build of either project needs: its configuration, the `readme`
#: and `license-files` it names, and the package itself.
SUPPORT = ("pyproject.toml", "README.md", "LICENSE", "NOTICE")


def build_wheel(project: Path, package: str, into: Path) -> Path:
    """Copy the project to a scratch directory, build there, return the wheel.

    Two deliberate choices, each made after the obvious version failed in CI.

    **`pip wheel`, not `python -m build`.** `build` is not a dependency of this
    project -- the dev extra is pytest, pytest-asyncio, ruff and mypy -- so the
    first version of this test passed locally, where it happened to be
    installed, and failed every job that runs the full suite. `pip` is always
    present by construction. `--no-build-isolation` keeps it offline: setuptools
    is the build backend and is already installed.

    **A copy, not the working tree.** setuptools stages into `<project>/build/lib`
    and `include-package-data` consults `*.egg-info/SOURCES.txt`, so a build in
    place inherits the previous build's staged files -- which is how the first
    version of this test passed both of its mutations while proving nothing.
    Clearing those caches would fix the measurement and mutate state the
    repository's own editable install and other tests sit on top of. Building a
    copy is hermetic without touching anything shared.
    """
    source = into / "src"
    source.mkdir(parents=True)
    for name in SUPPORT:
        shutil.copy2(project / name, source / name)
    shutil.copytree(
        project / package,
        source / package,
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
    )

    out = into / "wheel"
    subprocess.run(
        [
            sys.executable,
            "-m",
            "pip",
            "wheel",
            "--no-deps",
            "--no-build-isolation",
            "--wheel-dir",
            str(out),
            str(source),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    wheels = sorted(out.glob("*.whl"))
    assert len(wheels) == 1, f"expected one wheel in {out}, got {wheels}"
    return wheels[0]


@pytest.mark.parametrize(
    ("project", "package"),
    DISTRIBUTIONS,
    ids=[package for _, package in DISTRIBUTIONS],
)
def test_the_built_wheel_contains_the_marker(project: Path, package: str, tmp_path: Path) -> None:
    """The assertion a consumer's type checker actually depends on."""
    wheel = build_wheel(project, package, tmp_path)
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
