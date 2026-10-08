"""No package in this repository may shadow a standard-library module.

This is here because it already happened. The HTTP forward proxy arrived as
``gate/adapters/http/`` with its tests in ``tests/adapters/http/``, and every
test that ran ``python tests/adapters/upstream_server.py`` as a subprocess
started failing with::

    File ".../starlette/exceptions.py", line 3, in <module>
        import http.client
    ModuleNotFoundError: No module named 'http.client'

Running a file puts its own directory at the front of ``sys.path``, so
``tests/adapters/http/`` became *the* ``http`` package for that process and
the standard library's disappeared. The failure surfaced three imports deep
inside a third-party library, nowhere near the directory that caused it,
which is what makes this worth a test rather than a note: the error never
mentions the shadowing package.

The packages are now ``http_proxy``. The check is mechanical so that the next
plausible name -- ``json``, ``types``, ``select``, ``email``, ``logging`` --
is caught when somebody creates the directory rather than a week later.

Two names predate this test and are kept
----------------------------------------

``gate/infra/secrets`` and ``gate/api/routers/token.py`` are both named in
GATE_SPEC (§7 and §12.6), and ``secrets`` is the right word for what that
module does. They are safe for one specific reason: nothing in either
directory is ever executed as a file, so neither directory reaches
``sys.path``. :func:`test_an_allowed_name_still_has_no_runnable_script` holds
that reason in place -- add a ``__main__`` guard beside either of them and
this test starts failing again, which is the point of writing the exemption
as a condition rather than a list.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

#: Where a shadowing name would do damage: anywhere a file might be run from.
SEARCHED = ("gate", "tests", "packages")

STDLIB = frozenset(sys.stdlib_module_names)

#: Paths, relative to the repository root, whose stdlib name is deliberate.
#: Every entry needs a reason in the module docstring above, and stays valid
#: only while the directory holds nothing runnable.
ALLOWED = {
    Path("gate/infra/secrets"),
    Path("gate/api/routers/token.py"),
}


def _allowed(path: Path) -> bool:
    return path.relative_to(ROOT) in ALLOWED


def directories() -> list[Path]:
    found: set[Path] = set()
    for top in SEARCHED:
        base = ROOT / top
        if not base.is_dir():
            continue
        found.update(
            path
            for path in base.rglob("*")
            if path.is_dir() and not path.name.startswith((".", "__"))
        )
    return sorted(found)


DIRECTORIES = directories()


def test_there_are_directories_to_scan() -> None:
    assert DIRECTORIES, "the scan found nothing; the path is wrong, not the code"


@pytest.mark.parametrize("path", DIRECTORIES, ids=lambda p: p.name)
def test_no_directory_shadows_a_standard_library_module(path: Path) -> None:
    if _allowed(path):
        pytest.skip("deliberate; see the module docstring")
    assert path.name not in STDLIB, (
        f"{path.relative_to(ROOT)} shadows the standard library module "
        f"{path.name!r}. Any Python file run from its parent directory gets "
        f"this package instead of the real {path.name}, and the error will "
        f"surface somewhere else entirely. Rename it ({path.name}_proxy, "
        f"{path.name}_support, ...)."
    )


@pytest.mark.parametrize("path", DIRECTORIES, ids=lambda p: p.name)
def test_no_module_shadows_a_standard_library_module(path: Path) -> None:
    """The same hazard one level down: a file rather than a directory.

    ``tests/adapters/json.py`` would be imported by anything run from that
    directory that does ``import json``, including the libraries it imports.
    """
    offenders = sorted(
        module.name
        for module in path.glob("*.py")
        if module.stem in STDLIB and module.stem != "__init__" and not _allowed(module)
    )
    assert not offenders, (
        f"{path.relative_to(ROOT)} contains {offenders}, which shadow standard "
        "library modules for anything run from that directory."
    )


@pytest.mark.parametrize("allowed", sorted(ALLOWED), ids=str)
def test_an_allowed_name_still_has_no_runnable_script(allowed: Path) -> None:
    """The exemption is conditional, and this is the condition.

    A stdlib name is harmless only while its directory never lands on
    ``sys.path``, which means nothing beside it is ever run as a file.
    """
    target = ROOT / allowed
    assert target.exists(), f"{allowed} is gone; drop it from ALLOWED"
    directory = target if target.is_dir() else target.parent
    runnable = [
        path.name
        for path in sorted(directory.glob("*.py"))
        if '__name__ == "__main__"' in path.read_text(encoding="utf-8")
    ]
    assert not runnable, (
        f"{allowed} keeps its standard-library name only because nothing in "
        f"{directory.relative_to(ROOT)} is run as a file, and {runnable} now is. "
        "Rename the package or move the script."
    )
