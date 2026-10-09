"""Invariant §1.4.2: `qed.core` imports no network client.

An AST scan, not a runtime check: an import that only happens on one code path
still means the kernel can reach the network, and a kernel that can reach the
network cannot be audited offline.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

CORE = Path(__file__).resolve().parents[2] / "qed" / "core"

FORBIDDEN_ROOTS = frozenset(
    {
        "socket",
        "ssl",
        "selectors",
        "asyncio",
        "httpx",
        "requests",
        "aiohttp",
        "urllib",
        "urllib3",
        "http",
        "httplib2",
        "ftplib",
        "smtplib",
        "telnetlib",
        "websockets",
        "websocket",
        "grpc",
        "paramiko",
        "boto3",
        "botocore",
        "hvac",
        "psycopg",
        "sqlite3",
        "fastapi",
        "uvicorn",
        "starlette",
    }
)


def _module_roots(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            roots.add(node.module.split(".")[0])
    return roots


CORE_FILES = sorted(CORE.rglob("*.py"))


def test_there_are_core_files_to_scan() -> None:
    assert CORE_FILES, "the scan found no files; the path is wrong, not the code"


@pytest.mark.parametrize("path", CORE_FILES, ids=lambda p: p.name)
def test_core_module_imports_nothing_that_can_reach_the_network(path: Path) -> None:
    offenders = _module_roots(path) & FORBIDDEN_ROOTS
    assert not offenders, (
        f"{path.relative_to(CORE.parents[1])} imports {sorted(offenders)}; "
        "I/O belongs in qed.infra, and the decision path must stay pure"
    )
