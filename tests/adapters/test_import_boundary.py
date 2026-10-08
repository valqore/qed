"""Import boundaries for the adapter layer (carried forward from the week 1 review).

The bug this file prevents did not look like a bug. Valqore's
``mcp/gateway.py`` derives blast radius like this:

    verb_blast = _blast_from_tool_name(tool)
    try:
        from valqore.agents.action_intent import normalize
        ...
    except Exception:
        nb, nct = "low", "unknown"

``action_intent`` imports the IaC parser at module level. Move that code into a
tree where the import cannot resolve and the ``except`` swallows the
``ImportError``: no error, no log, and blast radius silently degrades to
matching the tool name. The Phase-0 inventory did not see it because it measured
import isolation with ``sys.modules``, which only reports top-level imports of
modules already loaded.

Two tests, aimed at the two halves of that failure:

1. ``intent.py`` may import nothing outside a fixed allowlist, so there is no
   import that *can* fail.
2. No module on the decision path may wrap an import, or the kernel call, in a
   bare ``except`` that falls through to a default. If the kernel cannot be
   reached the adapter must fail per its configured ``fail_mode`` and write an
   ``ungated_window`` record -- a gap that is recorded, not a gap that is
   guessed over.

An AST scan, not a runtime check: an import on a cold code path still means the
import exists.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
ADAPTERS = ROOT / "gate" / "adapters"
INTENT = ADAPTERS / "mcp" / "intent.py"

#: Everything ``gate/adapters/mcp/intent.py`` is allowed to import. The point is
#: the shortness of this list. Adding to it is a decision, not a detail: each
#: entry is an import that could fail at runtime and take classification with it.
INTENT_ALLOWLIST = frozenset(
    {
        "__future__",
        "dataclasses",
        "typing",
        "regex",
        "gate",  # gate.core.schemas, for the Scope literal
    }
)

#: Modules whose import would mean the classifier had grown a dependency on the
#: thing that caused the original bug.
FORBIDDEN_ANYWHERE_IN_INTENT = frozenset(
    {"json", "tempfile", "pathlib", "subprocess", "importlib", "yaml", "httpx", "mcp"}
)


def module_roots(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            roots.add(node.module.split(".")[0])
    return roots


class TestTheClassifierHasNoImportThatCanFail:
    def test_the_file_is_there_to_scan(self) -> None:
        assert INTENT.is_file(), "the path is wrong, not the code"

    def test_it_imports_only_the_allowlist(self) -> None:
        extra = module_roots(INTENT) - INTENT_ALLOWLIST
        assert not extra, (
            f"gate/adapters/mcp/intent.py imports {sorted(extra)}. Classification must not "
            "depend on anything that can fail to import: that is how Valqore's gateway "
            "silently degraded to tool-name matching. If the import is genuinely needed, "
            "add it to INTENT_ALLOWLIST deliberately."
        )

    @pytest.mark.parametrize("module", sorted(FORBIDDEN_ANYWHERE_IN_INTENT))
    def test_it_does_not_import_the_heavy_modules(self, module: str) -> None:
        assert module not in module_roots(INTENT)

    def test_it_has_no_function_level_imports(self) -> None:
        """A deferred import is the shape the original bug took.

        ``sys.modules`` could not see it, and neither can a reader skimming the
        header.
        """
        tree = ast.parse(INTENT.read_text(encoding="utf-8"), filename=str(INTENT))
        deferred = [
            node.lineno
            for parent in ast.walk(tree)
            if isinstance(parent, ast.FunctionDef | ast.AsyncFunctionDef)
            for node in ast.walk(parent)
            if isinstance(node, ast.Import | ast.ImportFrom)
        ]
        assert not deferred, f"imports inside a function at lines {deferred}"

    def test_it_imports_nothing_from_the_kernel_beyond_the_schema(self) -> None:
        """Classification is the adapter's job; deciding is the kernel's."""
        tree = ast.parse(INTENT.read_text(encoding="utf-8"), filename=str(INTENT))
        gate_modules = {
            node.module
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module and node.module.startswith("gate.")
        }
        assert gate_modules <= {"gate.core.schemas"}, gate_modules

    def test_it_is_importable_with_nothing_else_present(self) -> None:
        """A positive check to go with the structural ones."""
        import importlib
        import sys

        for name in [n for n in sys.modules if n.startswith("gate.adapters")]:
            del sys.modules[name]
        module = importlib.import_module("gate.adapters.mcp.intent")
        assert module.classify("db.drop_table", {}).deletes is True


class TestNoSilentFallbackOnTheDecisionPath:
    """``except Exception: <default>`` is the shape of the original bug."""

    def test_no_adapter_module_swallows_an_import_error(self) -> None:
        offenders: list[str] = []
        for path in sorted(ADAPTERS.rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if not isinstance(node, ast.Try):
                    continue
                imports_in_body = any(
                    isinstance(inner, ast.Import | ast.ImportFrom)
                    for statement in node.body
                    for inner in ast.walk(statement)
                )
                if imports_in_body and any(_is_broad(h) for h in node.handlers):
                    offenders.append(f"{path.relative_to(ROOT)}:{node.lineno}")
        assert not offenders, (
            "an import wrapped in a broad except, with a fallback: "
            f"{offenders}. Let it raise, or catch ImportError and say so out loud."
        )

    def test_a_caught_kernel_failure_is_always_recorded_or_refused(self) -> None:
        """Every broad ``except`` in the proxy must log, record or refuse.

        A handler whose body only assigns a default is the exact bug. This
        checks the weaker, mechanical property: that each handler does
        *something observable*.
        """
        path = ADAPTERS / "mcp" / "proxy.py"
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        silent: list[int] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.ExceptHandler) or not _is_broad(node):
                continue
            if not _mentions_any(
                node, {"logger", "_record_ungated", "_record_result", "_tool_error"}
            ):
                silent.append(node.lineno)
        assert not silent, (
            f"broad except at lines {silent} neither logs, records nor refuses. A caught "
            "failure that only sets a default is invisible, and in shadow mode nothing "
            "would ever reveal it."
        )


def _is_broad(handler: ast.ExceptHandler) -> bool:
    """``except:`` or ``except Exception``/``BaseException``."""
    if handler.type is None:
        return True
    names = [handler.type] if not isinstance(handler.type, ast.Tuple) else handler.type.elts
    return any(
        isinstance(name, ast.Name) and name.id in {"Exception", "BaseException"} for name in names
    )


def _mentions_any(node: ast.AST, names: set[str]) -> bool:
    for inner in ast.walk(node):
        if isinstance(inner, ast.Name) and inner.id in names:
            return True
        if isinstance(inner, ast.Attribute) and inner.attr in names:
            return True
    return False
