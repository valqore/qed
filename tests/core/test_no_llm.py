"""Invariant §1.4.1: no model SDK anywhere in `gate.core`.

Explanations may be model-generated in `gate.explain.*`. The engine must never
be able to consult one, because a decision an auditor cannot replay is not
evidence of anything.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from tests.core.test_no_network import CORE, CORE_FILES, _module_roots

FORBIDDEN_ROOTS = frozenset(
    {
        "anthropic",
        "openai",
        "cohere",
        "mistralai",
        "google",
        "litellm",
        "ollama",
        "llama_cpp",
        "transformers",
        "torch",
        "langchain",
        "langchain_core",
        "langgraph",
        "crewai",
        "sentence_transformers",
    }
)


@pytest.mark.parametrize("path", CORE_FILES, ids=lambda p: p.name)
def test_core_module_imports_no_model_sdk(path: Path) -> None:
    offenders = _module_roots(path) & FORBIDDEN_ROOTS
    assert not offenders, f"{path.name} imports {sorted(offenders)}"


def test_no_core_module_mentions_a_model_call() -> None:
    """Catches the shape an import scan misses: a lazily resolved client."""
    suspicious = ("messages.create", "chat.completions", "generate_content", "invoke_model")
    hits: list[str] = []
    for path in CORE_FILES:
        text = path.read_text(encoding="utf-8")
        tree = ast.parse(text, filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute):
                rendered = ast.unparse(node)
                hits += [
                    f"{path.relative_to(CORE)}: {rendered}"
                    for pattern in suspicious
                    if pattern in rendered
                ]
    assert not hits, hits
