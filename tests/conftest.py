"""Shared fixtures.

The proposal builder works by deep-merging a patch into one base proposal. That
keeps a golden case down to the two or three fields it is actually about, which
makes a 60-case table readable instead of 60 pages of JSON.
"""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

import pytest

from qed.core.policy.loader import baseline_pack_dir, load_bundle
from qed.core.policy.model import PolicyBundle
from qed.core.schemas import ActionProposal, BudgetState, Decision, EvalContext
from qed.infra.keys.file import FileSigner

NOW = "2026-10-07T12:00:00.000Z"

BASE_PROPOSAL: dict[str, Any] = {
    "schema_version": "1.0",
    "id": "01JB0000000000000000000000",
    "ts": NOW,
    "principal": {
        "token_jti": "01JB000000000000000000JTI0",
        "human_hash": "a" * 64,
        "agent_chain": ["claude-code@laptop-test"],
        "mandate_id": None,
        "client_fingerprint": None,
    },
    "action": {
        "kind": "mcp_tool",
        "name": "github.list_issues",
        "target": "repo:acme/payments",
        "params_hash": "0" * 64,
        "params_redacted": None,
        "method": None,
    },
    "context": {
        "environment": "dev",
        "tags": [],
        "adapter": "mcp-proxy/0.1.0",
        "adapter_id": "adp_test",
        "enforcement": "enforcing",
        "mode": "enforce",
        "cost_estimate": {"tokens": 0, "money_cents": 0, "currency": "USD", "known": True},
        "blast_radius_hints": {"writes": False, "deletes": False, "scope": "single_resource"},
        "intent": None,
        "summary": "test proposal",
    },
}


def deep_merge(base: dict[str, Any], patch: dict[str, Any]) -> dict[str, Any]:
    out = copy.deepcopy(base)
    for key, value in patch.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = deep_merge(out[key], value)
        else:
            out[key] = copy.deepcopy(value)
    return out


def make_proposal(patch: dict[str, Any] | None = None) -> ActionProposal:
    return ActionProposal.model_validate(deep_merge(BASE_PROPOSAL, patch or {}))


@pytest.fixture
def proposal() -> ActionProposal:
    return make_proposal()


@pytest.fixture(scope="session")
def baseline_bundle() -> PolicyBundle:
    result = load_bundle([baseline_pack_dir()])
    assert result.ok, [f.format() for f in result.errors]
    return result.bundle


@pytest.fixture
def ctx() -> EvalContext:
    return EvalContext(now=NOW)


@pytest.fixture
def budget() -> BudgetState:
    return BudgetState(token_jti=BASE_PROPOSAL["principal"]["token_jti"])


@pytest.fixture
def signer() -> FileSigner:
    return FileSigner.generate()


@pytest.fixture
def qed_dir(tmp_path: Path) -> Path:
    from qed.infra.keys.file import init_keys

    directory = tmp_path / "qed"
    init_keys(directory)
    return directory


ALLOW = Decision.ALLOW
BLOCK = Decision.BLOCK
APPROVE = Decision.REQUIRE_APPROVAL
