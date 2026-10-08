"""Deterministic blast-radius score, 0–100 (SPEC §5).

SPEC §5 says to port this from Valqore ``governance/blast_radius.py``. It is
written fresh instead. That module is a Kubernetes dependency-graph analyser
(Service→Deployment selectors, PDB, HPA, NetworkPolicy); with the Kubernetes
parts removed nothing remains, and its ``blast_radius`` is a *count of affected
resources* while this one is a *risk score* on a fixed 0–100 scale that ADR-008
thresholds at 60. Same name, different unit.
See ``docs/adr/0001-blast-radius-table.md`` and ``docs/blast-radius.md``.

The score is a pure function of the proposal. It never reads the network, a
cluster or a clock. Each contribution is additive and the total is clamped, so
the table can be read top to bottom and audited by hand.
"""

from __future__ import annotations

from typing import Final

import regex

from gate.core.schemas import ActionKind, ActionProposal

__all__ = ["BLAST_TABLE_VERSION", "explain", "score"]

BLAST_TABLE_VERSION = "1.0"

_SCOPE_BASE: Final[dict[str, int]] = {
    "single_resource": 10,
    "multi_resource": 30,
    "account": 60,
    "global": 80,
}

_ENVIRONMENT_BONUS: Final[dict[str, int]] = {"dev": 0, "staging": 5, "prod": 15}

_KIND_BONUS: Final[dict[ActionKind, int]] = {
    ActionKind.shell: 10,
    ActionKind.skill: 5,
    ActionKind.mcp_tool: 0,
    ActionKind.http: 0,
    ActionKind.custom: 0,
}

_WRITES_BONUS: Final = 10
_DELETES_BONUS: Final = 25


def _words(*terms: str) -> str:
    """Build an alternation that treats ``_`` as a word separator.

    Plain ``\\b`` is wrong for this domain. Tool and resource names are written
    ``terminate_instances``, ``GITHUB_TOKEN``, ``delete_repo``; since ``_`` is a
    word character, ``\\bterminate\\b`` does not match ``terminate_instances``
    and the score silently misses the most common naming style in the data it
    scores. A trailing ``(?=\\b|_)`` keeps ``dropbox`` from matching ``drop``.
    """
    alternation = "|".join(terms)
    return rf"(?i)(?:\b|_)(?:{alternation})(?=\b|_)"


#: Names, targets or parameters that touch the control plane itself.
_SENSITIVE = regex.compile(
    _words(
        "iam",
        "secret",
        "secrets",
        "credential",
        "credentials",
        "password",
        "kms",
        "keyring",
        "policy",
        "policies",
        "role",
        "roles",
        "rolebinding",
        "serviceaccount",
        "token",
        "mfa",
        "sso",
        "audit",
        "cloudtrail",
        "logging",
        "billing",
    )
)
_SENSITIVE_BONUS: Final = 15

#: Verbs that are irreversible or wide in effect.
_DESTRUCTIVE = regex.compile(
    _words(
        "drop",
        "truncate",
        "delete",
        "destroy",
        "terminate",
        "purge",
        "wipe",
        "revoke",
        "disable",
        "detach",
        "remove",
        "kill",
    )
    + r"|(?i)(force[-_ ]?push|rm\s+-[a-z]*[rf])"
)
_DESTRUCTIVE_BONUS: Final = 15

_MAX: Final = 100

#: Cap on how much parameter text is scanned, so the score stays O(1)-ish and a
#: 16 KB body cannot turn scoring into the slowest part of a decision.
_PARAMS_SCAN_LIMIT: Final = 4096


def _params_text(proposal: ActionProposal) -> str:
    """Flatten the string values of ``params_redacted`` into one haystack.

    Looking only at ``action.name`` and ``action.target`` is the trap that made
    Valqore's MCP gateway score a tool called ``execute_sql`` carrying
    ``DROP TABLE`` as low risk. The redacted parameters are deterministic data
    the kernel already has, so the score reads them too.
    """
    params = proposal.action.params_redacted
    if not params:
        return ""
    pieces: list[str] = []
    budget = _PARAMS_SCAN_LIMIT

    def walk(value: object, depth: int) -> None:
        nonlocal budget
        if budget <= 0 or depth > 6:
            return
        if isinstance(value, str):
            chunk = value[:budget]
            pieces.append(chunk)
            budget -= len(chunk)
        elif isinstance(value, dict):
            for key, item in value.items():
                walk(str(key), depth + 1)
                walk(item, depth + 1)
        elif isinstance(value, list | tuple):
            for item in value:
                walk(item, depth + 1)

    walk(params, 0)
    return " ".join(pieces)


def explain(proposal: ActionProposal) -> list[tuple[str, int]]:
    """Return the ordered (reason, points) contributions. Used by ``policy explain``."""
    action, context = proposal.action, proposal.context
    hints = context.blast_radius_hints
    identifiers = f"{action.name} {action.target}"
    params = _params_text(proposal)

    parts: list[tuple[str, int]] = [
        (f"scope={hints.scope}", _SCOPE_BASE[hints.scope]),
        (f"environment={context.environment}", _ENVIRONMENT_BONUS[context.environment]),
    ]
    if _KIND_BONUS[action.kind]:
        parts.append((f"kind={action.kind.value}", _KIND_BONUS[action.kind]))
    if hints.writes:
        parts.append(("writes", _WRITES_BONUS))
    if hints.deletes:
        parts.append(("deletes", _DELETES_BONUS))

    # Each signal is counted once, whether it was found in the identifiers or in
    # the parameters, so a verb that appears in both does not score twice.
    if _SENSITIVE.search(identifiers):
        parts.append(("touches identity/secrets/audit surface", _SENSITIVE_BONUS))
    elif params and _SENSITIVE.search(params):
        parts.append(("identity/secrets/audit surface named in parameters", _SENSITIVE_BONUS))

    if _DESTRUCTIVE.search(identifiers):
        parts.append(("destructive verb in name or target", _DESTRUCTIVE_BONUS))
    elif params and _DESTRUCTIVE.search(params):
        parts.append(("destructive verb in parameters", _DESTRUCTIVE_BONUS))
    return parts


def score(proposal: ActionProposal) -> int:
    """Blast-radius score in 0–100."""
    total = sum(points for _, points in explain(proposal))
    return min(total, _MAX)
