"""Credential broker (SPEC §7, ADR-001).

The idea in one sentence: **the agent never holds the credential**. It asks
the gate to do something; the gate decides; and if the answer is yes, the gate
attaches the credential on the way out. An agent that cannot read a token
cannot leak one, cannot be tricked into pasting one, and cannot keep using one
after its mandate is revoked.

That is also the difference between a gate and a linter. A linter tells you
the action was unwise. A broker means the action was not possible.

This package is the pure half: which upstream an action belongs to, and what
would be injected. Resolving the secret is :mod:`gate.infra.secrets`, because
reading Vault is I/O and the decision path must stay replayable.
"""

from __future__ import annotations

from gate.core.broker.model import (
    CredentialSpec,
    Enforcement,
    InjectSpec,
    Match,
    Secret,
    Upstream,
    UpstreamSet,
    describe,
    match_upstream,
)

__all__ = [
    "CredentialSpec",
    "Enforcement",
    "InjectSpec",
    "Match",
    "Secret",
    "Upstream",
    "UpstreamSet",
    "describe",
    "match_upstream",
]
