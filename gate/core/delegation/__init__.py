"""Delegation: tokens, actor chains, narrowing (SPEC §6).

Pure. This package decides whether a presented token is acceptable and what
principal it stands for. It never fetches a key, never calls an issuer and
never reads a clock of its own — the caller passes the key and the time in, the
same way the policy engine takes its context. Fetching and caching JWKS is
:mod:`gate.infra.jwks`.

The split matters more here than elsewhere. A token layer that can reach the
network is a token layer that behaves differently when the network is down, and
an air-gapped install has to make the same decisions as a connected one.
"""

from __future__ import annotations

from gate.core.delegation.claims import (
    ChainTooDeep,
    DelegationError,
    NarrowingViolation,
    TokenClaims,
    TokenVerificationError,
    flatten_actor_chain,
    narrows_from,
    principal_from,
    validate_claims,
)

__all__ = [
    "ChainTooDeep",
    "DelegationError",
    "NarrowingViolation",
    "TokenClaims",
    "TokenVerificationError",
    "flatten_actor_chain",
    "narrows_from",
    "principal_from",
    "validate_claims",
]
