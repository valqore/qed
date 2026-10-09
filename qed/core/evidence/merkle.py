"""Merkle roots for checkpoints (SPEC §10.4).

Binary tree over the ``hash`` of every record since the previous checkpoint.
When a level has an odd number of nodes the last one is duplicated. Leaves are
the record hashes as raw bytes; interior nodes are ``sha256(left || right)``.

Duplicating the last leaf is the well-known second-preimage shape, so the
interior concatenation is domain-separated from the leaves by construction: a
leaf is a record hash (itself already a domain-separated SPEC §10.2 digest over
0x1F-joined fields) and never a bare concatenation.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence

__all__ = ["merkle_root", "merkle_root_bytes"]


def merkle_root_bytes(leaves: Sequence[bytes]) -> bytes:
    if not leaves:
        raise ValueError("a checkpoint needs at least one record")
    level = list(leaves)
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [hashlib.sha256(level[i] + level[i + 1]).digest() for i in range(0, len(level), 2)]
    return level[0]


def merkle_root(leaf_hashes_hex: Sequence[str]) -> str:
    """Root over hex-encoded record hashes, returned as hex."""
    return merkle_root_bytes([bytes.fromhex(h) for h in leaf_hashes_hex]).hex()
