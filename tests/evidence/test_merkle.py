"""Merkle roots (SPEC §10.4)."""

from __future__ import annotations

import hashlib

import pytest
from qed_verify.verify import _merkle_root as verifier_root

from qed.core.evidence.merkle import merkle_root, merkle_root_bytes

H = [hashlib.sha256(bytes([i])).hexdigest() for i in range(8)]


def test_single_leaf_is_its_own_root() -> None:
    assert merkle_root([H[0]]) == H[0]


def test_two_leaves() -> None:
    expected = hashlib.sha256(bytes.fromhex(H[0]) + bytes.fromhex(H[1])).hexdigest()
    assert merkle_root(H[:2]) == expected


def test_odd_level_duplicates_the_last_leaf() -> None:
    three = merkle_root(H[:3])
    four = merkle_root([H[0], H[1], H[2], H[2]])
    assert three == four


def test_order_matters() -> None:
    assert merkle_root(H[:4]) != merkle_root([H[1], H[0], H[2], H[3]])


def test_changing_one_leaf_changes_the_root() -> None:
    altered = [*H[:7], hashlib.sha256(b"different").hexdigest()]
    assert merkle_root(H) != merkle_root(altered)


def test_empty_input_is_refused() -> None:
    with pytest.raises(ValueError, match="at least one"):
        merkle_root([])


def test_bytes_and_hex_helpers_agree() -> None:
    assert merkle_root_bytes([bytes.fromhex(h) for h in H]).hex() == merkle_root(H)


@pytest.mark.parametrize("count", list(range(1, 9)))
def test_verifier_agrees_with_the_producer(count: int) -> None:
    assert merkle_root(H[:count]) == verifier_root(H[:count])
