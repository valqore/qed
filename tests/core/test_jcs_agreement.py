"""The producer and the verifier must canonicalise identically.

`gate.core.jcs` and `gate_verify.jcs` are two implementations on purpose
(see the docstring in the latter). Two implementations only buy independence if
something checks they agree; this is that check.
"""

from __future__ import annotations

import pytest
from gate_verify import jcs as verifier

from gate.core import jcs as producer

CORPUS: list[object] = [
    None,
    True,
    False,
    0,
    1,
    -1,
    2**53 - 1,
    0.0,
    1.0,
    1.5,
    -2.25,
    1e21,
    1e-7,
    1e20,
    0.000001,
    "",
    "plain",
    'a\nb\tc"d\\e',
    "\x00\x1f",
    "Ünïcode ✓",
    "\U0001f600",
    [],
    {},
    [1, "two", None, True],
    {"b": 1, "a": 2, "A": 3},
    {"！": 1, "\U0001f600": 2},
    {"nested": {"deep": [{"x": 1}, {"y": [2, 3]}]}},
    {
        "_assurance": "kernel",
        "_dev": False,
        "_enforcement": "enforcing",
        "_key_id": "ed25519:0123456789abcdef",
        "_mode": "shadow",
        "verdict": {"decision": "BLOCK", "hits": [{"rule_id": "AG-DAT-007"}]},
    },
]


@pytest.mark.parametrize("value", CORPUS, ids=range(len(CORPUS)))
def test_both_implementations_produce_the_same_bytes(value: object) -> None:
    assert producer.dumps(value) == verifier.dumps(value)
    assert producer.sha256_hex(value) == verifier.sha256_hex(value)
