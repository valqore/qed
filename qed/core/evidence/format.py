"""Evidence-format constants (ADR-0006).

Everything here ends up inside a hash input or inside the signed genesis
payload, so changing a value changes the format: chains written before the
change verify only against the old value. That is a format version bump, not a
rename.

For that reason none of these strings carries the product name. The product is
still looking for its final name (SPEC §24.1), and a brand that appears in a
hash domain separator turns a marketing decision into an evidence-compatibility
decision. The brand belongs in places that are *not* hashed -- the OSCAL
``generator`` prop, the CLI name, the distribution name on PyPI.

``tests/evidence/test_format_constants.py`` pins the exact bytes and the
resulting digests, so any change to them is a visible, deliberate diff.
"""

from __future__ import annotations

from typing import Final

__all__ = ["CHAIN_FORMAT", "GENESIS_DOMAIN", "PRINCIPAL_DOMAIN"]

#: Identifier of the evidence chain format. Recorded in the genesis payload and
#: exported as the OSCAL ``chain-format`` prop. Bump the number for a breaking
#: change to the record construction, never for a rename.
CHAIN_FORMAT: Final = "evidence-chain/1"

#: Domain separator for the genesis ``prev_hash``. Binds a chain to one instance
#: identity, so two instances cannot splice their chains together.
GENESIS_DOMAIN: Final = f"{CHAIN_FORMAT}:genesis:"

#: Domain separator for principal hashes. Without one, a principal hash and some
#: other sha256 of the same string would collide across uses.
PRINCIPAL_DOMAIN: Final = f"{CHAIN_FORMAT}:principal:"
