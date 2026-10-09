"""Resolving a credential reference to a credential (SPEC §7.2).

Three sources, one interface, and a cache in front of all of them.

Never written anywhere. Not to the chain (which records `upstream_id` and
nothing else), not to a log, and not to disk. The value lives in memory for
at most its TTL and is handed out wrapped in
:class:`qed.core.broker.Secret`, whose every rendering path is redacted.

Vault is an optional extra (`pip install valqore-qed[vault]`). Asking for a
`vault:` reference without it is an error that says so, rather than a stack
trace about a missing module — the operator wrote the config and deserves to
be told what to install.
"""

from __future__ import annotations

from qed.infra.secrets.broker import Brokerage, CredentialBroker
from qed.infra.secrets.resolver import (
    CredentialResolver,
    SecretNotAvailable,
    SecretResolutionError,
)

__all__ = [
    "Brokerage",
    "CredentialBroker",
    "CredentialResolver",
    "SecretNotAvailable",
    "SecretResolutionError",
]
