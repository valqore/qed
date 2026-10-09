"""Backwards-compatible home for ``SqliteStore`` (SPEC §15).

The store moved to :mod:`qed.infra.storage.store` in week 6 when it gained a
second backend, and it kept its name here because fifteen modules import it
from this path and a rename across all of them would have been churn with no
reader benefit.
"""

from __future__ import annotations

from qed.infra.storage.store import ChainIntegrityError, Checkpoint, SqliteStore, SqlStore

__all__ = ["ChainIntegrityError", "Checkpoint", "SqlStore", "SqliteStore"]
