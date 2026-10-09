"""Chain maintenance: checkpoint, publish, purge (SPEC §10.4, §10.6).

Three jobs that nothing was doing. Each has a threshold in the spec and each
had an implementation with no caller: `writer.checkpoint()` was reachable only
from `qed checkpoint`, publishers did not exist, and `apply_retention` was
written in the previous commit with nothing to invoke it.

They belong together because they are the same job — advancing the chain's
housekeeping — and because they must happen in this order:

1. **checkpoint**, which fixes a Merkle root over everything since the last one;
2. **publish** that root, which is what makes it an anchor rather than a
   number inside the thing it summarises;
3. **purge** expired payloads, which is safe only once the records are covered
   by a published root. Purging first would leave a window in which the
   payloads were gone and nothing outside the instance had attested to the
   hashes they produced.

**One writer.** Everything here appends to the chain, so the caller must be the
only writer: the leader on the HA path, the single process on SQLite. The
functions do not check — "am I the only writer" is not a question a writer can
answer about itself — which is why the only callers are the maintenance loop
and the CLI.

**Nothing here raises.** A maintenance pass that threw would stop the loop,
and a stopped loop is a chain that quietly never checkpoints again. Failures
come back in the result and are logged.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime

from qed.core.schemas import EvidenceRecord, utcnow
from qed.infra.publishers import Receipt, build_publishers, publish_checkpoint
from qed.infra.publishers.model import PublicationError, Publisher

__all__ = ["MaintenanceResult", "maintain", "publishers_for"]

logger = logging.getLogger("qed.maintenance")


@dataclass
class MaintenanceResult:
    """What one pass did. All-zero when there was nothing due."""

    checkpoint: EvidenceRecord | None = None
    receipts: list[Receipt] = field(default_factory=list)
    purged: int = 0
    #: Something went wrong that an operator should see. Never raised, because
    #: a maintenance pass that threw would stop the loop, and a stopped loop
    #: is a chain that quietly never checkpoints again.
    errors: list[str] = field(default_factory=list)

    @property
    def acted(self) -> bool:
        return self.checkpoint is not None or self.purged > 0

    def summary(self) -> dict[str, object]:
        return {
            "checkpointed": None if self.checkpoint is None else self.checkpoint.seq,
            "published": [receipt.as_payload() for receipt in self.receipts],
            "purged": self.purged,
            "errors": list(self.errors),
        }


def publishers_for(config: object) -> tuple[list[Publisher], list[str]]:
    """Build the configured publishers, reporting a bad config rather than raising.

    A misconfigured publisher is an operator error and should be loud, but it
    must not take the chain down: the instance can still decide, record and
    checkpoint with no anchor, and that state is strictly better than one that
    refuses to start. So it returns the error for `/readyz` and `qed doctor` to
    carry.
    """
    from qed.config import QedConfig

    assert isinstance(config, QedConfig)
    if not config.evidence.checkpoint.publishing:
        return [], []
    try:
        return build_publishers(config.evidence.checkpoint.publishers), []
    except PublicationError as exc:
        return [], [str(exc)]


def maintain(
    session: object,
    *,
    now: datetime | None = None,
    force_checkpoint: bool = False,
) -> MaintenanceResult:
    """One maintenance pass. The caller must be the chain's only writer."""
    from qed.runtime import Session, apply_retention

    assert isinstance(session, Session)
    stamp = now if now is not None else utcnow()
    result = MaintenanceResult()

    publishers, problems = publishers_for(session.config)
    result.errors.extend(problems)

    # 1 -- checkpoint, if one is due.
    try:
        result.checkpoint = session.writer.checkpoint(force=force_checkpoint, now=stamp)
    except Exception as exc:
        result.errors.append(f"checkpoint failed: {type(exc).__name__}: {exc}")
        logger.exception("checkpoint failed")

    # 2 -- publish it. Only the new one: a failed publication from an earlier
    # checkpoint is retried by the next checkpoint's own publication, not by
    # re-publishing a root an anchor may already hold under the same name.
    if result.checkpoint is not None and publishers:
        result.receipts = publish_checkpoint(publishers, result.checkpoint)
        # Keyed on `to_seq`, which is the `checkpoints` row's primary key --
        # not on the checkpoint record's own seq, which is one higher.
        payload = result.checkpoint.payload or {}
        covered = payload.get("to_seq")
        session.store.record_publication(
            seq_to=covered if isinstance(covered, int) else result.checkpoint.seq,
            receipts=[receipt.as_payload() for receipt in result.receipts],
        )
        for receipt in result.receipts:
            if not receipt.ok:
                result.errors.append(f"{receipt.publisher}: {receipt.error}")
                logger.error("checkpoint publication failed: %s", receipt.error)

    # 3 -- purge, last. Records covered by a published root can lose their
    # payloads without losing the attestation that their hashes existed;
    # purging first would open a window where neither was true.
    try:
        retention = apply_retention(session, now=stamp)
        result.purged = retention.purged
    except Exception as exc:
        result.errors.append(f"retention failed: {type(exc).__name__}: {exc}")
        logger.exception("retention failed")

    if result.acted:
        logger.info("maintenance: %s", result.summary())
    return result
