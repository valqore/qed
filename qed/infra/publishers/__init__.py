"""Publishing checkpoints somewhere the instance cannot edit (SPEC §10.4).

A checkpoint is a Merkle root over a range of the chain, signed and appended
like any other record. On its own it proves only that the instance was
internally consistent *at the moment an auditor reads it* — an operator who
rewrote the chain could recompute every root and every signature, and nothing
in the export would say so.

Publishing is what closes that. The root goes somewhere outside the instance's
control and is timestamped by something other than the instance: an S3 bucket
with object-lock, a GCS bucket with a locked retention policy, a signed git tag
in a repository somebody else can read, a file on a volume with a different
retention policy. An auditor then compares the root in the export against the
root that was published, and a rewritten chain fails that comparison.

Three rules that all five implementations follow.

**A failed publication never stops the chain.** A bucket that is unreachable
must not make `qed` stop deciding, so every publisher returns a
:class:`Receipt` with ``ok=False`` instead of raising. What it must not do is
disappear: the failure lands in the ``checkpoints`` table, in the *next*
checkpoint's payload, and in ``GET /v1/status``.

**Receipts go in the next checkpoint, never this one.** A receipt describes a
record that has already been hashed and signed; writing it back into that
record would change the hash the receipt is about. So each checkpoint's payload
carries the previous checkpoint's receipts, and the first one carries none.

**A publisher sees the record, not the chain.** It is handed the serialised
checkpoint record and nothing else — no store, no signer, no payload of any
other record. Publication is an outbound copy of one root; a publisher that
could read the chain would be a second thing to audit.
"""

from __future__ import annotations

from collections.abc import Callable

from qed.core.schemas import EvidenceRecord
from qed.infra.publishers.model import (
    PublicationError,
    Publisher,
    Receipt,
    checkpoint_bytes,
    checkpoint_name,
)

__all__ = [
    "PublicationError",
    "Publisher",
    "Receipt",
    "build_publishers",
    "checkpoint_bytes",
    "checkpoint_name",
    "publish_checkpoint",
]


def build_publishers(specs: list[dict[str, object]]) -> list[Publisher]:
    """Construct the configured publishers (SPEC §16's `evidence.checkpoint`).

    Imported lazily and by name, so an instance with no S3 publisher never
    imports boto3, an instance with no GCS publisher never imports
    google-cloud-storage, and an instance with no git publisher never shells
    out. An unknown type raises: a silently ignored publisher is an anchor the
    operator believes exists.
    """
    from qed.infra.publishers.file import FilePublisher
    from qed.infra.publishers.gcs import GcsRetentionPublisher
    from qed.infra.publishers.git import GitTagPublisher
    from qed.infra.publishers.s3 import S3ObjectLockPublisher
    from qed.remote.anchor import AnchorPublisher

    builders: dict[str, Callable[[dict[str, object]], Publisher]] = {
        "file": FilePublisher.from_config,
        "s3-object-lock": S3ObjectLockPublisher.from_config,
        # The GCP twin of the one above: a locked GCS retention policy is the
        # analogue of object-lock COMPLIANCE. See `publishers/gcs.py`.
        "gcs-retention": GcsRetentionPublisher.from_config,
        "git-tag": GitTagPublisher.from_config,
        # The only publisher that sends anything to a third party, and the only
        # one that does not copy the whole record. See `qed/remote/anchor.py`.
        "qed-anchor": AnchorPublisher.from_config,
    }
    publishers: list[Publisher] = []
    for spec in specs:
        kind = str(spec.get("type", ""))
        builder = builders.get(kind)
        if builder is None:
            raise PublicationError(
                f"unknown checkpoint publisher {kind!r}. The configured ones are: "
                f"{', '.join(sorted(builders))}. A publisher that was ignored because "
                "nobody recognised its name would be an anchor the operator believes "
                "exists."
            )
        options = {key: value for key, value in spec.items() if key != "type"}
        publishers.append(builder(options))
    return publishers


def publish_checkpoint(publishers: list[Publisher], record: EvidenceRecord) -> list[Receipt]:
    """Publish one checkpoint to every configured target.

    Every publisher is tried even after one fails: they are independent
    anchors, and the point of configuring two is that one of them working is
    useful. A publisher that raises anyway -- which the protocol says it will
    not -- is turned into a failed receipt here, because an exception escaping
    this function would stop the maintenance tick and with it the chain.
    """
    receipts: list[Receipt] = []
    for publisher in publishers:
        try:
            receipts.append(publisher.publish(record))
        except Exception as exc:
            receipts.append(
                Receipt(
                    publisher=getattr(publisher, "kind", type(publisher).__name__),
                    target="",
                    ok=False,
                    error=f"the publisher raised instead of returning a receipt: "
                    f"{type(exc).__name__}: {exc}",
                )
            )
    return receipts
