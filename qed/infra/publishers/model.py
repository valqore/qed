"""The publisher seam: what every target has in common (SPEC §10.4).

Small on purpose. A publisher is handed one serialised checkpoint record and
answers with a receipt; everything else — when to publish, what to do with the
receipt, how to report a failure — belongs to the caller.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Protocol, runtime_checkable

from qed.core.schemas import EvidenceRecord, rfc3339_ms, utcnow

__all__ = [
    "PublicationError",
    "Publisher",
    "Receipt",
    "checkpoint_bytes",
    "checkpoint_name",
]


class PublicationError(RuntimeError):
    """A publisher is misconfigured.

    Distinct from a publication that *failed*: a failure is a receipt with
    ``ok=False`` and the chain carries on, while this is raised at
    construction, where an operator can still fix it. A bucket name that is
    absent from the config is not something to discover at the first
    checkpoint.
    """


@dataclass(frozen=True)
class Receipt:
    """What came back from publishing one checkpoint.

    Stored in the ``checkpoints`` table and copied into the *next*
    checkpoint's payload. A receipt in the chain is the durable part: the
    table can be restored from a backup, and the chain cannot.
    """

    publisher: str
    #: Where it went, in whatever form that target names things: a path, an
    #: ``s3://`` URL, a tag name.
    target: str
    ok: bool
    at: datetime = field(default_factory=utcnow)
    #: Whatever the target gave back that an auditor can check the copy with --
    #: an ETag, a version id, an object-lock retain-until date, a commit sha.
    #: This is the half that makes a receipt worth storing.
    proof: dict[str, object] = field(default_factory=dict)
    #: Why it failed, when it did. Never a stack trace, and never a credential:
    #: the message goes into the chain and into `qed status`.
    error: str = ""

    def as_payload(self) -> dict[str, object]:
        """The form that goes into a checkpoint payload and the store."""
        document: dict[str, object] = {
            "publisher": self.publisher,
            "target": self.target,
            "ok": self.ok,
            "at": rfc3339_ms(self.at),
        }
        if self.proof:
            document["proof"] = dict(sorted(self.proof.items()))
        if self.error:
            document["error"] = self.error
        return document


@runtime_checkable
class Publisher(Protocol):
    """One anchor target."""

    #: The `type` in the config, and what appears in a receipt.
    kind: str

    @classmethod
    def from_config(cls, options: dict[str, object]) -> Publisher:
        """Build from the config block, or raise :class:`PublicationError`."""
        ...

    def publish(self, record: EvidenceRecord) -> Receipt:
        """Copy the checkpoint out. Returns a receipt; does not raise."""
        ...

    def describe(self) -> str:
        """One line for `qed doctor`, with no credential in it."""
        ...


def checkpoint_name(record: EvidenceRecord) -> str:
    """A stable, sortable name for one published checkpoint.

    ``qed-checkpoint-0000001234-<root prefix>.json``. Zero-padded because these
    are listed by name in a bucket and a git tag list, and `seq 9` sorting
    after `seq 10` makes a human reading that list draw the wrong conclusion
    about which anchor is newest. The root prefix is in the name so that two
    anchors for the same sequence number -- which should be impossible -- are
    visibly different rather than one silently overwriting the other.
    """
    payload = record.payload or {}
    root = str(payload.get("merkle_root", ""))[:16] or "noroot"
    return f"qed-checkpoint-{record.seq:010d}-{root}.json"


def checkpoint_bytes(record: EvidenceRecord) -> bytes:
    """The record as it will be published: the canonical JSON of the record.

    The whole record, not just the root. An auditor comparing a published
    anchor against an export needs the `hash`, the `key_id` and the signature
    too -- a bare Merkle root proves nothing about who computed it.
    """
    from qed.core import jcs

    return jcs.canonicalize(record.model_dump(mode="json"))
