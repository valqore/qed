"""Publishing a checkpoint to GCS with a retention policy (SPEC §10.4).

The GCP twin of `qed/infra/publishers/s3.py`, and the second anchor that
genuinely anchors. A bucket with a **locked** retention policy refuses to
delete or overwrite an object until its retention expires, and the policy
itself can never afterwards be shortened or removed -- not by the uploader,
not by a project owner, not by anybody. A checkpoint published there fixes a
Merkle root at a point in time the instance cannot revise, which is the claim
a rewritten chain cannot satisfy.

Where this differs from S3, and why each difference is in the code rather than
only in this docstring.

**Retention is a property of the bucket, not of the upload.** S3 takes
`ObjectLockMode` on `put_object`; GCS takes nothing. Every object in a bucket
with a retention policy inherits it, so there is no per-object request to get
right -- and correspondingly nothing the publisher can ask for. What it can do
is *read the policy back* and say what it found, which is what `publish` does.

**This publisher never sets or locks a policy, by design.** It would be two
API calls, and it would defeat the anchor: the protection is worth something
precisely because the bucket is outside this instance's control. A publisher
that could lock a bucket could also unlock one it had just created, and the
operator who can rewrite the chain is the same operator who runs this process.
So retention is platform configuration that the publisher *asserts*, never
manages -- the same reasoning as object-lock only being settable when an S3
bucket is created, arrived at from the other direction.

**There are three states here, not two.** S3 has lock or no lock; GCS has no
policy, an unlocked policy, or a locked one, and the middle case is the one
that misleads. An unlocked policy really does refuse deletes -- measured, not
assumed -- so it stops an accident and reads like protection. But an
administrator can remove it and then delete, which makes it the exact analogue
of S3's `GOVERNANCE` mode: no defence against the threat the anchor exists
for. Only a locked policy is the analogue of `COMPLIANCE`. `require_locked`
defaults to true so that an unlocked bucket is a caveat written into the
receipt and into the chain, rather than a success an operator reads as one.

**Writes are create-only.** `if_generation_match=0` makes the upload fail if
anything is already at the key. On a locked bucket retention refuses the
overwrite anyway; on a bucket with no policy this is the only thing that turns
a silent overwrite into a visible failure, and two different anchors for one
checkpoint sequence is something an auditor must hear about. Re-publishing the
*same* checkpoint stays idempotent, because a precondition failure is checked
against the stored bytes before it is reported -- see `_already_published`.

`google-cloud-storage` is an optional extra: an instance with no GCS publisher
never imports it. Credentials come from Application Default Credentials, the
way every Google tool takes them, and deliberately not from `qed.yaml`, which
is a file somebody commits.

What proves any of this is `tests/evidence/test_gcs_retention_live.py`, which
runs this publisher against real Google Cloud Storage and asserts the refusal
rather than the request -- including that a project **owner** is refused, which
is the strongest principal the threat model has to deny. The unit tests beside
it use a fake client and can only check the call this module makes, which is
the shape of a claim rather than the claim.
"""

from __future__ import annotations

import base64
import hashlib
import logging
from typing import Any, Final

from qed.core.schemas import EvidenceRecord, rfc3339_ms
from qed.infra.publishers.model import (
    PublicationError,
    Receipt,
    checkpoint_bytes,
    checkpoint_name,
)

__all__ = ["GcsRetentionPublisher"]

LOG: Final = logging.getLogger("qed.publishers.gcs")

INSTALL_HINT: Final = (
    "the `gcs-retention` checkpoint publisher needs google-cloud-storage. Install "
    "`valqore-qed[gcs]`, or use a `file` publisher pointed at a volume the "
    "instance does not control."
)

#: What the receipt says when the bucket provides less than the config asked
#: for. Three states, three sentences, because an operator reading only `ok`
#: would see a success in all three.
NO_POLICY: Final = (
    "the bucket has no retention policy, so this anchor can be deleted or "
    "overwritten at any time. A retention policy can be added to an existing "
    "bucket, and has to be locked to be worth anything against an operator."
)
UNLOCKED_POLICY: Final = (
    "the bucket's retention policy is not locked, so an administrator can "
    "remove it and then delete this anchor. An unlocked policy stops an "
    "accident, not an operator -- it is the analogue of S3 object-lock's "
    "GOVERNANCE mode. Lock it to make this anchor worth having."
)


class GcsRetentionPublisher:
    kind = "gcs-retention"

    def __init__(
        self,
        bucket: str,
        *,
        prefix: str = "checkpoints/",
        require_locked: bool = True,
        project: str = "",
        client: Any | None = None,
    ) -> None:
        self.bucket = bucket
        self.prefix = prefix if prefix.endswith("/") or not prefix else prefix + "/"
        self.require_locked = require_locked
        self.project = project
        self._client = client

    @classmethod
    def from_config(cls, options: dict[str, object]) -> GcsRetentionPublisher:
        bucket = options.get("bucket")
        if not bucket:
            raise PublicationError("a `gcs-retention` publisher needs a `bucket`")

        raw = options.get("require_locked", True)
        if isinstance(raw, str):
            require_locked = raw.strip().lower() not in {"false", "no", "0", "off"}
        else:
            require_locked = bool(raw)
        if not require_locked:
            # Not refused -- there are reasons to run it, the same ones that
            # justify GOVERNANCE on S3 -- but it has to be written down,
            # because the protection is weaker than it looks.
            LOG.warning(
                "`require_locked: false` on the gcs-retention publisher: an unlocked "
                "retention policy can be removed by an administrator, who is the same "
                "principal that could rewrite the chain. A locked policy is what makes "
                "the anchor worth having."
            )

        return cls(
            bucket=str(bucket),
            prefix=str(options.get("prefix", "checkpoints/")),
            require_locked=require_locked,
            project=str(options.get("project", "")),
        )

    def describe(self) -> str:
        where = f" in {self.project}" if self.project else ""
        expectation = "locked retention required" if self.require_locked else "unlocked accepted"
        return f"gcs-retention: gs://{self.bucket}/{self.prefix}{where} ({expectation})"

    # ------------------------------------------------------------------ client

    @property
    def client(self) -> Any:
        if self._client is None:
            try:
                from google.cloud import storage
            except ImportError as exc:
                # `ImportError` and not `ModuleNotFoundError`, which is where
                # the S3 publisher's identical-looking line is correct and a
                # copy of it here was wrong. `google.cloud` is a **namespace
                # package**: any other `google-*` distribution -- and
                # `google-api-core` arrives with half of them -- provides the
                # `google.cloud` namespace on its own, so with
                # google-cloud-storage absent the import does not fail to find
                # a module, it fails to find a *name* in one that exists, and
                # raises the parent class. Measured, not reasoned: with the
                # extra uninstalled this line raised `ImportError: cannot
                # import name 'storage' from 'google.cloud' (unknown
                # location)`, the hint below never fired, and the operator got
                # that string in a receipt instead of being told what to
                # install. `test_the_install_hint_survives_a_namespace_package`
                # pins it.
                raise PublicationError(INSTALL_HINT) from exc
            # Application Default Credentials, like every other Google tool:
            # a workload identity in GKE, a metadata server on GCE, or
            # GOOGLE_APPLICATION_CREDENTIALS. `project` is optional because
            # bucket names are global and an anchor bucket usually lives in a
            # *different* project from the instance -- which is the topology
            # that makes it an anchor.
            self._client = storage.Client(project=self.project or None)
        return self._client

    # ----------------------------------------------------------------- publish

    def publish(self, record: EvidenceRecord) -> Receipt:
        key = f"{self.prefix}{checkpoint_name(record)}"
        target = f"gs://{self.bucket}/{key}"
        body = checkpoint_bytes(record)

        try:
            bucket = self.client.bucket(self.bucket)
            period, locked = self._retention(bucket)
            blob = bucket.blob(key)
            try:
                blob.upload_from_string(
                    body,
                    content_type="application/json",
                    # Create-only. See the module docstring.
                    if_generation_match=0,
                )
            except Exception as exc:
                if not self._is_precondition(exc):
                    raise
                # Something is already at this key. Only a *different* object
                # is a problem; the same bytes mean this checkpoint was
                # already published and the retry should not report a failure.
                if not self._already_published(bucket, key, body):
                    return Receipt(
                        publisher=self.kind,
                        target=target,
                        ok=False,
                        error=(
                            "a different object is already published at this key. Two "
                            "anchors for one checkpoint sequence should be impossible, "
                            "and this one was not overwritten."
                        ),
                    )
                blob = bucket.get_blob(key)
            else:
                blob.reload()
        except PublicationError as exc:
            return Receipt(publisher=self.kind, target=target, ok=False, error=str(exc))
        except Exception as exc:
            # Never raised onward: a bucket that is unreachable must not stop
            # the chain. The failure is in the receipt, the table and the next
            # checkpoint's payload.
            return Receipt(
                publisher=self.kind,
                target=target,
                ok=False,
                error=f"{type(exc).__name__}: {exc}",
            )

        proof: dict[str, object] = {
            "retention_locked": bool(locked),
            "generation": str(getattr(blob, "generation", "") or ""),
            "etag": str(getattr(blob, "etag", "") or ""),
        }
        if getattr(blob, "md5_hash", None):
            proof["md5"] = blob.md5_hash
        if getattr(blob, "crc32c", None):
            proof["crc32c"] = blob.crc32c
        if period:
            proof["retention_period_seconds"] = int(period)
        # The server's own answer for when this object becomes deletable --
        # not a date the publisher asked for. That asymmetry with S3 is worth
        # the extra field: it is the bucket confirming the policy applies to
        # this object, rather than the publisher restating its own request.
        expires = getattr(blob, "retention_expiration_time", None)
        if expires is not None:
            proof["retention_expires"] = rfc3339_ms(expires)

        if not period:
            caveat = NO_POLICY
        elif not locked and self.require_locked:
            caveat = UNLOCKED_POLICY
        else:
            caveat = ""

        return Receipt(
            publisher=self.kind,
            target=target,
            ok=True,
            proof=proof,
            # Succeeded, and said so, while providing less protection than the
            # config asked for. An operator reading the receipt sees the
            # distinction; one reading only `ok` would not.
            error=caveat,
        )

    # ------------------------------------------------------------------ probes

    def _retention(self, bucket: Any) -> tuple[int, bool]:
        """The bucket's retention period and whether its policy is locked.

        Asked rather than assumed, for the reason the S3 publisher asks about
        object-lock: a bucket with no policy accepts the upload and provides
        no protection, and the publisher must report which of the three states
        it found instead of implying the strongest.

        Note `bool(...)` on the lock rather than `is True`: the JSON API omits
        `retentionPolicy.isLocked` when a policy is unlocked, so the client
        surfaces **`None`** and not `False`. Measured against real GCS; an
        `is False` test here would have read every unlocked policy as a state
        this code had never heard of.
        """
        try:
            bucket.reload()
        except Exception:
            # Reading bucket metadata needs `storage.buckets.get`, which a
            # least-privilege anchor writer (`roles/storage.objectCreator`
            # alone) does not have. That must not fail the publication: the
            # object still lands, and the receipt says the protection is
            # unknown rather than claiming it.
            return 0, False
        period = getattr(bucket, "retention_period", None) or 0
        return int(period), bool(getattr(bucket, "retention_policy_locked", None))

    @staticmethod
    def _is_precondition(exc: Exception) -> bool:
        """Whether an upload failed because something was already at the key."""
        if type(exc).__name__ == "PreconditionFailed":
            return True
        return getattr(exc, "code", None) == 412

    @staticmethod
    def _already_published(bucket: Any, key: str, body: bytes) -> bool:
        """Whether the object at `key` is byte-for-byte the one we are publishing.

        Compared on the server's md5 rather than by downloading: the stored
        hash is what the bucket will hand an auditor. Not a security property
        -- the record carries its own signature, and this only decides whether
        a retry reports success or a collision.
        """
        existing = bucket.get_blob(key)
        if existing is None or not getattr(existing, "md5_hash", None):
            return False
        digest = hashlib.md5(body, usedforsecurity=False).digest()
        return str(existing.md5_hash) == base64.b64encode(digest).decode()
