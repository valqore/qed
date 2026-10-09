"""Publishing a checkpoint to S3 with object-lock (SPEC §10.4).

This is the anchor that actually anchors. Object-lock in compliance mode means
**nobody can delete or overwrite the object until the retain-until date** —
not the uploader, not an administrator, not the account root. So a checkpoint
published here fixes a Merkle root at a point in time that the instance cannot
afterwards revise, which is exactly the claim a rewritten chain cannot satisfy.

Three things that are easy to get wrong and that this module refuses rather
than assumes.

**Object-lock has to be enabled on the bucket at creation.** It cannot be
turned on later. A bucket without it accepts every upload here and silently
provides no lock at all, so the publisher asks and reports the answer in its
receipt rather than implying a protection that is not there.

**Compliance mode is the default, and `governance` is a conscious downgrade.**
In governance mode a principal with `s3:BypassGovernanceRetention` can delete
the object — which is the same set of people who could rewrite the chain, so
the anchor adds nothing against the threat it exists for.

**The retain-until date must outlive the audit.** Defaulting to a short
retention would produce anchors that quietly expire before anybody asks about
them.

`boto3` is an optional extra: an instance with no S3 publisher never imports
it.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any, Final

from qed.core.schemas import EvidenceRecord, rfc3339_ms, utcnow
from qed.infra.publishers.model import (
    PublicationError,
    Receipt,
    checkpoint_bytes,
    checkpoint_name,
)

__all__ = ["DEFAULT_RETAIN_DAYS", "S3ObjectLockPublisher"]

#: Seven years, matching the usual evidence obligation and SPEC §16's
#: `retention: { payload: 7y }`. An anchor that expires before the audit it
#: exists for is not an anchor.
DEFAULT_RETAIN_DAYS: Final = 7 * 365

INSTALL_HINT: Final = (
    "the `s3-object-lock` checkpoint publisher needs boto3. Install "
    "`valqore-qed[s3]`, or use a `file` publisher pointed at a volume the "
    "instance does not control."
)


class S3ObjectLockPublisher:
    kind = "s3-object-lock"

    def __init__(
        self,
        bucket: str,
        *,
        prefix: str = "checkpoints/",
        mode: str = "COMPLIANCE",
        retain_days: int = DEFAULT_RETAIN_DAYS,
        client: Any | None = None,
    ) -> None:
        self.bucket = bucket
        self.prefix = prefix if prefix.endswith("/") or not prefix else prefix + "/"
        self.mode = mode
        self.retain_days = retain_days
        self._client = client

    @classmethod
    def from_config(cls, options: dict[str, object]) -> S3ObjectLockPublisher:
        bucket = options.get("bucket")
        if not bucket:
            raise PublicationError("an `s3-object-lock` publisher needs a `bucket`")

        mode = str(options.get("mode", "COMPLIANCE")).upper()
        if mode not in {"COMPLIANCE", "GOVERNANCE"}:
            raise PublicationError(
                f"object-lock mode {mode!r} is not one of COMPLIANCE, GOVERNANCE"
            )
        if mode == "GOVERNANCE":
            # Not refused -- there are reasons to run it -- but it has to be
            # written down, because the protection is weaker than it looks.
            import logging

            logging.getLogger("qed.publishers.s3").warning(
                "object-lock mode is GOVERNANCE: a principal with "
                "s3:BypassGovernanceRetention can delete these anchors, which is the "
                "same set of people who could rewrite the chain. COMPLIANCE is what "
                "makes the anchor worth having."
            )

        # `or DEFAULT` would be wrong here: `retain_days: 0` is falsy, and
        # silently turning "no lock" into "seven years" hides the one value an
        # operator must not be allowed to set by accident.
        raw = options.get("retain_days")
        if raw is None:
            raw = DEFAULT_RETAIN_DAYS
        try:
            retain = int(str(raw))
        except ValueError:
            raise PublicationError(f"`retain_days` must be a number, not {raw!r}") from None
        if retain <= 0:
            raise PublicationError("`retain_days` must be positive; an unlocked anchor is none")

        return cls(
            bucket=str(bucket),
            prefix=str(options.get("prefix", "checkpoints/")),
            mode=mode,
            retain_days=retain,
        )

    def describe(self) -> str:
        return (
            f"s3-object-lock: s3://{self.bucket}/{self.prefix} ({self.mode}, {self.retain_days}d)"
        )

    # ------------------------------------------------------------------ client

    @property
    def client(self) -> Any:
        if self._client is None:
            try:
                import boto3
            except ModuleNotFoundError as exc:  # pragma: no cover - needs the extra absent
                raise PublicationError(INSTALL_HINT) from exc
            # Credentials come from the environment the way every AWS tool
            # takes them. Deliberately not from `qed.yaml`: the config file is
            # something somebody commits.
            self._client = boto3.client("s3")
        return self._client

    # ----------------------------------------------------------------- publish

    def publish(self, record: EvidenceRecord) -> Receipt:
        key = f"{self.prefix}{checkpoint_name(record)}"
        target = f"s3://{self.bucket}/{key}"
        body = checkpoint_bytes(record)
        retain_until = utcnow() + timedelta(days=self.retain_days)

        try:
            client = self.client
            locked = self._bucket_has_object_lock(client)
            response = client.put_object(
                Bucket=self.bucket,
                Key=key,
                Body=body,
                ContentType="application/json",
                ChecksumAlgorithm="SHA256",
                **(
                    {
                        "ObjectLockMode": self.mode,
                        "ObjectLockRetainUntilDate": retain_until,
                    }
                    if locked
                    else {}
                ),
            )
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
            "etag": str(response.get("ETag", "")).strip('"'),
            "object_lock": locked,
        }
        if response.get("VersionId"):
            proof["version_id"] = response["VersionId"]
        if response.get("ChecksumSHA256"):
            proof["checksum_sha256"] = response["ChecksumSHA256"]
        if locked:
            proof["mode"] = self.mode
            proof["retain_until"] = rfc3339_ms(retain_until)

        return Receipt(
            publisher=self.kind,
            target=target,
            ok=True,
            proof=proof,
            # Succeeded, and said so, while providing less protection than the
            # config asked for. An operator reading the receipt sees the
            # distinction; one reading only `ok` would not.
            error=(
                ""
                if locked
                else "the bucket has no object-lock configuration, so this anchor can be "
                "deleted or overwritten. Object-lock can only be enabled when a bucket "
                "is created."
            ),
        )

    def _bucket_has_object_lock(self, client: Any) -> bool:
        """Whether the bucket will actually hold a lock.

        Asked rather than assumed, because a bucket without object-lock
        accepts the upload and provides no lock -- and `put_object` with
        `ObjectLockMode` against such a bucket fails outright, which would
        make every checkpoint look like a network problem.
        """
        try:
            configuration = client.get_object_lock_configuration(Bucket=self.bucket)
        except Exception:
            return False
        rule = configuration.get("ObjectLockConfiguration", {})
        return str(rule.get("ObjectLockEnabled", "")).lower() == "enabled"
