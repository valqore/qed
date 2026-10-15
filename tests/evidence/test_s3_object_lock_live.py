"""The anchor, against a real S3 server (SPEC §10.4).

`THREAT_MODEL.md` has one control for "the whole chain is rewritten by the
operator": a checkpoint root published somewhere the instance cannot afterwards
revise. Everything else the verifier does is self-referential -- a chain
rewritten wholesale and re-signed passes every other check -- so this row is
the one that needs an implementation behind it rather than a mock.

Until this file, the `s3-object-lock` publisher's only test was a hand-written
`FakeS3` (`tests/evidence/test_publishers.py`) that records the keyword
arguments it is given. That proves the publisher *asks* for a lock. It cannot
prove that any server accepts the request as written, and it cannot prove the
one thing the control claims: **that the object then cannot be deleted.** A
fake that returns `{"ETag": ...}` for any call agrees just as readily with a
publisher that sends nonsense.

So these run over HTTP against a server that enforces retention, and assert the
refusal rather than the request. Five things here are invisible to a fake:

* that `ChecksumAlgorithm`, `ObjectLockMode` and `ObjectLockRetainUntilDate`
  are accepted **together** on one `put_object` -- an object-lock bucket
  requires a checksum or `Content-MD5`, and that the three compose is not
  obvious from either API reference;
* that deleting the locked version is refused, **and refused again** with
  `BypassGovernanceRetention` set from the store's root credentials;
* that a locked version survives both a plain delete (which writes a delete
  marker and hides it) and an overwrite (which adds a version beside it);
* that `GOVERNANCE` really is bypassable where `COMPLIANCE` is not, which is
  the entire argument for the default;
* that path-style addressing and request signing work against a non-AWS
  endpoint, which is what `endpoint_url` exists for.

**The server.** `QED_TEST_S3_ENDPOINT` points these anywhere: CI runs
LocalStack, and the same tests run unchanged against MinIO, Ceph or real AWS.
LocalStack's S3 is an independent reimplementation, not AWS code, so a refusal
it produces is evidence about the semantics rather than a tautology -- but it
is still an emulator, and one divergence is marked as such below:
`QED_TEST_S3_AWS=1` enables the single assertion that is AWS behaviour
LocalStack does not model (an ordinary bucket refusing a lock; LocalStack
accepts it and stores none). Both divergent behaviours argue for the same
thing, which is that the publisher asks the bucket before it trusts a success.

Skipped without `QED_TEST_S3_ENDPOINT`. CI sets it, then fails the job if these
tests skipped, because a test that skips itself proves nothing.
"""

from __future__ import annotations

import os
import uuid
from datetime import datetime
from typing import Any

import pytest

try:
    from botocore.exceptions import ClientError
except ModuleNotFoundError:  # the `s3` extra is absent, so every test here skips
    ClientError = Exception  # type: ignore[assignment, misc]

from qed.core.schemas import Assurance, EvidenceRecord, EvidenceType, utcnow
from qed.infra.publishers.model import checkpoint_bytes
from qed.infra.publishers.s3 import S3ObjectLockPublisher

ENDPOINT_ENV = "QED_TEST_S3_ENDPOINT"
ENDPOINT = os.environ.get(ENDPOINT_ENV, "")

#: Set to 1 when the endpoint is real AWS. One refusal below is AWS behaviour
#: that LocalStack does not model, and asserting it against LocalStack would
#: fail for a reason that has nothing to do with this publisher.
AWS_ENV = "QED_TEST_S3_AWS"

pytestmark = [
    pytest.mark.slow,
    pytest.mark.skipif(not ENDPOINT, reason=f"set {ENDPOINT_ENV} to run the object-lock tests"),
]

#: One day, not the seven years the publisher defaults to. A COMPLIANCE lock
#: cannot be shortened or removed by anybody, so a seven-year retention in a
#: test would mean a bucket nothing can clean up -- which matters the day these
#: run against something more permanent than a container.
RETAIN_DAYS = 1


def checkpoint() -> EvidenceRecord:
    """A checkpoint record, shaped like `tests/evidence/test_publishers.py`'s.

    The Merkle root is random per call because `checkpoint_name` derives the
    object key from the seq and the root: a fixed root would make every test
    here publish over the same locked key, and "the first version is still
    intact" would be asserting against whatever ran last.
    """
    root = uuid.uuid4().hex + uuid.uuid4().hex
    return EvidenceRecord(
        seq=41,
        ts=utcnow(),
        type=EvidenceType.checkpoint,
        assurance=Assurance.kernel,
        payload={"from_seq": 0, "to_seq": 40, "merkle_root": root, "records": 41},
        payload_hash="b" * 64,
        prev_hash="c" * 64,
        hash="d" * 64,
        key_id="ed25519:0000000000000000",
        sig="s" * 86,
    )


@pytest.fixture(scope="module")
def admin() -> Any:
    """A client for making buckets, built the way the publisher builds its own."""
    boto3 = pytest.importorskip("boto3", reason="the s3 extra is not installed")
    from botocore.config import Config

    return boto3.client(
        "s3",
        endpoint_url=ENDPOINT,
        config=Config(s3={"addressing_style": "path"}, retries={"max_attempts": 2}),
        region_name=os.environ.get("AWS_DEFAULT_REGION", "us-east-1"),
    )


@pytest.fixture(scope="module")
def locked_bucket(admin: Any) -> str:
    """A bucket with object-lock on, which can only be set at creation."""
    name = f"qed-locked-{uuid.uuid4().hex[:12]}"
    admin.create_bucket(Bucket=name, ObjectLockEnabledForBucket=True)
    return name


@pytest.fixture(scope="module")
def plain_bucket(admin: Any) -> str:
    name = f"qed-plain-{uuid.uuid4().hex[:12]}"
    admin.create_bucket(Bucket=name)
    return name


def publisher(bucket: str, **options: Any) -> S3ObjectLockPublisher:
    return S3ObjectLockPublisher.from_config(
        {
            "bucket": bucket,
            "endpoint_url": ENDPOINT,
            "retain_days": RETAIN_DAYS,
            **options,
        }
    )


def client_error(exc: Exception) -> str:
    """The error code a real server returned, for an assertion worth reading."""
    return str(getattr(exc, "response", {}).get("Error", {}).get("Code", type(exc).__name__))


class TestTheAnchorIsWritten:
    def test_the_real_api_accepts_the_call_this_publisher_makes(
        self, locked_bucket: str, admin: Any
    ) -> None:
        """A checksum **and** a lock **and** a retain-until date, in one
        `put_object`. An object-lock bucket requires the first, and nothing in
        the fake could have told us whether the three go together."""
        record = checkpoint()
        receipt = publisher(locked_bucket).publish(record)

        assert receipt.ok, receipt.error
        assert receipt.error == "", "a locked bucket should carry no caveat"
        assert receipt.proof["object_lock"] is True
        assert receipt.proof["mode"] == "COMPLIANCE"
        assert receipt.proof["etag"]
        assert receipt.proof["version_id"], "object-lock implies versioning"
        assert receipt.proof["checksum_sha256"], "the server computed and returned a checksum"
        assert receipt.proof["retain_until"]

    def test_the_bytes_an_auditor_reads_are_the_bytes_we_signed(
        self, locked_bucket: str, admin: Any
    ) -> None:
        record = checkpoint()
        receipt = publisher(locked_bucket).publish(record)
        assert receipt.ok, receipt.error

        key = receipt.target.split(f"{locked_bucket}/", 1)[1]
        stored = admin.get_object(Bucket=locked_bucket, Key=key)
        assert stored["Body"].read() == checkpoint_bytes(record)
        assert stored["ContentType"] == "application/json"
        assert stored["ObjectLockMode"] == "COMPLIANCE"
        assert isinstance(stored["ObjectLockRetainUntilDate"], datetime)


class TestTheAnchorCannotBeRemoved:
    """The control itself. Everything above is plumbing; this is the claim."""

    @pytest.fixture
    def published(self, locked_bucket: str) -> tuple[str, str]:
        record = checkpoint()
        receipt = publisher(locked_bucket).publish(record)
        assert receipt.ok, receipt.error
        key = receipt.target.split(f"{locked_bucket}/", 1)[1]
        return key, str(receipt.proof["version_id"])

    def test_deleting_the_locked_version_is_refused(
        self, locked_bucket: str, admin: Any, published: tuple[str, str]
    ) -> None:
        key, version = published
        with pytest.raises(ClientError) as caught:
            admin.delete_object(Bucket=locked_bucket, Key=key, VersionId=version)
        assert client_error(caught.value) in {"AccessDenied", "InvalidRequest"}

    def test_a_bypass_is_refused_too_in_compliance_mode(
        self, locked_bucket: str, admin: Any, published: tuple[str, str]
    ) -> None:
        """`s3:BypassGovernanceRetention` is the escape hatch the publisher's
        docstring says COMPLIANCE does not have. Asked for with the root
        credentials of the store, which is the strongest principal there is."""
        key, version = published
        with pytest.raises(ClientError) as caught:
            admin.delete_object(
                Bucket=locked_bucket, Key=key, VersionId=version, BypassGovernanceRetention=True
            )
        assert client_error(caught.value) in {"AccessDenied", "InvalidRequest"}

    def test_a_plain_delete_hides_it_and_does_not_destroy_it(
        self, locked_bucket: str, admin: Any, published: tuple[str, str]
    ) -> None:
        """A delete with no version id on a versioned bucket writes a delete
        marker. The object looks gone to anybody listing the key, and the
        locked version is still there -- which is what an auditor handed "it
        was deleted" needs to know."""
        key, version = published
        admin.delete_object(Bucket=locked_bucket, Key=key)
        assert admin.get_object(Bucket=locked_bucket, Key=key, VersionId=version)["Body"].read()

    def test_an_overwrite_adds_a_version_and_leaves_the_anchor_intact(
        self, locked_bucket: str, admin: Any, published: tuple[str, str]
    ) -> None:
        key, version = published
        original = admin.get_object(Bucket=locked_bucket, Key=key, VersionId=version)["Body"].read()

        admin.put_object(Bucket=locked_bucket, Key=key, Body=b"{}", ChecksumAlgorithm="SHA256")
        assert (
            admin.get_object(Bucket=locked_bucket, Key=key, VersionId=version)["Body"].read()
            == original
        )

    def test_governance_mode_really_is_bypassable(self, locked_bucket: str, admin: Any) -> None:
        """The downgrade, demonstrated rather than described. The publisher
        logs a warning for `mode: governance`; this is what the warning is
        about, and it is the reason COMPLIANCE is the default."""
        receipt = publisher(locked_bucket, mode="governance").publish(checkpoint())
        assert receipt.ok, receipt.error
        key = receipt.target.split(f"{locked_bucket}/", 1)[1]

        admin.delete_object(
            Bucket=locked_bucket,
            Key=key,
            VersionId=str(receipt.proof["version_id"]),
            BypassGovernanceRetention=True,
        )
        with pytest.raises(ClientError) as caught:
            admin.get_object(
                Bucket=locked_bucket, Key=key, VersionId=str(receipt.proof["version_id"])
            )
        assert client_error(caught.value) in {"NoSuchVersion", "NoSuchKey"}


class TestABucketWithoutObjectLock:
    def test_the_upload_succeeds_and_the_receipt_says_what_it_is_not(
        self, plain_bucket: str
    ) -> None:
        """The degradation path, against a server rather than a fake.

        Object-lock can only be enabled when a bucket is created, so an
        operator who pointed this at an ordinary bucket gets an anchor with no
        protection -- and has to be told, in the receipt that goes into the
        chain. This holds whether the endpoint refuses a lock it cannot honour
        (AWS) or accepts it and stores nothing (LocalStack), because the
        publisher asks the bucket first instead of inferring from the answer to
        `put_object`."""
        receipt = publisher(plain_bucket).publish(checkpoint())

        assert receipt.ok, receipt.error
        assert receipt.proof["object_lock"] is False
        assert "can be deleted or overwritten" in receipt.error
        assert "mode" not in receipt.proof

    def test_the_object_is_deletable_which_is_the_point(
        self, plain_bucket: str, admin: Any
    ) -> None:
        receipt = publisher(plain_bucket).publish(checkpoint())
        key = receipt.target.split(f"{plain_bucket}/", 1)[1]
        admin.delete_object(Bucket=plain_bucket, Key=key)

    @pytest.mark.skipif(
        not os.environ.get(AWS_ENV),
        reason=f"set {AWS_ENV}=1 when the endpoint is real AWS; LocalStack accepts the lock",
    )
    def test_sending_a_lock_to_such_a_bucket_is_refused_by_aws(
        self, plain_bucket: str, admin: Any
    ) -> None:
        """The first reason `_bucket_has_object_lock` exists, and the half this
        environment cannot show.

        Real S3 answers `InvalidRequest` -- "Bucket is missing Object Lock
        Configuration" -- so a publisher that sent the lock blindly would turn
        every checkpoint against an ordinary bucket into an error that reads
        like the network. LocalStack 4 instead **accepts** it and stores no
        lock, which is the second reason to ask: an endpoint can refuse the
        request or it can quietly provide nothing, and only asking first tells
        the two apart. Measured, not assumed -- this test failed against
        LocalStack with DID NOT RAISE, which is how the paragraph above got
        written.
        """
        with pytest.raises(ClientError) as caught:
            admin.put_object(
                Bucket=plain_bucket,
                Key="checkpoints/would-fail.json",
                Body=b"{}",
                ChecksumAlgorithm="SHA256",
                ObjectLockMode="COMPLIANCE",
                ObjectLockRetainUntilDate=utcnow(),
            )
        assert client_error(caught.value) == "InvalidRequest"


def test_an_unreachable_endpoint_is_a_receipt_and_not_an_exception() -> None:
    """The same guarantee as the fake's version of this test, against a real
    client: a port with nothing on it must not raise into the chain writer."""
    receipt = S3ObjectLockPublisher.from_config(
        {"bucket": "anchors", "endpoint_url": "http://127.0.0.1:1", "retain_days": RETAIN_DAYS}
    ).publish(checkpoint())
    assert not receipt.ok
    assert receipt.error
