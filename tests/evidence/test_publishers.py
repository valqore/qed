"""Checkpoint publishers (SPEC §10.4, week 7).

A checkpoint on its own proves that the instance was internally consistent at
the moment an auditor read it. An operator who rewrote the chain could
recompute every root and every signature, and nothing in the export would say
so. **Publishing is what closes that**: the root goes somewhere the instance
does not control, and a rewritten chain fails the comparison.

So the tests are about the properties that make a published root worth
comparing against, and about the rule that holds whatever happens:

* **a failed publication never stops the chain** -- every publisher returns a
  receipt with ``ok=False`` rather than raising;
* **but it never disappears either** -- the failure lands in the
  ``checkpoints`` table, in the next checkpoint's payload, and in `qed doctor`.

S3 is tested here against a fake client that records its calls, which pins the
arguments `put_object` gets -- a publisher that quietly omits `ObjectLockMode`
provides no lock while reporting success. That is the shape of the claim and
not the claim: a fake accepts any call and refuses no delete.
`tests/evidence/test_s3_object_lock_live.py` runs the same publisher against a
real MinIO and asserts the refusal, which is what `THREAT_MODEL.md`'s
chain-rewrite row actually rests on.
"""

from __future__ import annotations

import json
import subprocess
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from qed.core import jcs
from qed.core.schemas import Assurance, EvidenceRecord, EvidenceType, utcnow
from qed.infra.publishers import (
    PublicationError,
    Receipt,
    build_publishers,
    checkpoint_bytes,
    checkpoint_name,
    publish_checkpoint,
)
from qed.infra.publishers.file import FilePublisher
from qed.infra.publishers.gcs import (
    NO_POLICY,
    UNLOCKED_POLICY,
    GcsRetentionPublisher,
)
from qed.infra.publishers.git import GitTagPublisher
from qed.infra.publishers.s3 import DEFAULT_RETAIN_DAYS, S3ObjectLockPublisher


def checkpoint(seq: int = 7, root: str = "a" * 64) -> EvidenceRecord:
    return EvidenceRecord(
        seq=seq,
        ts=utcnow(),
        type=EvidenceType.checkpoint,
        assurance=Assurance.kernel,
        payload={"from_seq": 0, "to_seq": seq - 1, "merkle_root": root, "records": seq},
        payload_hash="b" * 64,
        prev_hash="c" * 64,
        hash="d" * 64,
        key_id="ed25519:0000000000000000",
        sig="s" * 86,
    )


# --------------------------------------------------------------------------
# What gets published
# --------------------------------------------------------------------------


class TestTheContents:
    def test_it_is_the_whole_record_and_not_just_the_root(self) -> None:
        """A bare Merkle root proves nothing about who computed it. An auditor
        comparing an anchor against an export needs the `hash`, the `key_id`
        and the signature too."""
        record = checkpoint()
        published = json.loads(checkpoint_bytes(record))
        assert published["merkle_root" if False else "hash"] == record.hash
        assert published["key_id"] == record.key_id
        assert published["sig"] == record.sig
        assert published["payload"]["merkle_root"] == "a" * 64

    def test_it_is_canonical_json(self) -> None:
        """The same record published twice has to produce the same bytes, or
        two anchors for one checkpoint would differ for no reason an auditor
        could explain."""
        record = checkpoint()
        assert checkpoint_bytes(record) == jcs.canonicalize(record.model_dump(mode="json"))
        assert checkpoint_bytes(record) == checkpoint_bytes(record)

    def test_the_name_sorts(self) -> None:
        """These are read as a listing in a bucket or a tag list, and `seq 9`
        sorting after `seq 10` makes a human draw the wrong conclusion about
        which anchor is newest."""
        names = sorted(checkpoint_name(checkpoint(seq)) for seq in (2, 9, 10, 1000))
        assert [name.split("-")[2] for name in names] == [
            "0000000002",
            "0000000009",
            "0000000010",
            "0000001000",
        ]

    def test_the_name_carries_the_root(self) -> None:
        """Two anchors for one sequence number should be impossible. If it
        happens the right outcome is two visibly different files, not one
        silently overwriting the other."""
        first = checkpoint_name(checkpoint(5, root="1" * 64))
        second = checkpoint_name(checkpoint(5, root="2" * 64))
        assert first != second


# --------------------------------------------------------------------------
# file
# --------------------------------------------------------------------------


class TestTheFilePublisher:
    def test_it_writes_the_record(self, tmp_path: Path) -> None:
        publisher = FilePublisher.from_config({"path": str(tmp_path / "anchors")})
        record = checkpoint()
        receipt = publisher.publish(record)

        assert receipt.ok, receipt.error
        written = Path(receipt.target)
        assert written.read_bytes() == checkpoint_bytes(record)
        assert receipt.proof["sha256"]
        assert receipt.proof["bytes"] == len(checkpoint_bytes(record))

    def test_the_directory_is_created(self, tmp_path: Path) -> None:
        publisher = FilePublisher.from_config({"path": str(tmp_path / "a" / "b" / "c")})
        assert publisher.publish(checkpoint()).ok

    def test_it_refuses_to_replace_an_anchor(self, tmp_path: Path) -> None:
        """Two anchors for one sequence number should be impossible, and if it
        happens a visible failure beats a silently replaced anchor."""
        publisher = FilePublisher.from_config({"path": str(tmp_path)})
        assert publisher.publish(checkpoint()).ok
        again = publisher.publish(checkpoint())
        assert not again.ok
        assert "refusing to replace" in again.error

    def test_nothing_partial_is_left_behind(self, tmp_path: Path) -> None:
        """Written to a temporary name and moved, so a reader never sees half
        an anchor."""
        publisher = FilePublisher.from_config({"path": str(tmp_path)})
        publisher.publish(checkpoint())
        assert not list(tmp_path.glob("*.part"))

    def test_an_unwritable_path_is_a_receipt_and_not_an_exception(self, tmp_path: Path) -> None:
        clash = tmp_path / "taken"
        clash.write_text("not a directory", encoding="utf-8")
        publisher = FilePublisher.from_config({"path": str(clash)})
        receipt = publisher.publish(checkpoint())
        assert not receipt.ok
        assert receipt.error

    def test_a_path_is_required(self) -> None:
        with pytest.raises(PublicationError, match="needs a `path`"):
            FilePublisher.from_config({})

    def test_describe_has_no_secret_in_it(self, tmp_path: Path) -> None:
        assert FilePublisher.from_config({"path": str(tmp_path)}).describe().startswith("file:")


# --------------------------------------------------------------------------
# s3-object-lock
# --------------------------------------------------------------------------


class FakeS3:
    """Records what it was asked to do. Nothing else."""

    def __init__(self, *, object_lock: bool = True, fail: Exception | None = None) -> None:
        self.object_lock = object_lock
        self.fail = fail
        self.calls: list[dict[str, Any]] = []

    def get_object_lock_configuration(self, **kwargs: Any) -> dict[str, Any]:
        if not self.object_lock:
            raise RuntimeError("ObjectLockConfigurationNotFoundError")
        return {"ObjectLockConfiguration": {"ObjectLockEnabled": "Enabled"}}

    def put_object(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(kwargs)
        if self.fail is not None:
            raise self.fail
        return {"ETag": '"abc123"', "VersionId": "v1", "ChecksumSHA256": "sha"}


def s3(client: FakeS3, **options: Any) -> S3ObjectLockPublisher:
    publisher = S3ObjectLockPublisher.from_config({"bucket": "anchors", **options})
    publisher._client = client
    return publisher


class TestTheS3Publisher:
    def test_it_asks_for_the_lock(self) -> None:
        """The whole reason this publisher exists. Compliance-mode object-lock
        means nobody can delete or overwrite the object until the retain-until
        date -- not the uploader, not an administrator, not the account root."""
        client = FakeS3()
        receipt = s3(client).publish(checkpoint())

        assert receipt.ok, receipt.error
        call = client.calls[0]
        assert call["ObjectLockMode"] == "COMPLIANCE"
        assert isinstance(call["ObjectLockRetainUntilDate"], datetime)
        assert receipt.proof["mode"] == "COMPLIANCE"
        assert receipt.proof["object_lock"] is True

    def test_the_default_retention_outlives_the_audit(self) -> None:
        """An anchor that expires before anybody asks about it is not an
        anchor. Seven years, matching the usual evidence obligation."""
        client = FakeS3()
        before = utcnow()
        s3(client).publish(checkpoint())
        retain = client.calls[0]["ObjectLockRetainUntilDate"]
        assert DEFAULT_RETAIN_DAYS == 7 * 365
        assert retain - before >= timedelta(days=7 * 365 - 1)

    def test_the_body_is_the_canonical_record(self) -> None:
        client = FakeS3()
        record = checkpoint()
        s3(client).publish(record)
        assert client.calls[0]["Body"] == checkpoint_bytes(record)
        assert client.calls[0]["ContentType"] == "application/json"

    def test_the_receipt_carries_what_an_auditor_can_check_with(self) -> None:
        receipt = s3(FakeS3()).publish(checkpoint())
        assert receipt.proof["etag"] == "abc123"
        assert receipt.proof["version_id"] == "v1"
        assert receipt.proof["checksum_sha256"] == "sha"
        assert receipt.proof["retain_until"]

    def test_a_bucket_without_object_lock_succeeds_and_says_so(self) -> None:
        """It accepts the upload and provides no lock. Reporting `ok` with no
        caveat would claim a protection that is not there -- and passing
        `ObjectLockMode` to such a bucket fails outright, which would make
        every checkpoint look like a network problem."""
        client = FakeS3(object_lock=False)
        receipt = s3(client).publish(checkpoint())

        assert receipt.ok
        assert "ObjectLockMode" not in client.calls[0]
        assert receipt.proof["object_lock"] is False
        assert "can be deleted or overwritten" in receipt.error

    def test_an_unreachable_bucket_is_a_receipt_and_not_an_exception(self) -> None:
        """A bucket that is down must not stop qed deciding."""
        receipt = s3(FakeS3(fail=RuntimeError("connection reset"))).publish(checkpoint())
        assert not receipt.ok
        assert "connection reset" in receipt.error

    def test_governance_mode_is_allowed_and_warned_about(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """A principal with `s3:BypassGovernanceRetention` can delete the
        object -- the same set of people who could rewrite the chain, so the
        anchor adds nothing against the threat it exists for."""
        import logging

        with caplog.at_level(logging.WARNING, logger="qed.publishers.s3"):
            publisher = S3ObjectLockPublisher.from_config(
                {"bucket": "anchors", "mode": "governance"}
            )
        assert publisher.mode == "GOVERNANCE"
        assert "BypassGovernanceRetention" in caplog.text

    def test_an_unknown_mode_is_refused(self) -> None:
        with pytest.raises(PublicationError, match="COMPLIANCE, GOVERNANCE"):
            S3ObjectLockPublisher.from_config({"bucket": "a", "mode": "whatever"})

    def test_a_bucket_is_required(self) -> None:
        with pytest.raises(PublicationError, match="needs a `bucket`"):
            S3ObjectLockPublisher.from_config({})

    def test_a_zero_retention_is_refused(self) -> None:
        with pytest.raises(PublicationError, match="unlocked anchor is none"):
            S3ObjectLockPublisher.from_config({"bucket": "a", "retain_days": 0})

    def test_describe_names_the_bucket_and_the_mode(self) -> None:
        described = S3ObjectLockPublisher.from_config({"bucket": "acme"}).describe()
        assert "acme" in described
        assert "COMPLIANCE" in described


# --------------------------------------------------------------------------
# git-tag
# --------------------------------------------------------------------------


def git_available() -> bool:
    try:
        return (
            subprocess.run(["git", "--version"], capture_output=True, check=False).returncode == 0
        )
    except OSError:  # pragma: no cover
        return False


@pytest.mark.skipif(not git_available(), reason="git is not installed")
class TestTheGitPublisher:
    @pytest.fixture
    def repository(self, tmp_path: Path) -> Path:
        path = tmp_path / "anchors.git"
        path.mkdir()
        for command in (
            ["git", "init", "-q"],
            ["git", "config", "user.email", "qed@example.com"],
            ["git", "config", "user.name", "qed"],
            ["git", "config", "commit.gpgsign", "false"],
            ["git", "config", "tag.gpgsign", "false"],
        ):
            subprocess.run(command, cwd=path, check=True, capture_output=True)
        (path / "README").write_text("anchors\n", encoding="utf-8")
        subprocess.run(["git", "add", "README"], cwd=path, check=True, capture_output=True)
        subprocess.run(
            ["git", "commit", "-q", "-m", "init"], cwd=path, check=True, capture_output=True
        )
        return path

    def test_it_creates_an_annotated_tag_carrying_the_record(self, repository: Path) -> None:
        publisher = GitTagPublisher.from_config({"repository": str(repository), "push": False})
        record = checkpoint()
        receipt = publisher.publish(record)

        assert receipt.ok, receipt.error
        shown = subprocess.run(
            ["git", "tag", "-l", receipt.target, "--format=%(contents)"],
            cwd=repository,
            capture_output=True,
            text=True,
            check=True,
        )
        assert json.loads(shown.stdout.strip()) == json.loads(checkpoint_bytes(record))

    def test_a_local_tag_says_it_anchors_nothing(self, repository: Path) -> None:
        """The push is what makes it an anchor. A local tag is as rewritable
        as the chain beside it."""
        publisher = GitTagPublisher.from_config({"repository": str(repository), "push": False})
        receipt = publisher.publish(checkpoint())
        assert receipt.ok
        assert receipt.proof["pushed"] is False
        assert "lives only beside the chain" in receipt.error

    def test_the_tag_name_sorts(self, repository: Path) -> None:
        publisher = GitTagPublisher.from_config({"repository": str(repository), "push": False})
        assert publisher.publish(checkpoint(9)).target.endswith("0000000009")

    def test_a_failed_push_is_reported_as_a_failure(self, repository: Path) -> None:
        """The local tag exists and the anchor does not, so `ok` has to be
        False -- and the tag is left in place, because the next attempt can
        push it."""
        publisher = GitTagPublisher.from_config(
            {"repository": str(repository), "remote": "nowhere"}
        )
        receipt = publisher.publish(checkpoint())
        assert not receipt.ok
        assert "could not push" in receipt.error
        assert receipt.proof["tag"]

    def test_a_duplicate_tag_is_a_failure(self, repository: Path) -> None:
        publisher = GitTagPublisher.from_config({"repository": str(repository), "push": False})
        assert publisher.publish(checkpoint()).ok
        assert not publisher.publish(checkpoint()).ok

    def test_a_directory_that_is_not_a_repository_is_refused(self, tmp_path: Path) -> None:
        with pytest.raises(PublicationError, match="not a git repository"):
            GitTagPublisher.from_config({"repository": str(tmp_path)})

    def test_a_repository_is_required(self) -> None:
        with pytest.raises(PublicationError, match="needs a `repository`"):
            GitTagPublisher.from_config({})


# --------------------------------------------------------------------------
# GCS retention
# --------------------------------------------------------------------------


class FakeGcsBlob:
    def __init__(self, store: FakeGcsBucket, key: str) -> None:
        self._store = store
        self.key = key
        self.generation: int | None = None
        self.etag = ""
        self.md5_hash = ""
        self.crc32c = ""
        self.retention_expiration_time: datetime | None = None

    def upload_from_string(
        self, data: bytes, content_type: str = "", if_generation_match: int | None = None
    ) -> None:
        self._store.uploads.append(
            {
                "key": self.key,
                "data": data,
                "content_type": content_type,
                "if_generation_match": if_generation_match,
            }
        )
        if self._store.upload_error is not None:
            raise self._store.upload_error
        if if_generation_match == 0 and self.key in self._store.objects:
            raise FakePrecondition("412 object already exists")
        self._store.objects[self.key] = data
        self._hydrate()

    def _hydrate(self) -> None:
        import base64
        import hashlib

        data = self._store.objects[self.key]
        self.generation = 1792199925131168
        self.etag = "etag-abc"
        self.md5_hash = base64.b64encode(hashlib.md5(data, usedforsecurity=False).digest()).decode()
        self.crc32c = "R98Qnw=="
        if self._store.retention_period:
            self.retention_expiration_time = utcnow() + timedelta(
                seconds=self._store.retention_period
            )

    def reload(self) -> None:
        self._hydrate()

    def delete(self) -> None:  # pragma: no cover - not exercised by the publisher
        raise AssertionError("the publisher must never delete an anchor")


class FakePrecondition(Exception):
    """Stands in for `google.api_core.exceptions.PreconditionFailed`.

    Matched by class *name* and by a `code` of 412, the way the publisher
    does, so that this fake does not have to import google-cloud-storage to
    exercise the branch.
    """

    code = 412

    def __init__(self, message: str = "") -> None:
        super().__init__(message)


FakePrecondition.__name__ = "PreconditionFailed"


class FakeGcsBucket:
    """Models the three retention states and the create-only precondition.

    A fake, with a fake's limits: it can show that the publisher asks for
    `if_generation_match=0` and that it maps a bucket's state to the right
    caveat, and it cannot show that any server refuses a delete. That is
    `tests/evidence/test_gcs_retention_live.py`, which runs against real GCS.
    """

    def __init__(
        self,
        *,
        retention_period: int | None = None,
        locked: bool | None = None,
        reload_error: Exception | None = None,
        upload_error: Exception | None = None,
    ) -> None:
        self.retention_period = retention_period
        # `None` and not `False` for an unlocked policy, which is what the
        # real client surfaces -- the JSON API omits `isLocked` entirely.
        self.retention_policy_locked = locked
        self.reload_error = reload_error
        self.upload_error = upload_error
        self.objects: dict[str, bytes] = {}
        self.uploads: list[dict[str, Any]] = []

    def reload(self) -> None:
        if self.reload_error is not None:
            raise self.reload_error

    def blob(self, key: str) -> FakeGcsBlob:
        return FakeGcsBlob(self, key)

    def get_blob(self, key: str) -> FakeGcsBlob | None:
        if key not in self.objects:
            return None
        blob = FakeGcsBlob(self, key)
        blob._hydrate()
        return blob


class FakeGcsClient:
    def __init__(self, bucket: FakeGcsBucket) -> None:
        self._bucket = bucket

    def bucket(self, name: str) -> FakeGcsBucket:
        return self._bucket


def gcs(bucket: FakeGcsBucket, **options: Any) -> GcsRetentionPublisher:
    publisher = GcsRetentionPublisher.from_config({"bucket": "anchors", **options})
    publisher._client = FakeGcsClient(bucket)
    return publisher


class TestTheGcsPublisher:
    def test_the_write_is_create_only(self) -> None:
        """On a locked bucket retention refuses an overwrite anyway; on a
        bucket with no policy this precondition is the only thing that turns a
        silent overwrite into a visible failure."""
        bucket = FakeGcsBucket(retention_period=3600, locked=True)
        receipt = gcs(bucket).publish(checkpoint())

        assert receipt.ok, receipt.error
        assert bucket.uploads[0]["if_generation_match"] == 0
        assert bucket.uploads[0]["content_type"] == "application/json"

    def test_the_published_bytes_are_the_canonical_record(self) -> None:
        bucket = FakeGcsBucket(retention_period=3600, locked=True)
        record = checkpoint()
        gcs(bucket).publish(record)

        key = f"checkpoints/{checkpoint_name(record)}"
        assert bucket.objects[key] == checkpoint_bytes(record)

    def test_a_locked_policy_carries_no_caveat(self) -> None:
        receipt = gcs(FakeGcsBucket(retention_period=3600, locked=True)).publish(checkpoint())

        assert receipt.ok
        assert receipt.error == ""
        assert receipt.proof["retention_locked"] is True
        assert receipt.proof["retention_period_seconds"] == 3600
        assert receipt.proof["retention_expires"]

    def test_an_unlocked_policy_is_reported_as_the_downgrade_it_is(self) -> None:
        """The middle state, which is the one that misleads: it refuses
        deletes, so it reads like protection, and an administrator can remove
        it and then delete. The analogue of object-lock GOVERNANCE."""
        receipt = gcs(FakeGcsBucket(retention_period=3600, locked=None)).publish(checkpoint())

        assert receipt.ok, "the copy landed"
        assert receipt.error == UNLOCKED_POLICY
        assert receipt.proof["retention_locked"] is False

    def test_no_policy_at_all_is_reported_too(self) -> None:
        receipt = gcs(FakeGcsBucket()).publish(checkpoint())

        assert receipt.ok
        assert receipt.error == NO_POLICY
        assert receipt.proof["retention_locked"] is False
        assert "retention_expires" not in receipt.proof
        assert "retention_period_seconds" not in receipt.proof

    def test_an_unlocked_policy_can_be_accepted_on_purpose(self) -> None:
        receipt = gcs(
            FakeGcsBucket(retention_period=3600, locked=None), require_locked=False
        ).publish(checkpoint())

        assert receipt.ok
        assert receipt.error == ""

    def test_a_bucket_with_no_policy_is_a_caveat_even_when_unlocked_is_accepted(self) -> None:
        """`require_locked: false` waives the lock, not the policy. A bucket
        with no retention at all provides nothing, and saying so is not
        something an operator can switch off by accident."""
        receipt = gcs(FakeGcsBucket(), require_locked=False).publish(checkpoint())

        assert receipt.ok
        assert receipt.error == NO_POLICY

    def test_republishing_the_same_checkpoint_is_idempotent(self) -> None:
        bucket = FakeGcsBucket(retention_period=3600, locked=True)
        record = checkpoint()
        first = gcs(bucket).publish(record)
        second = gcs(bucket).publish(record)

        assert first.ok and second.ok, second.error
        assert second.proof["generation"] == first.proof["generation"]

    def test_a_different_object_at_the_key_is_a_failure_and_is_not_overwritten(self) -> None:
        """Two different anchors for one checkpoint sequence should be
        impossible. If it happens, the operator hears about it."""
        bucket = FakeGcsBucket(retention_period=3600, locked=True)
        record = checkpoint()
        key = f"checkpoints/{checkpoint_name(record)}"
        bucket.objects[key] = b'{"not":"ours"}'

        receipt = gcs(bucket).publish(record)

        assert not receipt.ok
        assert "a different object is already published" in receipt.error
        assert bucket.objects[key] == b'{"not":"ours"}'

    def test_a_bucket_whose_metadata_cannot_be_read_still_publishes(self) -> None:
        """A least-privilege anchor writer holds `roles/storage.objectCreator`
        and cannot call `storage.buckets.get`. The object must still land, and
        the receipt must claim no protection it could not confirm."""
        bucket = FakeGcsBucket(
            retention_period=3600, locked=True, reload_error=RuntimeError("403 forbidden")
        )
        receipt = gcs(bucket).publish(checkpoint())

        assert receipt.ok
        assert receipt.proof["retention_locked"] is False
        assert receipt.error == NO_POLICY

    def test_an_upload_that_fails_is_a_receipt_and_not_an_exception(self) -> None:
        """A bucket that is unreachable must not stop the chain."""
        bucket = FakeGcsBucket(
            retention_period=3600, locked=True, upload_error=RuntimeError("no route to host")
        )
        receipt = gcs(bucket).publish(checkpoint())

        assert not receipt.ok
        assert "no route to host" in receipt.error

    def test_it_needs_a_bucket(self) -> None:
        with pytest.raises(PublicationError, match="needs a `bucket`"):
            GcsRetentionPublisher.from_config({})

    @pytest.mark.parametrize(
        ("value", "expected"),
        [("false", False), ("no", False), ("0", False), ("off", False), ("true", True)],
    )
    def test_require_locked_reads_yaml_strings(self, value: str, expected: bool) -> None:
        """A quoted `require_locked: "false"` must not read as true, which is
        what `bool("false")` would have done."""
        built = GcsRetentionPublisher.from_config({"bucket": "a", "require_locked": value})
        assert built.require_locked is expected

    def test_describe_carries_no_credential(self) -> None:
        built = GcsRetentionPublisher.from_config({"bucket": "anchors", "project": "acme"})
        described = built.describe()
        assert "gs://anchors/checkpoints/" in described
        assert "locked retention required" in described

    def test_the_install_hint_survives_a_namespace_package(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Without the `gcs` extra, the operator must be told what to install.

        The reason this is a test and not a one-liner: `google.cloud` is a
        **namespace package**, so with google-cloud-storage absent but any
        other `google-*` distribution present -- `google-api-core` comes with
        half of them -- `from google.cloud import storage` raises
        `ImportError` and not `ModuleNotFoundError`. The first version of this
        publisher caught the narrower class, copied from the S3 publisher
        where boto3 makes it correct, and an operator without the extra got
        `cannot import name 'storage' from 'google.cloud'` in a receipt
        instead of an install hint.

        The stub below reproduces exactly that: a `google.cloud` that exists
        and has no `storage` in it.
        """
        import sys
        import types

        monkeypatch.setitem(sys.modules, "google.cloud", types.ModuleType("google.cloud"))
        built = GcsRetentionPublisher.from_config({"bucket": "anchors"})

        with pytest.raises(PublicationError, match=r"valqore-qed\[gcs\]"):
            built.client

    def test_a_missing_extra_is_a_receipt_with_the_hint_in_it(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """And it reaches the chain as a failed receipt, not an exception."""
        import sys
        import types

        monkeypatch.setitem(sys.modules, "google.cloud", types.ModuleType("google.cloud"))
        receipt = GcsRetentionPublisher.from_config({"bucket": "anchors"}).publish(checkpoint())

        assert not receipt.ok
        assert "valqore-qed[gcs]" in receipt.error


# --------------------------------------------------------------------------
# Building them, and publishing to several
# --------------------------------------------------------------------------


class TestBuildingFromConfig:
    def test_each_type(self, tmp_path: Path) -> None:
        built = build_publishers(
            [
                {"type": "file", "path": str(tmp_path)},
                {"type": "s3-object-lock", "bucket": "anchors"},
                {"type": "gcs-retention", "bucket": "anchors"},
            ]
        )
        assert [publisher.kind for publisher in built] == [
            "file",
            "s3-object-lock",
            "gcs-retention",
        ]

    def test_an_unknown_type_is_refused(self) -> None:
        """A publisher that was ignored because nobody recognised its name
        would be an anchor the operator believes exists."""
        with pytest.raises(PublicationError, match="unknown checkpoint publisher"):
            build_publishers([{"type": "carrier-pigeon"}])

    def test_the_message_lists_what_is_available(self) -> None:
        with pytest.raises(PublicationError) as caught:
            build_publishers([{"type": "nope"}])
        for kind in ("file", "s3-object-lock", "gcs-retention", "git-tag"):
            assert kind in str(caught.value)

    def test_nothing_configured_builds_nothing(self) -> None:
        assert build_publishers([]) == []


class TestPublishingToSeveral:
    def test_every_target_is_tried_even_after_one_fails(self, tmp_path: Path) -> None:
        """They are independent anchors, and the point of configuring two is
        that one of them working is useful."""
        broken = tmp_path / "file-not-dir"
        broken.write_text("x", encoding="utf-8")
        publishers = build_publishers(
            [
                {"type": "file", "path": str(broken)},
                {"type": "file", "path": str(tmp_path / "good")},
            ]
        )
        receipts = publish_checkpoint(publishers, checkpoint())
        assert len(receipts) == 2
        assert [receipt.ok for receipt in receipts] == [False, True]

    def test_a_publisher_that_raises_becomes_a_failed_receipt(self) -> None:
        """The protocol says a publisher returns a receipt. One that raises
        anyway must not stop the maintenance tick, and with it the chain."""

        class Rude:
            kind = "rude"

            def publish(self, record: EvidenceRecord) -> Receipt:
                raise RuntimeError("no")

            def describe(self) -> str:  # pragma: no cover
                return "rude"

        receipts = publish_checkpoint([Rude()], checkpoint())  # type: ignore[list-item]
        assert not receipts[0].ok
        assert "raised instead of returning a receipt" in receipts[0].error


class TestTheReceipt:
    def test_the_payload_form_is_small_and_sorted(self) -> None:
        receipt = Receipt(
            publisher="file",
            target="/anchors/x.json",
            ok=True,
            proof={"z": 1, "a": 2},
        )
        payload = receipt.as_payload()
        assert list(payload) == ["publisher", "target", "ok", "at", "proof"]
        assert list(payload["proof"]) == ["a", "z"]  # type: ignore[index]

    def test_a_clean_receipt_carries_no_error_key(self) -> None:
        assert "error" not in Receipt(publisher="file", target="x", ok=True).as_payload()

    def test_a_failure_carries_the_reason(self) -> None:
        payload = Receipt(publisher="file", target="x", ok=False, error="gone").as_payload()
        assert payload["error"] == "gone"
