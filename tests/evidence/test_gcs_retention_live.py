"""The GCS anchor, against real Google Cloud Storage (SPEC §10.4).

The companion to `test_s3_object_lock_live.py`, and it exists for the same
reason. `THREAT_MODEL.md` has one control for "the whole chain is rewritten by
the operator": a checkpoint root published somewhere the instance cannot
afterwards revise. Every other check the verifier makes is self-referential --
a chain rewritten wholesale and re-signed passes all of them -- so this row is
the one that needs a measurement behind it rather than a mock.

**Why a fake was not enough, concretely.** The GCS publisher was designed and
then deliberately left unbuilt for a day because the only local option,
`fsouza/fake-gcs-server`, turned out not to implement retention at all: it
accepts `retention_period`, reads it back as `None`, accepts the delete, and
the object is gone. A publisher tested only against that would have shipped an
anchor whose central claim had never been observed to hold anywhere. These
tests run against the real service instead, and assert the refusal rather than
the request.

Four things here are invisible to a fake, and two of them contradicted what the
API reference implies:

* that a retention policy refuses a delete **issued by a project owner** --
  the strongest principal the threat model has to deny, and the one a fake
  cannot speak for;
* that it refuses an overwrite as well, so an anchor cannot be replaced in
  place by one computed over a rewritten chain;
* that `retentionPolicy.isLocked` is **absent** from the JSON for an unlocked
  policy, so the client surfaces `None` rather than `False` -- which is why
  `GcsRetentionPublisher._retention` coerces with `bool()` and not `is True`;
* that `blob.retention_expiration_time` comes back populated, which is the
  server confirming the policy binds *this object* rather than the publisher
  restating its own request.

**The buckets.** `QED_TEST_GCS_BUCKET` is a bucket with a retention policy,
locked or not; these tests read which and assert the mapping either way, so
the same file runs against both. `QED_TEST_GCS_PLAIN_BUCKET` is a bucket with
no policy, for the degradation path. The credentials come from Application
Default Credentials and **must be allowed to delete**, because a delete
refused for lack of permission would prove nothing about retention -- which is
why the assertions below check that the refusal names the retention policy
instead of merely being a 403.

Skipped without those variables. Unlike the S3 job, CI does not currently set
them: there is no free, locally-runnable GCS that enforces retention, and the
real service needs a billing account. So these were run by hand against real
GCS and the results are in `docs/checkpoints.md`; the skip is honest about
what is and is not continuously verified.
"""

from __future__ import annotations

import os
import uuid
from datetime import datetime
from typing import Any

import pytest

from qed.core.schemas import Assurance, EvidenceRecord, EvidenceType, utcnow
from qed.infra.publishers.gcs import NO_POLICY, UNLOCKED_POLICY, GcsRetentionPublisher
from qed.infra.publishers.model import checkpoint_bytes

BUCKET_ENV = "QED_TEST_GCS_BUCKET"
PLAIN_ENV = "QED_TEST_GCS_PLAIN_BUCKET"
#: Gates the one class that changes bucket configuration. See
#: `TestWhyTheLockMatters`.
DESTRUCTIVE_ENV = "QED_TEST_GCS_DESTRUCTIVE"

BUCKET = os.environ.get(BUCKET_ENV, "")
PLAIN = os.environ.get(PLAIN_ENV, "")

pytestmark = [
    pytest.mark.slow,
    pytest.mark.skipif(
        not BUCKET, reason=f"set {BUCKET_ENV} to a retention bucket to run the GCS anchor tests"
    ),
]


def checkpoint() -> EvidenceRecord:
    """A checkpoint record with a random Merkle root.

    Random because `checkpoint_name` derives the object key from the seq and
    the root. A fixed root would make every test here publish to the same key
    in a bucket where **nothing can be deleted**, so the second test onwards
    would be asserting against whatever the first one left behind.
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
    """A client with delete permission, for attempting what must be refused."""
    storage = pytest.importorskip("google.cloud.storage", reason="the gcs extra is not installed")
    return storage.Client()


@pytest.fixture(scope="module")
def locked(admin: Any) -> bool:
    """Whether the retention bucket's policy is locked.

    Read from the bucket rather than declared in an environment variable. A
    locked policy can never be removed, so a test bucket is usually unlocked
    with a short period; asserting the *mapping* from the observed state to
    the receipt's caveat is the part that is worth checking, and it is worth
    checking in whichever state the operator's bucket happens to be in.
    """
    bucket = admin.bucket(BUCKET)
    bucket.reload()
    assert bucket.retention_period, (
        f"{BUCKET_ENV} must name a bucket with a retention policy; "
        f"gs://{BUCKET} has none, so nothing here would be testing retention"
    )
    return bool(bucket.retention_policy_locked)


def publisher(bucket: str, **options: Any) -> GcsRetentionPublisher:
    return GcsRetentionPublisher.from_config({"bucket": bucket, **options})


def refusal(exc: Exception) -> str:
    return str(exc)


class TestTheAnchorIsWritten:
    def test_the_real_api_accepts_the_call_this_publisher_makes(
        self, admin: Any, locked: bool
    ) -> None:
        """A create-only upload into a retention bucket, and the proof the
        server hands back. Nothing in a fake could have said whether
        `if_generation_match=0` composes with a retention policy."""
        receipt = publisher(BUCKET).publish(checkpoint())

        assert receipt.ok, receipt.error
        assert receipt.proof["generation"], "the server assigned a generation"
        assert receipt.proof["etag"]
        assert receipt.proof["md5"], "the server computed an md5"
        assert receipt.proof["retention_period_seconds"]
        assert receipt.proof["retention_locked"] is locked

    def test_the_server_confirms_retention_binds_this_object(self) -> None:
        """`retention_expiration_time` is the bucket's answer for when this
        object becomes deletable, not a date the publisher asked for. It is
        the difference between the receipt recording a request and recording
        a fact."""
        receipt = publisher(BUCKET).publish(checkpoint())

        assert receipt.ok, receipt.error
        assert receipt.proof["retention_expires"], (
            "a retention bucket must report when this object becomes deletable; "
            "fake-gcs-server returns None here, which is why it could not be used"
        )

    def test_the_bytes_an_auditor_reads_are_the_bytes_we_signed(self, admin: Any) -> None:
        record = checkpoint()
        receipt = publisher(BUCKET).publish(record)
        assert receipt.ok, receipt.error

        key = receipt.target.split(f"{BUCKET}/", 1)[1]
        blob = admin.bucket(BUCKET).get_blob(key)
        assert blob.download_as_bytes() == checkpoint_bytes(record)
        assert blob.content_type == "application/json"
        assert isinstance(blob.retention_expiration_time, datetime)

    def test_the_caveat_matches_what_the_bucket_actually_provides(self, locked: bool) -> None:
        """The three-state mapping, which is this publisher's whole addition
        over the S3 one. A locked policy is the analogue of object-lock
        COMPLIANCE and carries no caveat; an unlocked one is the analogue of
        GOVERNANCE and must say so in the receipt that goes into the chain."""
        receipt = publisher(BUCKET).publish(checkpoint())

        assert receipt.ok, receipt.error
        if locked:
            assert receipt.error == "", "a locked policy should carry no caveat"
        else:
            assert receipt.error == UNLOCKED_POLICY

    def test_an_operator_can_accept_an_unlocked_policy_on_purpose(self, locked: bool) -> None:
        """`require_locked: false` is the conscious downgrade, and it silences
        the caveat without changing what was published."""
        if locked:
            pytest.skip("the bucket's policy is locked, so there is no caveat to waive")
        receipt = publisher(BUCKET, require_locked=False).publish(checkpoint())

        assert receipt.ok
        assert receipt.error == ""
        assert receipt.proof["retention_locked"] is False


class TestTheAnchorCannotBeRemoved:
    """The control itself. Everything above is plumbing; this is the claim."""

    @pytest.fixture
    def published(self) -> str:
        receipt = publisher(BUCKET).publish(checkpoint())
        assert receipt.ok, receipt.error
        return receipt.target.split(f"{BUCKET}/", 1)[1]

    def test_deleting_the_anchor_is_refused(self, admin: Any, published: str) -> None:
        """Attempted with Application Default Credentials, which for these
        tests is a principal that *may* delete. The assertion names the
        retention policy on purpose: a 403 for lack of permission would pass a
        weaker test while proving nothing about retention at all."""
        from google.api_core import exceptions as gexc

        blob = admin.bucket(BUCKET).get_blob(published)
        with pytest.raises(gexc.Forbidden) as caught:
            blob.delete()

        assert "retention policy" in refusal(caught.value), (
            "the delete was refused, but not by retention -- so these credentials "
            "cannot demonstrate the control. Grant them delete permission."
        )
        assert admin.bucket(BUCKET).get_blob(published) is not None, "still there"

    def test_overwriting_the_anchor_is_refused(self, admin: Any, published: str) -> None:
        """The attack this anchor exists to stop is not deletion but
        *replacement*: an anchor swapped for one computed over a rewritten
        chain would still be present, and would still verify."""
        from google.api_core import exceptions as gexc

        original = admin.bucket(BUCKET).get_blob(published).download_as_bytes()
        with pytest.raises(gexc.Forbidden) as caught:
            admin.bucket(BUCKET).blob(published).upload_from_string(b'{"root":"rewritten"}')

        assert "retention policy" in refusal(caught.value)
        assert admin.bucket(BUCKET).get_blob(published).download_as_bytes() == original

    def test_republishing_the_same_checkpoint_is_idempotent(self) -> None:
        """A retry after a partial failure must not be reported as a
        collision. The create-only precondition fails on the second attempt,
        and the publisher compares the stored bytes before deciding what that
        means."""
        record = checkpoint()
        first = publisher(BUCKET).publish(record)
        second = publisher(BUCKET).publish(record)

        assert first.ok, first.error
        assert second.ok, second.error
        assert second.proof["generation"] == first.proof["generation"], "the same object"

    def test_a_different_object_at_the_key_is_reported_not_overwritten(self, admin: Any) -> None:
        """Two different anchors for one checkpoint sequence should be
        impossible. If it happens anyway, the operator hears about it instead
        of one of them quietly replacing the other."""
        record = checkpoint()
        from qed.infra.publishers.model import checkpoint_name

        key = f"checkpoints/{checkpoint_name(record)}"
        admin.bucket(BUCKET).blob(key).upload_from_string(b'{"not":"ours"}')

        receipt = publisher(BUCKET).publish(record)

        assert not receipt.ok
        assert "a different object is already published" in receipt.error
        assert admin.bucket(BUCKET).get_blob(key).download_as_bytes() == b'{"not":"ours"}'


class TestWhyTheLockMatters:
    """The three-state argument's last link, measured rather than asserted.

    The publisher's docstring says an unlocked policy "stops an accident, not
    an operator". That is the kind of sentence that reads like reasoning and
    can still be wrong, so it is a test: remove the policy, delete the anchor,
    put the policy back. On a locked bucket the same removal is refused, which
    is the other half of the same claim and the reason `require_locked`
    defaults to true.

    **Opt-in separately.** This is the only test in the file that changes the
    bucket's configuration and destroys an object, and `QED_TEST_GCS_BUCKET`
    pointed at a real anchor bucket by mistake must not lose its policy to a
    test run. `QED_TEST_GCS_DESTRUCTIVE=1` is the second key.
    """

    @pytest.fixture(autouse=True)
    def _opted_in(self) -> None:
        if not os.environ.get(DESTRUCTIVE_ENV):
            pytest.skip(f"set {DESTRUCTIVE_ENV}=1 to let this mutate the bucket's retention policy")

    def test_an_unlocked_policy_can_be_removed_and_the_anchor_then_deleted(
        self, admin: Any, locked: bool
    ) -> None:
        if locked:
            pytest.skip("the policy is locked; the test below covers that state")

        receipt = publisher(BUCKET).publish(checkpoint())
        assert receipt.ok
        key = receipt.target.split(f"{BUCKET}/", 1)[1]
        bucket = admin.bucket(BUCKET)
        bucket.reload()
        period = bucket.retention_period

        try:
            bucket.retention_period = None
            bucket.patch()
            # The anchor the policy was refusing to delete a moment ago.
            bucket.get_blob(key).delete()
            assert bucket.get_blob(key) is None, "gone, which is the weakness"
        finally:
            bucket.retention_period = period
            bucket.patch()

    def test_a_locked_policy_cannot_be_removed(self, admin: Any, locked: bool) -> None:
        """What `require_locked` is actually buying. A locked policy can never
        be shortened or removed -- not by the uploader, not by a project owner
        -- which is what makes a GCS anchor the equal of an S3 object-lock one
        in COMPLIANCE mode."""
        if not locked:
            pytest.skip("the policy is unlocked; the test above covers that state")
        from google.api_core import exceptions as gexc

        bucket = admin.bucket(BUCKET)
        bucket.retention_period = None
        with pytest.raises((gexc.Forbidden, gexc.BadRequest)):
            bucket.patch()

        bucket.reload()
        assert bucket.retention_period, "the policy is still there"
        assert bucket.retention_policy_locked


class TestABucketWithoutARetentionPolicy:
    """The degradation path, against a server rather than a fake."""

    @pytest.fixture(autouse=True)
    def _needs_plain(self) -> None:
        if not PLAIN:
            pytest.skip(f"set {PLAIN_ENV} to a bucket with no retention policy")

    def test_the_upload_succeeds_and_the_receipt_says_what_it_is_not(self) -> None:
        receipt = publisher(PLAIN).publish(checkpoint())

        assert receipt.ok, receipt.error
        assert receipt.proof["retention_locked"] is False
        assert receipt.error == NO_POLICY
        assert "retention_expires" not in receipt.proof, (
            "no policy means the server reports no expiration, and the receipt must not imply one"
        )

    def test_the_object_is_deletable_which_is_the_point(self, admin: Any) -> None:
        receipt = publisher(PLAIN).publish(checkpoint())
        key = receipt.target.split(f"{PLAIN}/", 1)[1]
        admin.bucket(PLAIN).get_blob(key).delete()


def test_a_bucket_that_does_not_exist_is_a_receipt_and_not_an_exception() -> None:
    """The same guarantee as the fake's version of this test, against a real
    client: a missing bucket must not raise into the chain writer."""
    receipt = publisher(f"qed-no-such-bucket-{uuid.uuid4().hex[:12]}").publish(checkpoint())

    assert not receipt.ok
    assert receipt.error
