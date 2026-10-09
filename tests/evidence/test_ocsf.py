"""OCSF events for a SIEM (SPEC §18, `docs/siem.md`).

Two things are being checked, and the second is why the first matters.

**The mapping is the one a SIEM expects.** A verdict is Authorization (3003),
because that is the class that exists for "a request was allowed or denied";
everything else is API Activity (6003). Getting a class_uid wrong does not
fail: the event is ingested, lands in the wrong dashboard, and is noticed when
somebody cannot find it.

**No principal, target or payload leaves the instance.** A SIEM event is a copy
shipped to a system with different access controls, and the chain's own
discipline -- principals as hashes, targets out of anything exported -- has to
hold here too or it holds nowhere.
"""

from __future__ import annotations

import json

import pytest

from qed.core.evidence.export.ocsf import (
    ACTIVITY_ALLOW,
    ACTIVITY_DENY,
    CLASS_API_ACTIVITY,
    CLASS_AUTHORIZATION,
    SCHEMA_VERSION,
    to_ocsf,
)
from qed.core.schemas import Assurance, EvidenceRecord, EvidenceType, Mode, utcnow

HASH = "a" * 64
PRINCIPAL = "p" * 64


def record(
    type_: EvidenceType,
    payload: dict[str, object] | None = None,
    *,
    mode: Mode | None = None,
) -> EvidenceRecord:
    return EvidenceRecord(
        seq=7,
        ts=utcnow(),
        type=type_,
        assurance=Assurance.kernel,
        payload=payload if payload is not None else {},
        payload_hash="b" * 64,
        prev_hash="c" * 64,
        hash=HASH,
        key_id="ed25519:0123456789abcdef",
        sig="s" * 86,
        mode=mode,
    )


def verdict(decision: str, *, hits: list[dict[str, object]] | None = None, **extra: object):  # type: ignore[no-untyped-def]
    return {
        "verdict": {
            "proposal_id": "01JBPROPOSAL00000000000000",
            "decision": decision,
            "policy_hash": "d" * 64,
            "hits": hits or [],
            **extra,
        }
    }


def event(type_: EvidenceType, payload: dict[str, object] | None = None, **kwargs):  # type: ignore[no-untyped-def]
    return to_ocsf(record(type_, payload, **kwargs), instance_id="qed-test")


# --------------------------------------------------------------------------
# The class mapping
# --------------------------------------------------------------------------


class TestWhichClass:
    def test_a_verdict_is_authorization(self) -> None:
        """The class that exists for "a request was allowed or denied"."""
        mapped = event(EvidenceType.verdict, verdict("ALLOW"))
        assert mapped["class_uid"] == CLASS_AUTHORIZATION
        assert mapped["class_name"] == "Authorization"
        assert mapped["category_uid"] == 3

    def test_an_approval_decision_is_authorization_too(self) -> None:
        """An approval is an authorization decision made by a person rather
        than by a rule. Putting it in an Entity Management class would split
        one question -- who allowed this? -- across two dashboards."""
        mapped = event(
            EvidenceType.approval_decided,
            {"approval_id": "apr_1", "decision": "approve_once"},
        )
        assert mapped["class_uid"] == CLASS_AUTHORIZATION

    @pytest.mark.parametrize(
        "type_",
        [
            EvidenceType.proposal,
            EvidenceType.execution_result,
            EvidenceType.budget_update,
            EvidenceType.key_rotated,
            EvidenceType.checkpoint,
            EvidenceType.admin_action,
        ],
    )
    def test_everything_else_is_api_activity(self, type_: EvidenceType) -> None:
        assert event(type_)["class_uid"] == CLASS_API_ACTIVITY

    def test_the_type_uid_is_class_times_hundred_plus_activity(self) -> None:
        """OCSF's own rule, and a consumer indexes on it."""
        mapped = event(EvidenceType.verdict, verdict("ALLOW"))
        assert mapped["type_uid"] == CLASS_AUTHORIZATION * 100 + ACTIVITY_ALLOW


class TestTheActivity:
    def test_allow_is_assign_privileges(self) -> None:
        mapped = event(EvidenceType.verdict, verdict("ALLOW"))
        assert mapped["activity_id"] == ACTIVITY_ALLOW
        assert mapped["activity_name"] == "Assign Privileges"

    def test_block_is_revoke_privileges(self) -> None:
        mapped = event(EvidenceType.verdict, verdict("BLOCK"))
        assert mapped["activity_id"] == ACTIVITY_DENY

    def test_require_approval_is_unknown_and_says_so_in_action(self) -> None:
        """OCSF's activity_id has no third value, and REQUIRE_APPROVAL is the
        verdict a reviewer cares about most. Forcing it to Allow would report
        a grant that has not happened, so it is Unknown with the real decision
        beside it."""
        mapped = event(EvidenceType.verdict, verdict("REQUIRE_APPROVAL"))
        assert mapped["activity_id"] == 0
        assert mapped["action"] == "REQUIRE_APPROVAL"

    def test_the_decision_always_travels_verbatim(self) -> None:
        for decision in ("ALLOW", "BLOCK", "REQUIRE_APPROVAL"):
            assert event(EvidenceType.verdict, verdict(decision))["action"] == decision


class TestTheSeverity:
    def test_a_block_is_high(self) -> None:
        assert event(EvidenceType.verdict, verdict("BLOCK"), mode=Mode.enforce)["severity_id"] == 4

    def test_a_shadow_block_is_lower(self) -> None:
        """It stopped nothing. Paging on a shadow-mode BLOCK would train people
        to ignore the channel, which is the opposite of what a SIEM feed is
        for."""
        enforced = event(EvidenceType.verdict, verdict("BLOCK"), mode=Mode.enforce)
        shadow = event(EvidenceType.verdict, verdict("BLOCK"), mode=Mode.shadow)
        assert int(str(shadow["severity_id"])) < int(str(enforced["severity_id"]))

    def test_an_allow_is_informational(self) -> None:
        assert event(EvidenceType.verdict, verdict("ALLOW"))["severity_id"] == 1

    def test_an_ungated_window_is_high(self) -> None:
        """An adapter proceeded without a verdict. The one API Activity record
        that is an incident rather than a log line."""
        assert event(EvidenceType.ungated_window)["severity_id"] == 4

    def test_the_severity_is_not_the_rule_severity(self) -> None:
        """A CRITICAL rule that fired in shadow mode stopped nothing."""
        hits = [{"rule_id": "AG-X-001", "severity": "CRITICAL", "message": "m"}]
        mapped = event(EvidenceType.verdict, verdict("ALLOW", hits=hits), mode=Mode.shadow)
        assert mapped["severity_id"] == 1


class TestTheRules:
    def test_the_rules_that_decided_it_are_carried(self) -> None:
        hits = [
            {"rule_id": "AG-BLR-003", "severity": "HIGH", "message": "Destructive change"},
            {"rule_id": "AG-BLR-005", "severity": "HIGH", "message": "Score above 60"},
        ]
        mapped = event(EvidenceType.verdict, verdict("BLOCK", hits=hits))
        authorizations = mapped["authorizations"]
        assert isinstance(authorizations, list)
        assert [a["policy"]["uid"] for a in authorizations] == ["AG-BLR-003", "AG-BLR-005"]
        assert all(a["decision"] == "BLOCK" for a in authorizations)

    def test_no_rules_means_no_authorizations_key(self) -> None:
        """Absent rather than empty: OCSF consumers treat an empty list as "we
        looked and there were none", which is not what a default-verdict
        decision means."""
        assert "authorizations" not in event(EvidenceType.verdict, verdict("ALLOW"))

    def test_the_policy_hash_is_a_label(self) -> None:
        """Which bundle decided it. The one thing that makes a historical
        verdict re-explicable."""
        mapped = event(EvidenceType.verdict, verdict("ALLOW"))
        metadata = mapped["metadata"]
        assert isinstance(metadata, dict)
        assert f"policy_hash:{'d' * 64}" in metadata["labels"]  # type: ignore[operator]


# --------------------------------------------------------------------------
# What must not leak
# --------------------------------------------------------------------------


class TestWhatDoesNotLeave:
    def test_a_principal_appears_only_as_a_hash(self) -> None:
        payload = {
            "proposal": {
                "id": "01JBX",
                "principal": {
                    "human_hash": PRINCIPAL,
                    "agent_chain": ["claude-code@laptop"],
                },
                "action": {"name": "github.list_issues", "target": "repo:acme/payments"},
            }
        }
        mapped = event(EvidenceType.proposal, payload)
        actor = mapped["actor"]
        assert isinstance(actor, dict)
        assert actor["user"] == {"uid": PRINCIPAL}
        assert "name" not in actor["user"]  # type: ignore[operator]
        assert "email_addr" not in str(mapped)

    def test_the_target_never_leaves(self) -> None:
        """The verb, never the target. A target is the half of an action that
        names somebody's data, and a SIEM event goes to a system with
        different access controls."""
        payload = {
            "proposal": {"action": {"name": "postgres.execute_sql", "target": "db:prod/orders"}}
        }
        mapped = event(EvidenceType.proposal, payload)
        assert "db:prod/orders" not in json.dumps(mapped)
        api = mapped["api"]
        assert isinstance(api, dict)
        assert api["operation"] == "postgres.execute_sql"

    def test_a_redacted_parameter_never_leaves(self) -> None:
        payload = {
            "proposal": {
                "action": {
                    "name": "x",
                    "params_redacted": {"sql": "DROP TABLE orders_archive"},
                }
            }
        }
        assert "orders_archive" not in json.dumps(event(EvidenceType.proposal, payload))

    def test_the_whole_payload_is_not_shipped(self) -> None:
        """An event is a derived view. Shipping the payload would make the SIEM
        a second evidence store with none of the first one's properties."""
        payload = {"secret_looking": "value-that-should-not-travel"}
        assert "value-that-should-not-travel" not in json.dumps(
            event(EvidenceType.budget_update, payload)
        )


# --------------------------------------------------------------------------
# Correlation
# --------------------------------------------------------------------------


class TestCorrelation:
    def test_the_record_hash_is_an_observable(self) -> None:
        """How somebody gets from an alert back to the evidence entry.
        `type_id: 10` is Fingerprint, which is what a record hash is."""
        mapped = event(EvidenceType.verdict, verdict("ALLOW"))
        observables = mapped["observables"]
        assert isinstance(observables, list)
        assert {"name": "record.hash", "type_id": 10, "value": HASH} in observables

    def test_the_instance_is_an_observable(self) -> None:
        mapped = event(EvidenceType.verdict, verdict("ALLOW"))
        assert any(
            o["value"] == "qed-test"
            for o in mapped["observables"]  # type: ignore[union-attr]
        )

    def test_raw_data_points_at_the_chain_entry(self) -> None:
        """instance and sequence number, which is enough to find the record."""
        assert event(EvidenceType.verdict, verdict("ALLOW"))["raw_data"] == "qed:qed-test:7"

    def test_the_proposal_id_joins_a_verdict_to_its_proposal(self) -> None:
        """A verdict event carries no action name -- the proposal event has it
        -- and this is how a SIEM puts the two together."""
        mapped = event(EvidenceType.verdict, verdict("ALLOW"))
        unmapped = mapped["unmapped"]
        assert isinstance(unmapped, dict)
        assert unmapped["qed_proposal_id"] == "01JBPROPOSAL00000000000000"

    def test_a_supplied_principal_reaches_a_verdict_event(self) -> None:
        """A verdict's payload holds the verdict and a proposal id, so without
        this the Authorization event -- the one a SIEM cares about most --
        would have `actor: unknown`."""
        mapped = to_ocsf(
            record(EvidenceType.verdict, verdict("BLOCK")),
            instance_id="qed-test",
            principal_hash=PRINCIPAL,
        )
        assert mapped["actor"]["user"]["uid"] == PRINCIPAL  # type: ignore[index]

    def test_the_event_says_the_chain_is_the_authority(self) -> None:
        """A SIEM event is unsigned and derived. Pointing at the verifier is
        how an auditor knows not to treat this as the record."""
        unmapped = event(EvidenceType.verdict, verdict("ALLOW"))["unmapped"]
        assert isinstance(unmapped, dict)
        assert "qed-verify" in str(unmapped["qed_verify_with"])
        assert unmapped["qed_record_hash"] == HASH
        assert unmapped["qed_key_id"] == "ed25519:0123456789abcdef"


class TestTheEnvelope:
    def test_the_schema_version_is_named(self) -> None:
        """A consumer's parser is written against a version, and a silent
        change of shape breaks an ingestion pipeline a month later."""
        metadata = event(EvidenceType.verdict, verdict("ALLOW"))["metadata"]
        assert isinstance(metadata, dict)
        assert metadata["version"] == SCHEMA_VERSION

    def test_the_product_is_named(self) -> None:
        metadata = event(EvidenceType.proposal)["metadata"]
        assert isinstance(metadata, dict)
        assert metadata["product"]["vendor_name"] == "Valqore"  # type: ignore[index]

    def test_every_event_is_json_serialisable(self) -> None:
        for type_ in EvidenceType:
            json.dumps(event(type_, verdict("ALLOW") if type_ is EvidenceType.verdict else {}))

    def test_a_purged_payload_still_maps(self) -> None:
        """Retention clears payloads. An event for a purged record is thinner
        and must not be an exception."""
        purged = EvidenceRecord(
            seq=3,
            ts=utcnow(),
            type=EvidenceType.proposal,
            assurance=Assurance.kernel,
            payload=None,
            payload_hash="b" * 64,
            prev_hash="c" * 64,
            hash=HASH,
            key_id="k",
            sig="s" * 86,
        )
        mapped = to_ocsf(purged, instance_id="qed-test")
        assert mapped["class_uid"] == CLASS_API_ACTIVITY
        assert mapped["actor"]["user"]["uid"] == "unknown"  # type: ignore[index]
