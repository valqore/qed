"""The self-governance gate's decision order (SPEC §17). Pure.

:func:`~qed.core.admin.decide_admin` takes every fact as an argument, so the
part with security content -- *which check runs first* -- is testable without a
chain, a store or a clock. The end-to-end behaviour is in
`tests/cli/test_admin_self_governance.py`.

The order is the content. Four of these tests exist only to pin an ordering
decision that would otherwise be an accident of how the function was written:

* `break_glass` after the governed check, so passing it on an ungoverned
  instance does not record a false emergency;
* `break_glass` before the approval checks, so an operator in an incident is
  not told to go and find an approval id first;
* the requester check before everything but the governed check, because
  without a requester there is nobody for separation of duties to exclude;
* the binding and single-use checks last, because both presuppose an approval
  that exists and is approved.
"""

from __future__ import annotations

import pytest

from qed.core.admin import (
    APPROVAL_FIELD,
    AdminOperation,
    AdminRefusal,
    decide_admin,
)

ROTATE = AdminOperation.keys_rotate
IMPORT = AdminOperation.packs_import
GOVERNED = frozenset({ROTATE, IMPORT})


def decide(**overrides: object):  # type: ignore[no-untyped-def]
    """`decide_admin` with the governed-and-approved happy path as the default."""
    kwargs: dict[str, object] = {
        "governed_operations": GOVERNED,
        "approval_id": "apr_1",
        "approval_status": "approved",
        "approval_operation": ROTATE,
        "approval_already_spent": False,
        "break_glass_reason": "",
        "requester": "alice@example.com",
    }
    kwargs.update(overrides)
    return decide_admin(overrides.pop("operation", ROTATE), **kwargs)  # type: ignore[arg-type]


class TestAnUngovernedInstance:
    def test_it_proceeds_with_nothing(self) -> None:
        verdict = decide_admin(
            ROTATE,
            governed_operations=frozenset(),
            approval_id=None,
            approval_status=None,
            approval_operation=None,
            approval_already_spent=False,
            break_glass_reason="",
            requester="",
        )
        assert verdict.allowed
        assert verdict.governed is False

    def test_the_record_says_it_was_ungated_by_configuration(self) -> None:
        """So an auditor can tell an unapproved rotation that was unapproved
        *by configuration* from one that evaded a gate. A missing field would
        leave them to assume."""
        verdict = decide_admin(
            ROTATE,
            governed_operations=frozenset(),
            approval_id=None,
            approval_status=None,
            approval_operation=None,
            approval_already_spent=False,
            break_glass_reason="",
            requester="",
        )
        assert verdict.payload() == {"self_governed": False}

    def test_break_glass_is_not_recorded_as_an_emergency(self) -> None:
        """A script may always pass `--break-glass`. Recording an emergency
        override on an instance with no gate would put a false alarm in an
        immutable chain, which is worse than ignoring the flag."""
        verdict = decide_admin(
            ROTATE,
            governed_operations=frozenset(),
            approval_id=None,
            approval_status=None,
            approval_operation=None,
            approval_already_spent=False,
            break_glass_reason="the key leaked",
            requester="alice@example.com",
        )
        assert verdict.allowed
        assert verdict.break_glass is False
        assert "break_glass" not in verdict.payload()
        assert "ignored" in verdict.reason

    def test_an_operation_outside_the_governed_set_is_ungated(self) -> None:
        """`operations: [packs_import]` must not gate a key rotation."""
        verdict = decide_admin(
            ROTATE,
            governed_operations=frozenset({IMPORT}),
            approval_id=None,
            approval_status=None,
            approval_operation=None,
            approval_already_spent=False,
            break_glass_reason="",
            requester="",
        )
        assert verdict.allowed
        assert verdict.governed is False


class TestAGovernedInstance:
    def test_an_approved_binding_approval_proceeds(self) -> None:
        verdict = decide()
        assert verdict.allowed
        assert verdict.governed is True
        assert verdict.approval_id == "apr_1"
        assert verdict.payload()[APPROVAL_FIELD] == "apr_1"

    def test_no_requester_is_refused_before_anything_else(self) -> None:
        """Without a requester there is nobody for separation of duties to
        exclude, so an approval would be meaningless even if one existed."""
        with pytest.raises(AdminRefusal, match="who is asking"):
            decide(requester="")

    def test_no_approval_says_what_to_do(self) -> None:
        with pytest.raises(AdminRefusal) as caught:
            decide(approval_id=None)
        message = str(caught.value)
        assert "--approval" in message
        assert "--break-glass" in message

    def test_a_pending_approval_names_the_command_and_the_exclusion(self) -> None:
        with pytest.raises(AdminRefusal) as caught:
            decide(approval_status="pending")
        message = str(caught.value)
        assert "qed approve" in message
        assert "other than alice@example.com" in message

    def test_a_denied_approval_does_not_proceed(self) -> None:
        with pytest.raises(AdminRefusal, match="not approved"):
            decide(approval_status="denied")

    def test_an_approval_for_another_operation_is_refused(self) -> None:
        """ "Approve the catalogue import" is a smaller ask than "approve
        rotating the signing key". Spending one on the other reads as an
        administrative slip and works as a privilege escalation."""
        with pytest.raises(AdminRefusal, match="granted for packs_import"):
            decide(approval_operation=IMPORT)

    def test_an_approval_for_no_known_operation_is_refused(self) -> None:
        """An approval that came from the ordinary agent path has no admin
        operation behind it, so it cannot authorise one."""
        with pytest.raises(AdminRefusal, match="unknown operation"):
            decide(approval_operation=None)

    def test_a_spent_approval_is_refused(self) -> None:
        with pytest.raises(AdminRefusal, match="already been used"):
            decide(approval_already_spent=True)


class TestBreakGlass:
    def test_it_proceeds_and_is_recorded(self) -> None:
        verdict = decide(approval_id=None, break_glass_reason="INC-412, key leaked")
        assert verdict.allowed
        assert verdict.break_glass is True
        payload = verdict.payload()
        assert payload["break_glass"] is True
        assert payload["break_glass_reason"] == "INC-412, key leaked"
        assert payload["self_governed"] is True

    def test_it_does_not_need_an_approval_id(self) -> None:
        """The whole point: the approver is asleep. Requiring an id would mean
        requiring the thing that is unavailable."""
        assert decide(approval_id=None, break_glass_reason="why").allowed

    def test_it_beats_a_pending_approval(self) -> None:
        """An operator who asked, got no answer, and then declared an incident
        should not have to cancel the request first."""
        verdict = decide(approval_status="pending", break_glass_reason="no answer in 40m")
        assert verdict.break_glass is True

    def test_it_still_needs_a_requester(self) -> None:
        """An emergency is not a reason to stop recording who acted -- that is
        the one fact an incident review will want."""
        with pytest.raises(AdminRefusal, match="who is asking"):
            decide(requester="", break_glass_reason="why")

    def test_it_does_not_bypass_a_spent_approval_check_by_accident(self) -> None:
        """Break-glass is an alternative to an approval, not a way to reuse
        one: the recorded authorisation is the reason, not the id."""
        verdict = decide(break_glass_reason="why", approval_already_spent=True)
        assert verdict.break_glass is True
        assert APPROVAL_FIELD not in verdict.payload()


class TestTheOperationNames:
    def test_the_spec_names_are_all_present(self) -> None:
        """SPEC §17 lists `policies:reload` and `keys:rotate`. `policy_reload`
        has no command behind it yet and is in the enum anyway: a name in a
        config that the enum does not know would be the quiet failure the
        validator exists to prevent."""
        assert {item.value for item in AdminOperation} >= {
            "keys_rotate",
            "packs_import",
            "policy_reload",
        }

    def test_they_are_snake_case(self) -> None:
        """`keys:rotate` in the spec, `keys_rotate` here -- a colon in a YAML
        list item is a parsing hazard for no benefit."""
        for item in AdminOperation:
            assert item.value.islower()
            assert ":" not in item.value
