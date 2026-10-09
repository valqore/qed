"""Submitting a proposal to somebody else's instance (SPEC §12.5).

`tests/cli/test_cli_ci.py` covers the happy path against a real `qed serve`.
What is covered here is the set of answers that are **not** a verdict, because
every one of them has a wrong way to interpret it and the wrong way is always
the same: treat it as permission.
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from qed.adapters.remote import PROPOSALS, RemoteError, submit
from qed.core.schemas import ActionProposal, Decision

ADAPTER_ID = "adp_remote"
SECRET = "r" * 48


@pytest.fixture
def proposal() -> ActionProposal:
    from tests.conftest import BASE_PROPOSAL

    return ActionProposal.model_validate(BASE_PROPOSAL)


def answering(
    status: int, body: object, *, seen: list[httpx.Request] | None = None
) -> httpx.Client:
    def handler(request: httpx.Request) -> httpx.Response:
        if seen is not None:
            seen.append(request)
        if isinstance(body, str):
            return httpx.Response(status, text=body)
        return httpx.Response(status, json=body)

    return httpx.Client(transport=httpx.MockTransport(handler))


def send(proposal: ActionProposal, client: httpx.Client, url: str = "https://qed.example"):  # type: ignore[no-untyped-def]
    return submit(proposal, url=url, adapter_id=ADAPTER_ID, adapter_secret=SECRET, client=client)


class TestTheRequest:
    def test_it_is_signed_the_way_an_adapter_signs(self, proposal: ActionProposal) -> None:
        seen: list[httpx.Request] = []
        client = answering(200, {"verdict": {"decision": "ALLOW"}, "evidence_ref": "3"}, seen=seen)
        send(proposal, client)

        request = seen[0]
        assert request.url.path == PROPOSALS
        assert request.headers["X-QED-Adapter-Id"] == ADAPTER_ID
        assert request.headers["X-QED-Signature"]
        assert request.headers["content-type"] == "application/json"

    def test_the_body_is_the_proposal_as_the_kernel_canonicalises_it(
        self, proposal: ActionProposal
    ) -> None:
        """Not `json.dumps` of a dict. The signature covers these exact bytes,
        and a re-serialisation that reordered a key or changed a timestamp's
        precision would be a signature over something else."""
        seen: list[httpx.Request] = []
        client = answering(200, {"verdict": {"decision": "ALLOW"}}, seen=seen)
        send(proposal, client)
        assert seen[0].content == proposal.model_dump_json().encode("utf-8")

    def test_a_trailing_slash_in_the_url_is_tolerated(self, proposal: ActionProposal) -> None:
        seen: list[httpx.Request] = []
        client = answering(200, {"verdict": {"decision": "ALLOW"}}, seen=seen)
        send(proposal, client, url="https://qed.example/")
        assert str(seen[0].url) == f"https://qed.example{PROPOSALS}"


class TestTheVerdict:
    def test_an_allow_comes_back_whole(self, proposal: ActionProposal) -> None:
        client = answering(
            200, {"verdict": {"decision": "ALLOW"}, "evidence_ref": "7", "enforced": True}
        )
        remote = send(proposal, client)
        assert remote.decision is Decision.ALLOW
        assert remote.evidence_ref == "7"
        assert remote.effective_decision is Decision.ALLOW

    def test_an_approval_carries_the_id_to_wait_on(self, proposal: ActionProposal) -> None:
        client = answering(
            202,
            {
                "verdict": {"decision": "REQUIRE_APPROVAL"},
                "evidence_ref": "9",
                "approval": {"approval_id": "apr_1", "status": "pending"},
            },
        )
        remote = send(proposal, client)
        assert remote.decision is Decision.REQUIRE_APPROVAL
        assert remote.approval_id == "apr_1"

    def test_shadow_mode_is_reported_rather_than_applied(self, proposal: ActionProposal) -> None:
        """A pipeline that failed on a shadow BLOCK would make shadow mode
        useless for its one purpose."""
        client = answering(200, {"verdict": {"decision": "BLOCK"}, "enforced": False})
        remote = send(proposal, client)
        assert remote.decision is Decision.BLOCK
        assert remote.effective_decision is Decision.ALLOW

    def test_an_instance_that_does_not_report_enforcement_is_assumed_to_enforce(
        self, proposal: ActionProposal
    ) -> None:
        """An older instance leaving the field out is not a reason to treat its
        refusals as advisory."""
        client = answering(200, {"verdict": {"decision": "BLOCK"}})
        assert send(proposal, client).effective_decision is Decision.BLOCK

    def test_an_outbox_reference_is_passed_through_unchanged(
        self, proposal: ActionProposal
    ) -> None:
        """On the HA path the reference is an outbox id, not a number
        (ADR-0009). Parsing it as an integer here would turn a valid reference
        into an error."""
        client = answering(
            200, {"verdict": {"decision": "ALLOW"}, "evidence_ref": "01JBXYZ", "enforced": True}
        )
        assert send(proposal, client).evidence_ref == "01JBXYZ"


class TestWhatIsNotAVerdict:
    """Each of these has a wrong reading, and it is always "probably allowed"."""

    def test_an_http_error_is_an_error(self, proposal: ActionProposal) -> None:
        client = answering(500, {"title": "boom", "detail": "the chain is unavailable"})
        with pytest.raises(RemoteError, match="500"):
            send(proposal, client)

    def test_the_problem_detail_is_what_the_operator_sees(self, proposal: ActionProposal) -> None:
        """RFC 9457's `detail` is the field written for a person; a status code
        alone would send them to look it up."""
        client = answering(401, {"title": "Unauthorized", "detail": "unknown adapter adp_x"})
        with pytest.raises(RemoteError, match="unknown adapter adp_x"):
            send(proposal, client)

    def test_a_200_with_no_verdict_is_an_error(self, proposal: ActionProposal) -> None:
        client = answering(200, {"evidence_ref": "3"})
        with pytest.raises(RemoteError, match="no verdict"):
            send(proposal, client)

    def test_a_200_that_is_not_json_is_an_error(self, proposal: ActionProposal) -> None:
        """A proxy's HTML error page in front of the instance, typically."""
        client = answering(200, "<html>gateway</html>")
        with pytest.raises(RemoteError, match="no verdict"):
            send(proposal, client)

    def test_an_unknown_decision_is_an_error(self, proposal: ActionProposal) -> None:
        """A newer instance answering something this build has no behaviour
        for. Refusing is the only safe reading: a decision nobody can map is
        not an allowance."""
        client = answering(200, {"verdict": {"decision": "PROBABLY"}})
        with pytest.raises(RemoteError, match="unknown decision"):
            send(proposal, client)

    def test_an_unreachable_instance_is_an_error(self, proposal: ActionProposal) -> None:
        def refuse(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("connection refused", request=request)

        client = httpx.Client(transport=httpx.MockTransport(refuse))
        with pytest.raises(RemoteError, match="could not reach"):
            send(proposal, client)

    def test_the_error_never_contains_the_secret(self, proposal: ActionProposal) -> None:
        """It is in a header on a request that is about to appear in whatever
        the caller logs."""
        client = answering(403, {"detail": "bad signature"})
        with pytest.raises(RemoteError) as caught:
            send(proposal, client)
        assert SECRET not in str(caught.value)


class TestItDoesNotNeedTheKernel:
    def test_the_module_imports_without_a_session_or_a_key(self) -> None:
        """It is a client. A CI runner that had to open a session to submit a
        proposal would need a signing key, which is the thing `--server`
        exists to avoid."""
        source = Path("qed/adapters/remote.py").read_text(encoding="utf-8")
        for forbidden in ("open_session", "load_signer", "ChainWriter", "check_proposal"):
            assert forbidden not in source, forbidden

    def test_the_verdict_is_json_serialisable_for_a_build_log(
        self, proposal: ActionProposal
    ) -> None:
        client = answering(200, {"verdict": {"decision": "ALLOW"}, "evidence_ref": "3"})
        json.dumps(send(proposal, client).raw)
