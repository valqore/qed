"""What an HTTP request becomes (SPEC §12.3, §3.1).

Two properties carry the weight here. The target has to be a URL, because
``match_upstream`` finds a host glob by splitting on ``://`` and the shipped
``AG-DAT-003`` egress rule matches ``action.target`` against ``*://*`` -- so a
target in some other shape would silently stop both of them working. And a
tunnel has to claim nothing it cannot see.
"""

from __future__ import annotations

import pytest

from gate.adapters.http_proxy.proxy import INTENT_HEADER, HttpProxyOptions, build_http_proposal
from gate.adapters.http_proxy.targets import classify_method, derive_target
from gate.adapters.http_proxy.wire import parse_headers, parse_request_line, resolve_target
from gate.core.broker.model import Upstream, UpstreamSet, match_upstream
from gate.core.evidence.hashing import principal_hash
from gate.core.policy.engine import evaluate
from gate.core.policy.loader import baseline_pack_dir, load_bundle
from gate.core.schemas import (
    ActionKind,
    BudgetState,
    Decision,
    Enforcement,
    EvalContext,
    Mode,
    utcnow,
)

OPTIONS = HttpProxyOptions(
    environment="prod",
    human_hash=principal_hash("ali@example.com"),
    enforcement=Enforcement.enforcing,
)


def proposal(request_line: str, *headers: str, **kwargs: object):  # type: ignore[no-untyped-def]
    line = parse_request_line(request_line.encode())
    parsed = parse_headers("\r\n".join(headers).encode())
    target = resolve_target(line, parsed)
    return build_http_proposal(
        line=line,
        target=target,
        headers=parsed,
        options=OPTIONS,
        mode=Mode.enforce,
        **kwargs,  # type: ignore[arg-type]
    )


class TestTheTarget:
    def test_a_plain_request_becomes_a_url(self) -> None:
        built, _ = proposal("POST http://api.test/v1/charges HTTP/1.1")
        assert built.action.target == "http://api.test/v1/charges"
        assert built.action.name == "POST /v1/charges"
        assert built.action.kind is ActionKind.http
        assert built.action.method == "POST"

    def test_a_tunnel_becomes_an_https_url_with_no_path(self) -> None:
        built, _ = proposal("CONNECT api.stripe.com:443 HTTP/1.1")
        assert built.action.target == "https://api.stripe.com"
        assert built.action.name == "CONNECT api.stripe.com"

    def test_the_query_is_not_in_the_target(self) -> None:
        """It carries tokens and its order varies between calls that mean the
        same thing; either would make a policy glob leaky or useless."""
        built, _ = proposal("GET http://api.test/v1/x?token=abc123&page=2 HTTP/1.1")
        assert built.action.target == "http://api.test/v1/x"
        assert "abc123" not in built.action.target

    def test_the_query_is_in_the_parameters_where_a_rule_can_see_it(self) -> None:
        built, _ = proposal("GET http://api.test/v1/x?token=abc123 HTTP/1.1")
        assert built.action.params_redacted is not None
        assert built.action.params_redacted["query"] == "token=abc123"

    def test_a_bare_root_and_an_empty_path_are_one_target(self) -> None:
        assert derive_target("https", "api.test", "/") == derive_target("https", "api.test", "")

    def test_the_host_glob_in_an_upstream_match_still_works(self) -> None:
        """The reason the target is a URL: `match_upstream` reads the host by
        splitting the target on `://`."""
        built, _ = proposal("GET https://ec2.amazonaws.com/?Action=X HTTP/1.1")
        upstreams = UpstreamSet(
            upstreams=[
                Upstream.model_validate(
                    {"id": "aws", "kind": "http", "match": {"host_globs": ["*.amazonaws.com"]}}
                )
            ]
        )
        matched = match_upstream(built, upstreams)
        assert matched is not None
        assert matched.id == "aws"

    def test_a_lookalike_host_does_not_match_the_glob(self) -> None:
        built, _ = proposal("GET https://ec2.amazonaws.com.evil.test/ HTTP/1.1")
        upstreams = UpstreamSet(
            upstreams=[
                Upstream.model_validate(
                    {"id": "aws", "kind": "http", "match": {"host_globs": ["*.amazonaws.com"]}}
                )
            ]
        )
        assert match_upstream(built, upstreams) is None


class TestBlastHints:
    @pytest.mark.parametrize("method", ["GET", "HEAD", "OPTIONS", "TRACE"])
    def test_a_safe_method_writes_nothing(self, method: str) -> None:
        built, intent = proposal(f"{method} http://api.test/v1/orders HTTP/1.1")
        assert built.context.blast_radius_hints.writes is False
        assert intent.change_type == "read"

    @pytest.mark.parametrize(
        ("method", "change"),
        [("POST", "create"), ("PUT", "update"), ("PATCH", "update"), ("DELETE", "delete")],
    )
    def test_an_unsafe_method_writes(self, method: str, change: str) -> None:
        _, intent = proposal(f"{method} http://api.test/v1/orders/8812 HTTP/1.1")
        assert intent.writes is True
        assert intent.change_type == change

    def test_only_delete_deletes(self) -> None:
        _, patch = proposal("PATCH http://api.test/v1/orders/1 HTTP/1.1")
        _, delete = proposal("DELETE http://api.test/v1/orders/1 HTTP/1.1")
        assert patch.deletes is False
        assert delete.deletes is True

    def test_deleting_a_collection_is_wider_than_deleting_an_item(self) -> None:
        _, collection = proposal("DELETE http://api.test/v1/orders HTTP/1.1")
        _, item = proposal("DELETE http://api.test/v1/orders/8812 HTTP/1.1")
        assert collection.scope == "multi_resource"
        assert item.scope == "single_resource"

    @pytest.mark.parametrize(
        "last", ["8812", "01J9ZQ8XK4WZ2M3N4P5Q6R7S8T", "config.json", "a" * 40]
    )
    def test_an_identifier_shaped_segment_reads_as_one_resource(self, last: str) -> None:
        _, intent = proposal(f"DELETE http://api.test/v1/orders/{last} HTTP/1.1")
        assert intent.scope == "single_resource"

    def test_a_tunnel_claims_nothing_about_what_it_does(self) -> None:
        """Guessing `writes=True` would route every TLS connection to an
        approver; guessing `writes=False` would tell the scorer the connection
        is harmless. Neither is known."""
        built, intent = proposal("CONNECT api.stripe.com:443 HTTP/1.1")
        assert intent.opaque is True
        assert intent.change_type == "unknown"
        assert built.context.blast_radius_hints.writes is False
        assert built.context.blast_radius_hints.deletes is False

    def test_the_tunnel_summary_says_what_the_gate_cannot_see(self) -> None:
        built, _ = proposal("CONNECT api.stripe.com:443 HTTP/1.1")
        assert "cannot see the method, path or body" in built.context.summary

    def test_a_connect_classification_needs_no_path(self) -> None:
        assert classify_method("CONNECT", connect=True).opaque is True


class TestTheRestOfTheProposal:
    def test_the_intent_header_becomes_the_declared_intent(self) -> None:
        built, _ = proposal(
            "POST http://api.test/v1/charges HTTP/1.1", f"{INTENT_HEADER}: refund order 123"
        )
        assert built.context.intent == "refund order 123"

    def test_without_the_header_there_is_no_intent(self) -> None:
        built, _ = proposal("POST http://api.test/v1/charges HTTP/1.1")
        assert built.context.intent is None

    def test_the_content_type_and_length_are_recorded_but_not_the_body(self) -> None:
        """`host_path` mode does not read the body (SPEC §12.3), so the record
        says how big it was and what it claimed to be, and nothing more."""
        built, _ = proposal(
            "POST http://api.test/v1/charges HTTP/1.1",
            "Content-Type: application/json",
            "Content-Length: 61",
        )
        assert built.action.params_redacted is not None
        assert built.action.params_redacted["content_type"] == "application/json"
        assert built.action.params_redacted["content_length"] == 61
        assert "body" not in built.action.params_redacted

    def test_the_enforcement_override_is_what_lands_in_the_record(self) -> None:
        built, _ = proposal("CONNECT api.test:443 HTTP/1.1", enforcement=Enforcement.advisory)
        assert built.context.enforcement is Enforcement.advisory

    def test_an_identityless_proxy_is_refused_at_construction(self) -> None:
        """Without a principal every verdict is a synthetic AG-IDN-007 BLOCK
        reached before any rule runs, and in shadow mode nothing would look
        wrong."""
        with pytest.raises(ValueError, match="AG-IDN-007"):
            HttpProxyOptions()


class TestThePolicyActuallySeesIt:
    """The shipped egress rule has to fire on what this adapter produces.

    A target in the wrong shape would leave AG-DAT-003 matching nothing, and
    the symptom -- an egress rule that never fires -- is invisible.
    """

    def decide(self, request_line: str):  # type: ignore[no-untyped-def]
        built, _ = proposal(request_line)
        bundle = load_bundle([baseline_pack_dir()]).bundle
        return evaluate(
            built,
            bundle,
            BudgetState(token_jti=built.principal.token_jti),
            EvalContext(now=utcnow()),
        )

    def test_the_egress_rule_fires_on_an_unlisted_host(self) -> None:
        verdict = self.decide("CONNECT pastebin.example.test:443 HTTP/1.1")
        assert "AG-DAT-003" in {hit.rule_id for hit in verdict.hits}

    def test_the_egress_rule_stays_quiet_for_a_listed_host(self) -> None:
        verdict = self.decide("CONNECT api.github.com:443 HTTP/1.1")
        assert "AG-DAT-003" not in {hit.rule_id for hit in verdict.hits}

    def test_a_request_to_the_metadata_endpoint_is_blocked(self) -> None:
        """The proxy is the first adapter that can see this, and credential
        theft through the instance metadata service is how an agent with
        network access escalates to the whole account."""
        verdict = self.decide("GET http://169.254.169.254/latest/meta-data/iam/ HTTP/1.1")
        hits = {hit.rule_id for hit in verdict.hits}
        assert "AG-DAT-013" in hits
        assert verdict.decision is Decision.BLOCK

    def test_the_metadata_rule_also_catches_the_tunnelled_form(self) -> None:
        verdict = self.decide("CONNECT metadata.google.internal:443 HTTP/1.1")
        assert "AG-DAT-013" in {hit.rule_id for hit in verdict.hits}

    def test_an_ordinary_host_is_not_caught_by_the_metadata_rule(self) -> None:
        verdict = self.decide("GET https://api.github.com/user HTTP/1.1")
        assert "AG-DAT-013" not in {hit.rule_id for hit in verdict.hits}
