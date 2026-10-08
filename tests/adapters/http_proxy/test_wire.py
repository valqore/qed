"""Reading HTTP/1.1 off the wire (SPEC §12.3).

Most of these are refusals, and that is the point. A proxy that is lenient
about framing can be made to disagree with the server behind it about where
one request ends and the next begins, and in this product the smuggled half
is the half that was never decided and never recorded. So the tests are
mostly a list of ways to be ambiguous, each one answered with a status rather
than a guess.
"""

from __future__ import annotations

import pytest

from gate.adapters.http_proxy.wire import (
    HOP_BY_HOP,
    MAX_HEADERS,
    MalformedRequest,
    build_forward_request,
    connect_established,
    content_length,
    get_header,
    has_chunked_body,
    parse_headers,
    parse_request_line,
    resolve_target,
    response,
    split_head,
)


def head(*lines: str) -> bytes:
    return ("\r\n".join(lines) + "\r\n\r\n").encode()


def parse(*lines: str):  # type: ignore[no-untyped-def]
    raw_line, raw_headers = split_head(head(*lines))
    line = parse_request_line(raw_line)
    headers = parse_headers(raw_headers)
    return line, headers, resolve_target(line, headers)


class TestTheRequestLine:
    def test_an_absolute_form_request_names_host_and_path(self) -> None:
        line, _, target = parse("GET http://api.example.com/v1/orders HTTP/1.1", "Host: x")
        assert line.method == "GET"
        assert target.host == "api.example.com"
        assert target.port == 80
        assert target.path == "/v1/orders"

    def test_connect_names_host_and_port(self) -> None:
        line, _, target = parse("CONNECT api.stripe.com:443 HTTP/1.1")
        assert line.is_connect
        assert (target.scheme, target.host, target.port) == ("https", "api.stripe.com", 443)

    def test_connect_without_a_port_is_refused_rather_than_defaulted(self) -> None:
        """Guessing 443 would put a port in the chain that nobody asked for."""
        with pytest.raises(MalformedRequest, match="does not default to 443"):
            parse("CONNECT api.stripe.com HTTP/1.1")

    def test_origin_form_is_honoured_through_the_host_header(self) -> None:
        """A client should not send this to a proxy. Some do, and the Host
        header carries everything needed to honour it."""
        _, _, target = parse("GET /health HTTP/1.1", "Host: internal.example.com:8080")
        assert (target.host, target.port, target.path) == ("internal.example.com", 8080, "/health")

    def test_origin_form_without_a_host_header_is_refused(self) -> None:
        with pytest.raises(MalformedRequest, match="needs a Host header"):
            parse("GET /health HTTP/1.1")

    def test_a_relative_target_that_is_not_a_path_is_refused(self) -> None:
        with pytest.raises(MalformedRequest, match="neither an absolute URL nor a path"):
            parse("GET api.example.com/v1 HTTP/1.1")

    @pytest.mark.parametrize(
        "raw",
        [
            b"GET",
            b"GET /",
            b"GET / HTTP/1.1 extra",
            b"GET  / HTTP/1.1",
        ],
    )
    def test_a_request_line_has_exactly_three_parts(self, raw: bytes) -> None:
        with pytest.raises(MalformedRequest):
            parse_request_line(raw)

    def test_http_2_over_this_socket_is_refused_with_505(self) -> None:
        with pytest.raises(MalformedRequest) as caught:
            parse_request_line(b"GET / HTTP/2.0")
        assert caught.value.status == 505

    def test_a_scheme_this_proxy_does_not_forward_is_refused_with_501(self) -> None:
        with pytest.raises(MalformedRequest) as caught:
            parse("GET ftp://files.example.com/x HTTP/1.1")
        assert caught.value.status == 501

    def test_userinfo_in_a_proxied_url_is_refused(self) -> None:
        """A credential in a place nothing masks, in a URL that would be
        forwarded verbatim."""
        with pytest.raises(MalformedRequest, match="userinfo"):
            parse("GET http://user:pw@api.example.com/v1 HTTP/1.1")

    def test_a_non_ascii_request_line_is_refused(self) -> None:
        with pytest.raises(MalformedRequest, match="not ASCII"):
            parse_request_line("GET http://exämple.com/ HTTP/1.1".encode())


class TestHosts:
    def test_an_ipv6_literal_keeps_its_brackets_off_and_its_port_on(self) -> None:
        _, _, target = parse("CONNECT [2001:db8::1]:8443 HTTP/1.1")
        assert (target.host, target.port) == ("2001:db8::1", 8443)

    def test_an_unclosed_ipv6_literal_is_refused(self) -> None:
        with pytest.raises(MalformedRequest, match="never closes"):
            parse("CONNECT [2001:db8::1:443 HTTP/1.1")

    @pytest.mark.parametrize("authority", ["api example.com:80", "api\x00.com:80", ":80"])
    def test_a_host_that_is_not_a_host_is_refused(self, authority: str) -> None:
        with pytest.raises(MalformedRequest):
            parse(f"CONNECT {authority} HTTP/1.1")

    @pytest.mark.parametrize("port", ["0", "70000", "http", "-1"])
    def test_a_port_that_is_not_a_port_is_refused(self, port: str) -> None:
        with pytest.raises(MalformedRequest):
            parse(f"CONNECT api.example.com:{port} HTTP/1.1")

    def test_the_default_port_stays_implicit_in_the_authority(self) -> None:
        """`https://api.github.com` and `https://api.github.com:443` are the
        same destination, and two targets for one destination means a policy
        glob matches one and misses the other."""
        _, _, explicit = parse("CONNECT api.github.com:443 HTTP/1.1")
        assert explicit.authority == "api.github.com"
        _, _, other = parse("CONNECT api.github.com:8443 HTTP/1.1")
        assert other.authority == "api.github.com:8443"


class TestHeaders:
    def test_order_and_spelling_are_kept(self) -> None:
        _, headers, _ = parse(
            "GET http://x.test/ HTTP/1.1", "X-First: 1", "x-second: 2", "X-First: 3"
        )
        assert headers == [("X-First", "1"), ("x-second", "2"), ("X-First", "3")]

    def test_lookup_folds_case_and_takes_the_last(self) -> None:
        _, headers, _ = parse("GET http://x.test/ HTTP/1.1", "X-A: 1", "x-a: 2")
        assert get_header(headers, "X-A") == "2"
        assert get_header(headers, "x-missing") is None

    def test_an_obs_fold_continuation_is_refused(self) -> None:
        """Deprecated by RFC 9112 §5.2 and the classic way to make two parsers
        see two different header sets."""
        with pytest.raises(MalformedRequest, match="may not begin with whitespace"):
            parse("GET http://x.test/ HTTP/1.1", "X-A: one", " continued")

    def test_a_header_line_without_a_colon_is_refused(self) -> None:
        with pytest.raises(MalformedRequest, match="no colon"):
            parse("GET http://x.test/ HTTP/1.1", "Broken")

    def test_a_header_name_that_is_not_a_token_is_refused(self) -> None:
        with pytest.raises(MalformedRequest, match="is not a header name"):
            parse("GET http://x.test/ HTTP/1.1", "X Bad: 1")

    def test_too_many_headers_is_a_431(self) -> None:
        lines = ["GET http://x.test/ HTTP/1.1"] + [f"X-{i}: v" for i in range(MAX_HEADERS + 2)]
        with pytest.raises(MalformedRequest) as caught:
            parse(*lines)
        assert caught.value.status == 431

    def test_an_oversized_head_is_a_431(self) -> None:
        with pytest.raises(MalformedRequest) as caught:
            split_head(b"GET / HTTP/1.1\r\nX: " + b"a" * (70 * 1024) + b"\r\n\r\n")
        assert caught.value.status == 431


class TestBodyFraming:
    def test_a_content_length_is_read(self) -> None:
        _, headers, _ = parse("POST http://x.test/ HTTP/1.1", "Content-Length: 42")
        assert content_length(headers) == 42

    def test_no_content_length_is_none_rather_than_zero(self) -> None:
        _, headers, _ = parse("GET http://x.test/ HTTP/1.1")
        assert content_length(headers) is None

    def test_two_content_lengths_that_agree_are_fine(self) -> None:
        _, headers, _ = parse(
            "POST http://x.test/ HTTP/1.1", "Content-Length: 5", "Content-Length: 5"
        )
        assert content_length(headers) == 5

    def test_two_content_lengths_that_disagree_are_refused(self) -> None:
        """Picking one is exactly how a proxy and its upstream come to
        different conclusions about where the request ends."""
        _, headers, _ = parse(
            "POST http://x.test/ HTTP/1.1", "Content-Length: 5", "Content-Length: 6"
        )
        with pytest.raises(MalformedRequest, match="different values"):
            content_length(headers)

    def test_a_content_length_that_is_not_a_number_is_refused(self) -> None:
        _, headers, _ = parse("POST http://x.test/ HTTP/1.1", "Content-Length: 5, 5")
        with pytest.raises(MalformedRequest, match="is not a number"):
            content_length(headers)

    def test_both_content_length_and_transfer_encoding_is_refused(self) -> None:
        """RFC 9112 §6.1: two different statements about where the request ends."""
        _, headers, _ = parse(
            "POST http://x.test/ HTTP/1.1", "Content-Length: 5", "Transfer-Encoding: chunked"
        )
        with pytest.raises(MalformedRequest, match="RFC 9112"):
            has_chunked_body(headers)

    def test_chunked_is_recognised(self) -> None:
        _, headers, _ = parse("POST http://x.test/ HTTP/1.1", "Transfer-Encoding: chunked")
        assert has_chunked_body(headers) is True

    def test_an_unsupported_transfer_encoding_is_a_501(self) -> None:
        _, headers, _ = parse("POST http://x.test/ HTTP/1.1", "Transfer-Encoding: gzip, chunked")
        with pytest.raises(MalformedRequest) as caught:
            has_chunked_body(headers)
        assert caught.value.status == 501

    def test_transfer_encoding_identity_is_not_chunked(self) -> None:
        _, headers, _ = parse("POST http://x.test/ HTTP/1.1", "Transfer-Encoding: identity")
        assert has_chunked_body(headers) is False


class TestBuildingTheForwardedRequest:
    def build(self, *lines: str, **kwargs: object) -> str:
        line, headers, target = parse(*lines)
        return build_forward_request(
            method=line.method,
            target=target,
            headers=headers,
            body_length=content_length(headers),
            **kwargs,  # type: ignore[arg-type]
        ).decode()

    def test_it_is_sent_in_origin_form(self) -> None:
        out = self.build("GET http://api.test/v1/orders?page=2 HTTP/1.1")
        assert out.startswith("GET /v1/orders?page=2 HTTP/1.1\r\n")

    def test_the_host_header_comes_from_the_resolved_target(self) -> None:
        """Not from whatever the client sent: the forwarded request has to say
        one thing only about where it is going."""
        out = self.build("GET http://api.test/v1 HTTP/1.1", "Host: lies.example.com")
        assert "Host: api.test\r\n" in out
        assert "lies.example.com" not in out

    @pytest.mark.parametrize("header", sorted(HOP_BY_HOP))
    def test_every_hop_by_hop_header_is_dropped(self, header: str) -> None:
        out = self.build("GET http://api.test/ HTTP/1.1", f"{header}: whatever")
        # Line by line, not as a substring: "te" appears inside "api.test".
        assert f"{header}: whatever" not in out.split("\r\n")

    def test_connection_close_and_via_are_always_set(self) -> None:
        out = self.build("GET http://api.test/ HTTP/1.1")
        assert "Connection: close\r\n" in out
        assert "Via: 1.1 gate\r\n" in out

    def test_an_ordinary_header_survives_with_its_spelling(self) -> None:
        out = self.build("GET http://api.test/ HTTP/1.1", "user-AGENT: claude-code")
        assert "user-AGENT: claude-code\r\n" in out

    def test_a_dropped_name_is_removed_case_insensitively(self) -> None:
        out = self.build(
            "GET http://api.test/ HTTP/1.1",
            "AUTHORIZATION: Bearer agent-token",
            drop=frozenset({"authorization"}),
        )
        assert "agent-token" not in out

    def test_an_added_header_is_appended(self) -> None:
        out = self.build(
            "GET http://api.test/ HTTP/1.1",
            drop=frozenset({"authorization"}),
            add={"Authorization": "Bearer from-the-broker"},
        )
        assert "Authorization: Bearer from-the-broker\r\n" in out

    def test_the_content_length_is_rewritten_once(self) -> None:
        out = self.build("POST http://api.test/ HTTP/1.1", "Content-Length: 11")
        assert out.count("Content-Length") == 1
        assert "Content-Length: 11\r\n" in out

    def test_a_request_with_no_body_declares_no_length(self) -> None:
        out = self.build("GET http://api.test/ HTTP/1.1")
        assert "Content-Length" not in out


class TestResponses:
    def test_a_refusal_carries_the_explanation_in_the_body(self) -> None:
        """The reader is an agent or its HTTP library, and the body of a 403 is
        the one place the explanation reliably survives."""
        out = response(403, "[gate BLOCK] AG-BLR-001: no.\n").decode()
        assert out.startswith("HTTP/1.1 403 Forbidden\r\n")
        assert out.endswith("[gate BLOCK] AG-BLR-001: no.\n")
        assert "Content-Length: 29\r\n" in out

    def test_an_empty_response_declares_a_zero_length_and_no_type(self) -> None:
        out = response(503).decode()
        assert "Content-Length: 0\r\n" in out
        assert "Content-Type" not in out

    def test_the_tunnel_response_carries_no_length_at_all(self) -> None:
        """RFC 9110 §9.3.6 forbids it, and a Content-Length: 0 makes some
        clients wait for a body that never comes."""
        out = connect_established().decode()
        assert out == "HTTP/1.1 200 Connection Established\r\nVia: 1.1 gate\r\n\r\n"
        assert "Content-Length" not in out


class TestSplittingTheHead:
    def test_a_head_with_no_headers_splits_cleanly(self) -> None:
        line, headers = split_head(b"CONNECT a.test:443 HTTP/1.1\r\n\r\n")
        assert line == b"CONNECT a.test:443 HTTP/1.1"
        assert parse_headers(headers) == []

    def test_an_empty_head_is_refused(self) -> None:
        with pytest.raises(MalformedRequest, match="empty"):
            split_head(b"\r\n\r\n")
