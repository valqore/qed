"""HTTP/1.1 on the wire, as bytes (SPEC §12.3). Pure.

No sockets. Every function here takes bytes and returns a value, so the
parsing can be tested against the malformed requests that matter without a
listening port.

Why hand-write this
-------------------

A forward proxy has to read request framing that a normal HTTP *client*
library never produces: absolute-form request lines, ``CONNECT``, and
deliberately malformed framing from something trying to get past QED.
``http.client`` and ``httpx`` parse responses, not proxied requests, and
``h11`` would be a dependency carried for one direction of one adapter.

Strictness is the point
-----------------------

A proxy that is lenient about framing is a proxy that can be made to disagree
with the server behind it about where one request ends and the next begins.
That disagreement is request smuggling, and in this product it has a sharper
edge than usual: the smuggled half of the request is the half QED never
decided, so it would execute with no verdict and leave no record. Anything
ambiguous is refused with a 400 instead.

Specifically refused:

* both ``Content-Length`` and ``Transfer-Encoding`` (RFC 9112 §6.1);
* two ``Content-Length`` headers that disagree;
* obs-fold continuation lines (a leading space on a header line);
* a header name that is not a token, or a value carrying CR, LF or NUL;
* anything past the size limits in SPEC §17's spirit.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final

__all__ = [
    "HOP_BY_HOP",
    "MAX_HEADERS",
    "MAX_HEADER_BLOCK",
    "MAX_REQUEST_LINE",
    "Headers",
    "MalformedRequest",
    "RequestLine",
    "ResolvedTarget",
    "build_forward_request",
    "connect_established",
    "content_length",
    "get_header",
    "has_chunked_body",
    "parse_headers",
    "parse_request_line",
    "resolve_target",
    "response",
    "split_head",
]

#: Generous enough for a real URL with a long query, small enough that a
#: client dribbling bytes cannot make the proxy hold a megabyte per socket.
MAX_REQUEST_LINE: Final = 8 * 1024
MAX_HEADER_BLOCK: Final = 64 * 1024
MAX_HEADERS: Final = 100

#: Headers that belong to one hop and must not be forwarded (RFC 9110 §7.6.1).
#: ``proxy-authorization`` is in here for the obvious reason and would also be
#: stripped as a credential; listing it twice is cheaper than depending on the
#: other list staying as it is.
HOP_BY_HOP: Final = frozenset(
    {
        "connection",
        "proxy-connection",
        "keep-alive",
        "transfer-encoding",
        "te",
        "trailer",
        "trailers",
        "upgrade",
        "proxy-authenticate",
        "proxy-authorization",
    }
)

#: A header name is a token (RFC 9110 §5.6.2). Anything else is a request
#: trying to be read two different ways by two different parsers.
_TOKEN = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")

#: What a host may contain. Deliberately narrow: a host with a space, a slash
#: or a control character in it is not a host, it is an attempt to make the
#: connect call and the policy decision disagree about where the bytes go.
_HOST = re.compile(r"^[A-Za-z0-9._\-]+$")

#: ``Headers`` keeps the order and the original spelling, because a proxy
#: forwards what it was given. Lookups go through :func:`get_header`, which
#: folds case the way HTTP does.
Headers = list[tuple[str, str]]


class MalformedRequest(ValueError):
    """The request cannot be read one way only.

    Carries the status to answer with, so the caller does not have to map
    error text back onto a code.
    """

    def __init__(self, message: str, *, status: int = 400) -> None:
        super().__init__(message)
        self.status = status


@dataclass(frozen=True)
class RequestLine:
    method: str
    #: Exactly as sent: ``host:443`` for CONNECT, an absolute URL for the
    #: ordinary proxy form, or a path for the origin form.
    target: str
    version: str

    @property
    def is_connect(self) -> bool:
        return self.method == "CONNECT"


@dataclass(frozen=True)
class ResolvedTarget:
    """Where the request is actually going."""

    scheme: str
    host: str
    port: int
    #: Path and query as sent, ``""`` for CONNECT. Kept together because this
    #: is what gets forwarded in the origin-form request line.
    path: str

    @property
    def authority(self) -> str:
        """``host`` or ``host:port``, the default port left implicit.

        The default is left out so that ``https://api.github.com`` and
        ``https://api.github.com:443`` do not produce two different
        ``action.target`` values for the same destination -- a policy glob
        would then match one and miss the other.
        """
        default = 443 if self.scheme == "https" else 80
        return self.host if self.port == default else f"{self.host}:{self.port}"

    @property
    def path_only(self) -> str:
        return self.path.split("?", 1)[0]

    @property
    def query(self) -> str:
        _, _, rest = self.path.partition("?")
        return rest


def split_head(head: bytes) -> tuple[bytes, bytes]:
    """Split a request head into its first line and its header block.

    ``head`` is everything up to and including the blank line. A head with no
    CRLF at all never came from an HTTP/1.1 client.
    """
    if len(head) > MAX_HEADER_BLOCK:
        raise MalformedRequest(
            f"the request head is larger than {MAX_HEADER_BLOCK} bytes",
            status=431,
        )
    stripped = head.removesuffix(b"\r\n\r\n")
    line, separator, rest = stripped.partition(b"\r\n")
    if not separator and not line:
        raise MalformedRequest("the request head is empty")
    if len(line) > MAX_REQUEST_LINE:
        raise MalformedRequest(
            f"the request line is longer than {MAX_REQUEST_LINE} bytes", status=414
        )
    return line, rest


def parse_request_line(raw: bytes) -> RequestLine:
    """``METHOD target HTTP/1.1``, or a 400."""
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError:
        raise MalformedRequest("the request line is not ASCII") from None
    parts = text.split(" ")
    if len(parts) != 3:
        raise MalformedRequest("a request line has exactly three space-separated parts")
    method, target, version = parts
    if not _TOKEN.match(method):
        raise MalformedRequest(f"{method!r} is not a method")
    if version not in {"HTTP/1.0", "HTTP/1.1"}:
        # HTTP/2 and /3 do not have a request line at all, so a client sending
        # one of those over this socket has already gone wrong somewhere.
        raise MalformedRequest(f"{version!r} is not a version this proxy speaks", status=505)
    if not target:
        raise MalformedRequest("the request line has no target")
    return RequestLine(method=method, target=target, version=version)


def parse_headers(raw: bytes) -> Headers:
    """The header block, in order, with original spelling kept."""
    if not raw:
        return []
    headers: Headers = []
    for chunk in raw.split(b"\r\n"):
        if not chunk:
            continue
        if chunk[:1] in (b" ", b"\t"):
            # obs-fold. Deprecated by RFC 9112 §5.2, and the classic way to
            # make two parsers see two different header sets.
            raise MalformedRequest("a header line may not begin with whitespace")
        try:
            line = chunk.decode("latin-1")
        except UnicodeDecodeError:  # pragma: no cover - latin-1 maps every byte
            raise MalformedRequest("a header line is not decodable") from None
        name, separator, value = line.partition(":")
        if not separator:
            raise MalformedRequest(f"header line {line!r} has no colon")
        if not _TOKEN.match(name):
            raise MalformedRequest(f"{name!r} is not a header name")
        value = value.strip(" \t")
        if any(character in value for character in ("\r", "\n", "\x00")):
            raise MalformedRequest(f"the value of {name!r} carries a control character")
        headers.append((name, value))
        if len(headers) > MAX_HEADERS:
            raise MalformedRequest(f"more than {MAX_HEADERS} headers", status=431)
    return headers


def get_header(headers: Headers, name: str) -> str | None:
    """The last value for ``name``, case-folded lookup, or None.

    Last rather than first because that is what a server does with a repeated
    header it tolerates; where it matters that there is only one,
    :func:`content_length` checks for itself.
    """
    wanted = name.lower()
    found: str | None = None
    for key, value in headers:
        if key.lower() == wanted:
            found = value
    return found


def resolve_target(line: RequestLine, headers: Headers) -> ResolvedTarget:
    """Where this request goes, from the three request forms a proxy sees."""
    if line.is_connect:
        host, port = _split_authority(line.target, default_port=None)
        return ResolvedTarget(scheme="https", host=host, port=port, path="")

    if line.target.startswith("/"):
        # Origin form. A client should not send this to a proxy, but some do,
        # and the Host header carries everything needed to honour it.
        host_header = get_header(headers, "host")
        if not host_header:
            raise MalformedRequest("an origin-form request to a proxy needs a Host header")
        host, port = _split_authority(host_header, default_port=80)
        return ResolvedTarget(scheme="http", host=host, port=port, path=line.target)

    scheme, separator, rest = line.target.partition("://")
    if not separator:
        raise MalformedRequest(
            f"{line.target!r} is neither an absolute URL nor a path; a forward proxy "
            "needs to know the host to decide and to connect"
        )
    scheme = scheme.lower()
    if scheme not in {"http", "https"}:
        raise MalformedRequest(f"this proxy forwards http and https, not {scheme!r}", status=501)
    authority, slash, tail = rest.partition("/")
    if "@" in authority:
        # userinfo in a proxied URL is both deprecated (RFC 9110 §4.2.4) and a
        # credential in a place nothing masks. Refused rather than forwarded.
        raise MalformedRequest("a userinfo component in a proxied URL is not forwarded")
    host, port = _split_authority(authority, default_port=443 if scheme == "https" else 80)
    return ResolvedTarget(scheme=scheme, host=host, port=port, path=f"/{tail}" if slash else "/")


def _split_authority(authority: str, *, default_port: int | None) -> tuple[str, int]:
    """``host:port`` into its parts, with IPv6 brackets handled.

    ``default_port=None`` means the port is required, which is the CONNECT
    case: ``CONNECT example.com`` does not say where to connect, and guessing
    443 would mean the chain recorded a port nobody asked for.
    """
    host = authority
    port_text = ""
    if authority.startswith("["):
        closing = authority.find("]")
        if closing < 0:
            raise MalformedRequest(f"{authority!r} opens an IPv6 literal and never closes it")
        host = authority[1:closing]
        remainder = authority[closing + 1 :]
        if remainder.startswith(":"):
            port_text = remainder[1:]
        elif remainder:
            raise MalformedRequest(f"{authority!r} has trailing junk after the IPv6 literal")
        if not host:
            raise MalformedRequest("an IPv6 literal with nothing in it is not a host")
        return host, _port(port_text, default_port)

    if ":" in authority:
        host, _, port_text = authority.rpartition(":")
    if not host:
        raise MalformedRequest(f"{authority!r} has no host")
    if not _HOST.match(host):
        raise MalformedRequest(f"{host!r} is not a host name or address")
    return host, _port(port_text, default_port)


def _port(text: str, default: int | None) -> int:
    if not text:
        if default is None:
            raise MalformedRequest("CONNECT needs host:port; it does not default to 443")
        return default
    if not text.isdigit():
        raise MalformedRequest(f"{text!r} is not a port")
    port = int(text)
    if not 1 <= port <= 65535:
        raise MalformedRequest(f"{port} is not a port")
    return port


def content_length(headers: Headers) -> int | None:
    """The declared body length, or None when none is declared.

    Two ``Content-Length`` headers that disagree are refused rather than
    resolved: picking one is exactly how a proxy and its upstream come to
    different conclusions about where the request ends.
    """
    values = [value for name, value in headers if name.lower() == "content-length"]
    if not values:
        return None
    distinct = {value.strip() for value in values}
    if len(distinct) > 1:
        raise MalformedRequest(f"Content-Length appears {len(values)} times with different values")
    text = distinct.pop()
    if not text.isdigit():
        raise MalformedRequest(f"Content-Length {text!r} is not a number")
    return int(text)


def has_chunked_body(headers: Headers) -> bool:
    """Whether the client is using chunked transfer for the request body."""
    encodings = [value for name, value in headers if name.lower() == "transfer-encoding"]
    if not encodings:
        return False
    if content_length(headers) is not None:
        raise MalformedRequest(
            "the request carries both Content-Length and Transfer-Encoding, which is "
            "two different statements about where it ends (RFC 9112 §6.1)"
        )
    tokens = {token.strip().lower() for value in encodings for token in value.split(",")}
    tokens.discard("")
    tokens.discard("identity")
    if tokens - {"chunked"}:
        raise MalformedRequest(f"unsupported Transfer-Encoding {sorted(tokens)}", status=501)
    return "chunked" in tokens


def build_forward_request(
    *,
    method: str,
    target: ResolvedTarget,
    headers: Headers,
    drop: frozenset[str] = frozenset(),
    add: dict[str, str] | None = None,
    body_length: int | None,
) -> bytes:
    """The request to send upstream, in origin form.

    Hop-by-hop headers go, plus anything in ``drop`` -- which is where the
    broker's stripped credential names arrive. ``Connection: close`` is set
    because v1 handles one request per client connection, and ``Via`` is added
    because a proxy that hides itself is a proxy nobody can debug
    (RFC 9110 §7.6.3).
    """
    lines = [f"{method} {target.path or '/'} HTTP/1.1"]
    seen: set[str] = set()
    for name, value in headers:
        folded = name.lower()
        if folded in HOP_BY_HOP or folded in drop:
            continue
        if folded in {"host", "via", "content-length"}:
            # Rewritten below from the resolved target and the real body
            # length, so that the forwarded request says one thing only.
            continue
        lines.append(f"{name}: {value}")
        seen.add(folded)

    lines.append(f"Host: {target.authority}")
    if body_length is not None:
        lines.append(f"Content-Length: {body_length}")
    for name, value in (add or {}).items():
        if name.lower() in seen:  # pragma: no cover - callers drop before adding
            raise ValueError(f"{name} is already present; strip it before attaching one")
        lines.append(f"{name}: {value}")
    lines.append("Via: 1.1 qed")
    lines.append("Connection: close")
    return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")


_REASONS: Final = {
    200: "Connection Established",
    400: "Bad Request",
    403: "Forbidden",
    405: "Method Not Allowed",
    414: "URI Too Long",
    431: "Request Header Fields Too Large",
    501: "Not Implemented",
    502: "Bad Gateway",
    503: "Service Unavailable",
    504: "Gateway Timeout",
    505: "HTTP Version Not Supported",
}


def connect_established() -> bytes:
    """The response that opens a tunnel.

    No ``Content-Length`` and no ``Transfer-Encoding``: RFC 9110 §9.3.6
    forbids both on a 2xx answer to CONNECT, because everything after the
    blank line is the tunnel rather than a body. A ``Content-Length: 0`` here
    makes some clients wait for a body that never comes.
    """
    return b"HTTP/1.1 200 Connection Established\r\nVia: 1.1 qed\r\n\r\n"


def response(
    status: int, body: str = "", *, content_type: str = "text/plain; charset=utf-8"
) -> bytes:
    """A complete response for the agent, with the body as the explanation.

    Plain text on purpose. The reader is a coding agent or whatever library it
    uses, and a verdict in the body of a 403 is the one place the explanation
    reliably survives: an agent that only logs ``403`` still logs the rule ids
    with it.
    """
    payload = body.encode("utf-8")
    head = [
        f"HTTP/1.1 {status} {_REASONS.get(status, 'Error')}",
        f"Content-Length: {len(payload)}",
        "Connection: close",
        "Via: 1.1 qed",
    ]
    if payload:
        head.insert(1, f"Content-Type: {content_type}")
    return ("\r\n".join(head) + "\r\n\r\n").encode("latin-1") + payload
