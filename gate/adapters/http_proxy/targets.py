"""What an HTTP request is about to do, from the request line alone. Pure.

Two jobs, both of which the kernel needs before it can score anything: name
the resource (``action.target``) and guess the damage (``BlastHints``).

Why the target is a URL
-----------------------

SPEC §3.1 calls ``action.target`` a "URI-ish resource id", and SPEC §12.3 says
to produce it with ``map_host_to_target(host)`` using ``upstreams.match``.
Writing ``aws:ec2:…`` here would need a mapping table nobody has filled in,
and it would also break two things that already work: ``match_upstream``
finds a host glob by splitting the target on ``://``, and the shipped
``AG-DAT-003`` egress rule matches ``action.target`` against ``*://*``. So the
target is the destination as a URL -- ``https://api.github.com/repos/acme`` --
and the upstream match, the egress rule and a human reading the chain all get
the same string.

The query is deliberately **not** in the target. A query string carries
tokens, order varies between calls that mean the same thing, and both would
make a policy glob either leaky or useless. It goes into the parameters
instead, where ``AG-DAT-001`` can see it and the masking pass can clean it on
the way into the chain.

Why CONNECT gets no write hints
-------------------------------

A ``CONNECT`` tunnel has no method and no path. Guessing ``writes=True``
would route every TLS connection to an approver; guessing ``writes=False``
would tell the blast-radius scorer the connection is harmless. Neither is
known, so neither is claimed: the hints stay at their defaults and the
summary says in words that the gate is deciding on reachability alone.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from gate.core.schemas import Scope

__all__ = [
    "READ_METHODS",
    "HttpIntent",
    "action_name",
    "classify_method",
    "derive_target",
    "summary_for",
]

#: Methods RFC 9110 defines as safe. ``OPTIONS`` and ``TRACE`` are in here as
#: well: they change nothing, though ``TRACE`` is worth a rule of its own one
#: day for what it reflects back.
READ_METHODS: Final = frozenset({"GET", "HEAD", "OPTIONS", "TRACE"})

#: A method that replaces or removes a whole collection is a different size of
#: mistake from one that touches a document, and the path is the only clue
#: available. A path with no identifier-looking last segment -- ``/v1/orders``
#: rather than ``/v1/orders/8812`` -- is treated as the collection.
_COLLECTION_METHODS: Final = frozenset({"DELETE", "PUT"})


@dataclass(frozen=True)
class HttpIntent:
    """The SPEC §3.1 hints for one request, plus why."""

    writes: bool
    deletes: bool
    scope: Scope
    change_type: str
    reasons: tuple[str, ...]
    #: True when the gate is deciding on the host alone because the rest is
    #: inside TLS. Recorded in the summary and counted by the proxy; no rule
    #: reads it.
    opaque: bool = False


def classify_method(method: str, path: str = "", *, connect: bool = False) -> HttpIntent:
    """Derive the hints for one request."""
    if connect:
        return HttpIntent(
            writes=False,
            deletes=False,
            scope="single_resource",
            change_type="unknown",
            reasons=(
                "CONNECT tunnel: the method, path and body are inside TLS, so nothing "
                "about what the request does is knowable here",
            ),
            opaque=True,
        )

    upper = method.upper()
    if upper in READ_METHODS:
        return HttpIntent(
            writes=False,
            deletes=False,
            scope="single_resource",
            change_type="read",
            reasons=(f"{upper} is a safe method",),
        )

    deletes = upper == "DELETE"
    change = {"POST": "create", "PUT": "update", "PATCH": "update", "DELETE": "delete"}.get(
        upper, "unknown"
    )
    scope: Scope = "single_resource"
    reasons = [f"{upper} changes state on the server"]
    if upper in _COLLECTION_METHODS and _is_collection(path):
        scope = "multi_resource"
        reasons.append(f"{path} names a collection rather than one resource")
    return HttpIntent(
        writes=True,
        deletes=deletes,
        scope=scope,
        change_type=change,
        reasons=tuple(reasons),
    )


def _is_collection(path: str) -> bool:
    """Whether the path's last segment looks like a collection, not an item.

    Best effort and known to be so: a segment that is all digits, a ULID, a
    UUID or anything with a dot in it reads as one resource, and everything
    else reads as the collection. Wrong either way it only moves a hint, and
    the hint feeds a score a rule can override.
    """
    segments = [segment for segment in path.split("?", 1)[0].split("/") if segment]
    if not segments:
        return True
    last = segments[-1]
    if last.isdigit() or "." in last:
        return False
    # A long run of hex, digits and dashes is an id: a ULID, a UUID, a commit
    # sha. A short word is the collection.
    return not (
        len(last) >= 16 and all(character.isalnum() or character == "-" for character in last)
    )


def derive_target(scheme: str, authority: str, path: str = "") -> str:
    """``scheme://authority/path``, with the query dropped.

    The trailing slash of a bare root is dropped as well, so that ``/`` and
    ``""`` do not produce two targets for one destination.
    """
    clean = path.split("?", 1)[0]
    if clean in {"", "/"}:
        return f"{scheme}://{authority}"
    return f"{scheme}://{authority}{clean}"


def action_name(method: str, path_or_authority: str) -> str:
    """``"POST /v1/charges"`` or ``"CONNECT api.stripe.com"`` (SPEC §12.3)."""
    return f"{method.upper()} {path_or_authority}"


def summary_for(method: str, target: str, intent: HttpIntent) -> str:
    """One line an approver can act on without reading the request."""
    if intent.opaque:
        return (
            f"{method.upper()} opens a TLS tunnel to {target}; the gate is deciding on "
            "reachability alone and cannot see the method, path or body inside it"
        )
    verb = {"read": "read", "create": "create on", "update": "change", "delete": "delete on"}.get(
        intent.change_type, "call"
    )
    extra = " (more than one resource)" if intent.scope == "multi_resource" else ""
    return f"{method.upper()} wants to {verb} {target}{extra}"
