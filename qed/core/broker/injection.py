"""Attaching a credential to an outgoing call (SPEC §7.2). Pure.

Takes an upstream and an already-resolved :class:`Secret` and says what to put
where. It does not resolve, does not send, and does not log.

Stripping comes first
---------------------

Before anything is attached, whatever the agent supplied is removed. This
matters more than the attaching: an enforcing adapter that added the broker's
header while leaving the agent's in place would be an adapter where the agent
still decides which credential is used. A header QED did not put there
has no business reaching the upstream.

A note on stdio
---------------

A stdio child process receives its environment once, at spawn. "Resolved per
request" (SPEC §7.2) is therefore true for HTTP upstreams and not for stdio
ones, where the credential is fixed for the life of the process and the TTL
cache governs re-spawns instead. Saying so is better than implying a
freshness the transport cannot give.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from qed.core.broker.model import Secret, Upstream

__all__ = [
    "STRIPPED_HEADERS",
    "Injection",
    "plan_injection",
    "strip_agent_credentials",
]

#: Removed from anything an enforcing adapter forwards. Lower-case, because
#: HTTP header names are case-insensitive and an agent that capitalised
#: `AUTHORIZATION` would otherwise sail straight through.
STRIPPED_HEADERS = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "cookie",
        "x-api-key",
        "api-key",
        "x-auth-token",
        "x-access-token",
        "x-amz-security-token",
        "x-goog-api-key",
    }
)


@dataclass(frozen=True)
class Injection:
    """What to apply to the outgoing call.

    Secrets live in :class:`Secret` right up to the moment of use, so this
    object can be built, passed around and — if something goes wrong —
    printed, without leaking.
    """

    upstream_id: str
    env: dict[str, Secret] = field(default_factory=dict)
    headers: dict[str, Secret] = field(default_factory=dict)
    query: dict[str, Secret] = field(default_factory=dict)
    #: True when the upstream wants request signing (`sigv4`), which cannot be
    #: expressed as a header here: it depends on the request body and has to
    #: happen at send time. The adapter checks this and refuses rather than
    #: forwarding unsigned, because forwarding unsigned would be the agent's
    #: own credentials getting used after all.
    needs_signing: bool = False

    def env_values(self) -> dict[str, str]:
        """Revealed, for handing to a child process. Call at spawn only."""
        return {name: secret.reveal() for name, secret in self.env.items()}

    def header_values(self) -> dict[str, str]:
        """Revealed, for one outgoing request. Call at send only."""
        return {name: secret.reveal() for name, secret in self.headers.items()}

    def query_values(self) -> dict[str, str]:
        """Revealed, for one outgoing URL. Call at send only.

        A credential in a query string is worse than one in a header -- it
        lands in access logs on both ends -- but some APIs take nothing else,
        and QED holding it is still better than the agent holding it.
        """
        return {name: secret.reveal() for name, secret in self.query.items()}


def strip_agent_credentials(headers: dict[str, str]) -> tuple[dict[str, str], list[str]]:
    """Remove anything the agent supplied that looks like a credential.

    Returns the cleaned headers and the names removed, so the adapter can say
    what it dropped. An agent repeatedly trying to attach its own
    `Authorization` is worth noticing: it usually means somebody wired a token
    into the agent and is wondering why it is ignored, but it can also mean
    the agent is trying to reach past QED.
    """
    kept: dict[str, str] = {}
    removed: list[str] = []
    for name, value in headers.items():
        if name.lower() in STRIPPED_HEADERS:
            removed.append(name)
        else:
            kept[name] = value
    return kept, removed


def plan_injection(upstream: Upstream, secret: Secret) -> Injection:
    """What this upstream's credential spec means in practice."""
    spec = upstream.credential
    if spec is None:  # pragma: no cover - callers check `effective_enforcement`
        raise ValueError(f"upstream {upstream.id} has no credential to inject")

    inject = spec.inject
    rendered = Secret(inject.format.format(value=secret.reveal()))

    if inject.type == "env":
        if not inject.name:
            raise ValueError(f"{upstream.id}: an `env` injection needs a `name`")
        return Injection(upstream_id=upstream.id, env={inject.name: rendered})
    if inject.type == "header":
        if not inject.name:
            raise ValueError(f"{upstream.id}: a `header` injection needs a `name`")
        return Injection(upstream_id=upstream.id, headers={inject.name: rendered})
    if inject.type == "query":
        if not inject.name:
            raise ValueError(f"{upstream.id}: a `query` injection needs a `name`")
        return Injection(upstream_id=upstream.id, query={inject.name: rendered})
    return Injection(upstream_id=upstream.id, needs_signing=True)
