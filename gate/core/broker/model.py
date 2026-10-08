"""Upstreams, matching and the secret wrapper (SPEC §7). Pure.

The one thing worth reading closely here is :class:`Secret`. "Never log a
credential" is a rule people break by accident — an exception handler that
formats its locals, a debug print left in, a model dumped to JSON for a
payload. So the value is wrapped in a type whose every rendering path is
redacted, and getting the real bytes out takes a deliberately awkward method
name. That turns a leak from something you can do absent-mindedly into
something you have to type out.
"""

from __future__ import annotations

from fnmatch import fnmatchcase
from typing import Any, Literal

from pydantic import Field

from gate.core.schemas import ActionProposal, Enforcement, Environment, Frozen

__all__ = [
    "CredentialSpec",
    "Enforcement",
    "InjectSpec",
    "Match",
    "Secret",
    "Upstream",
    "UpstreamSet",
    "match_upstream",
]

REDACTED = "<redacted>"


#: Re-exported, not redefined. `Enforcement` already exists on the proposal
#: schema, and a second enum with the same two members would type-check
#: everywhere and compare unequal exactly once, in the one place it mattered
#: -- which is how mypy found it.
#:
#: ``advisory`` is the honest answer when the gate does not hold the
#: credential: it still decides and still records, but the agent carries its
#: own token and could bypass the gate entirely. An adapter claiming to be
#: enforcing in that state would put a lie in the evidence.


class Secret:
    """A credential that cannot be printed by accident.

    ``str``, ``repr``, f-strings and ``%`` formatting all render
    ``<redacted>``. Pydantic never sees it because it is not a model field
    anywhere, and ``reveal()`` is the only way to the real value.
    """

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        self._value = value

    def reveal(self) -> str:
        """The actual credential. Call this at the point of injection only."""
        return self._value

    def __str__(self) -> str:
        return REDACTED

    def __repr__(self) -> str:
        return f"Secret({REDACTED})"

    def __format__(self, spec: str) -> str:
        return REDACTED

    def __bool__(self) -> bool:
        return bool(self._value)

    def __len__(self) -> int:
        """Length of the secret, which is safe to know and useful in a health
        check ("the env var is set but empty")."""
        return len(self._value)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Secret) and self._value == other._value

    def __hash__(self) -> int:  # pragma: no cover - not used as a key, but
        raise TypeError("a Secret is not hashable; do not use one as a dict key")


class Match(Frozen):
    """How a proposal is recognised as belonging to an upstream.

    Every present constraint must hold. An absent one means "any", the same
    reading as a rule's ``applies_to``, so nobody has to hold two different
    semantics in their head.
    """

    mcp_server: str | None = None
    host_globs: list[str] | None = None
    target_globs: list[str] | None = None
    environments: list[Environment] | None = None


class InjectSpec(Frozen):
    """How the credential is attached to the outgoing call."""

    type: Literal["env", "header", "sigv4", "query"]
    name: str | None = None
    #: ``"Bearer {value}"``. The placeholder is filled at injection time and
    #: the result is never stored.
    format: str = "{value}"


class CredentialSpec(Frozen):
    source: Literal["env", "file", "vault"]
    ref: str
    inject: InjectSpec


class Upstream(Frozen):
    id: str
    kind: Literal["mcp", "http"]
    match: Match = Match()
    credential: CredentialSpec | None = None
    enforcement: Enforcement = Enforcement.enforcing

    @property
    def effective_enforcement(self) -> Enforcement:
        """An upstream with no credential cannot be enforcing, whatever it says.

        Config that claims more than it can deliver is worse than config that
        admits the gap, because the claim ends up in the evidence.
        """
        return Enforcement.advisory if self.credential is None else self.enforcement


class UpstreamSet(Frozen):
    upstreams: list[Upstream] = Field(default_factory=list)

    def by_id(self, upstream_id: str) -> Upstream | None:
        return next((u for u in self.upstreams if u.id == upstream_id), None)


def _host_of(target: str) -> str:
    """The host part of an action target, for `host_globs`.

    Targets are not URLs in general (`db:prod/orders`, `repo:acme/payments`),
    so this is best effort and returns the whole string when there is nothing
    URL-shaped to take.
    """
    rest = target.split("://", 1)[-1]
    return rest.split("/", 1)[0].split("@")[-1]


def _matches(upstream: Upstream, proposal: ActionProposal) -> bool:
    rule = upstream.match
    if rule.environments is not None and proposal.context.environment not in rule.environments:
        return False
    if rule.mcp_server is not None:
        # MCP tool names are `server.tool`; the server is what identifies the
        # upstream, and a tool name without a dot cannot name one.
        server = proposal.action.name.split(".", 1)[0] if "." in proposal.action.name else ""
        if server != rule.mcp_server:
            return False
    if rule.target_globs is not None and not any(
        fnmatchcase(proposal.action.target, g) for g in rule.target_globs
    ):
        return False
    if rule.host_globs is not None:
        host = _host_of(proposal.action.target)
        if not any(fnmatchcase(host, g) for g in rule.host_globs):
            return False
    return True


def match_upstream(proposal: ActionProposal, upstreams: UpstreamSet) -> Upstream | None:
    """The upstream this action belongs to, or None.

    **First match wins, in file order.** Not "most specific": specificity
    between a host glob and an environment list is not a thing anyone can
    rank, and a resolution order nobody can predict is worse than one they
    can read top to bottom. An operator who wants a narrow rule puts it above
    the broad one, the way they already do with firewall rules.
    """
    for upstream in upstreams.upstreams:
        if _matches(upstream, proposal):
            return upstream
    return None


def describe(upstream: Upstream) -> dict[str, Any]:
    """Posture for `gate doctor`. Carries no secret, only where one comes from."""
    credential = upstream.credential
    return {
        "id": upstream.id,
        "kind": upstream.kind,
        "enforcement": upstream.effective_enforcement.value,
        "configured": credential is not None,
        "source": None if credential is None else credential.source,
        "inject": None if credential is None else credential.inject.type,
        # The reference, not the value: `secret/data/gate/pg#DATABASE_URL`
        # tells an operator where to look and tells an attacker nothing they
        # could not read from the config file anyway.
        "ref": None if credential is None else credential.ref,
    }
