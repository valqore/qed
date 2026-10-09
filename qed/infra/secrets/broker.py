"""The broker an adapter actually talks to (SPEC §7).

Puts the two halves together: match the action to an upstream (pure), resolve
its credential (I/O), and hand back an injection plan — or say plainly that
there is none and the adapter is advisory for this target.

Why `enforcement` stops being a flag
------------------------------------

Before this, an adapter was told it was enforcing by a command-line option.
That is a claim, and it ends up in `context.enforcement`, which ends up in
the evidence. If the credential was missing the claim was simply wrong, and
nothing in the chain said so.

Now the answer is derived per action: QED is enforcing for this call if,
and only if, it is holding the credential for it. An adapter cannot assert
otherwise, because it never gets asked.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from qed.core.broker.injection import Injection, plan_injection
from qed.core.broker.model import Enforcement, Upstream, UpstreamSet, match_upstream
from qed.core.schemas import ActionProposal
from qed.infra.secrets.resolver import CredentialResolver, SecretResolutionError

logger = logging.getLogger(__name__)

__all__ = ["Brokerage", "CredentialBroker"]


@dataclass(frozen=True)
class Brokerage:
    """What the broker can do for one action."""

    enforcement: Enforcement
    upstream: Upstream | None = None
    injection: Injection | None = None
    #: Why it is advisory, when it is. Shown by `qed doctor` and recorded as
    #: free text on the proposal, never as a credential.
    reason: str = ""

    @property
    def enforcing(self) -> bool:
        return self.enforcement is Enforcement.enforcing


@dataclass
class CredentialBroker:
    """Resolves the credential for an action, or explains why it cannot."""

    upstreams: UpstreamSet
    resolver: CredentialResolver

    def for_server(self, server: str, *, environment: str) -> Brokerage:
        """The credential for a whole MCP server, resolved at spawn time.

        A stdio child process receives its environment once, before any tool
        call exists, so an `env` injection cannot be per-action however much
        SPEC §7.2 would prefer it. This matches on `mcp_server` alone -- the
        part of the rule that is knowable at spawn -- and the per-action
        :meth:`for_action` still decides what `context.enforcement` records
        for each individual call, which can differ when the upstream also
        constrains the environment or the target.
        """
        for upstream in self.upstreams.upstreams:
            if upstream.match.mcp_server != server:
                continue
            environments = upstream.match.environments
            if environments is not None and environment not in environments:
                continue
            if upstream.credential is None:
                return Brokerage(
                    enforcement=Enforcement.advisory,
                    upstream=upstream,
                    reason=f"upstream {upstream.id} has no credential configured",
                )
            try:
                secret = self.resolver.resolve(upstream.credential)
            except SecretResolutionError as exc:
                logger.warning("upstream %s is advisory: %s", upstream.id, exc)
                return Brokerage(
                    enforcement=Enforcement.advisory,
                    upstream=upstream,
                    reason=f"credential for {upstream.id} is unavailable: {exc}",
                )
            return Brokerage(
                enforcement=upstream.enforcement,
                upstream=upstream,
                injection=plan_injection(upstream, secret),
            )
        return Brokerage(
            enforcement=Enforcement.advisory,
            reason=f"no upstream is configured for the MCP server {server!r}",
        )

    def for_action(self, proposal: ActionProposal) -> Brokerage:
        upstream = match_upstream(proposal, self.upstreams)
        if upstream is None:
            return Brokerage(
                enforcement=Enforcement.advisory,
                reason="no upstream matches this action, so the agent is using its own credentials",
            )
        if upstream.credential is None:
            return Brokerage(
                enforcement=Enforcement.advisory,
                upstream=upstream,
                reason=f"upstream {upstream.id} has no credential configured",
            )
        try:
            secret = self.resolver.resolve(upstream.credential)
        except SecretResolutionError as exc:
            # Advisory, loudly. The alternative -- failing the action -- would
            # make a missing environment variable look like a policy decision,
            # and the operator would go looking in the wrong place.
            logger.warning("upstream %s is advisory: %s", upstream.id, exc)
            return Brokerage(
                enforcement=Enforcement.advisory,
                upstream=upstream,
                reason=f"credential for {upstream.id} is unavailable: {exc}",
            )
        return Brokerage(
            enforcement=upstream.enforcement,
            upstream=upstream,
            injection=plan_injection(upstream, secret),
        )
