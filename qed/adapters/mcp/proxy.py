"""The MCP proxy itself (SPEC §12.1).

One process, two MCP connections. Toward the agent it is an MCP server; toward
the upstream it is an MCP client. Every ``tools/call`` becomes an
:class:`~qed.core.schemas.ActionProposal`, goes through
``qed.runtime.check_proposal`` -- the same function ``qed check`` calls -- and
is then forwarded or refused according to the verdict.

Three things are worth knowing before reading the code.

**Identity is preserved.** ``initialize`` reports the upstream's own
``serverInfo``; the proxy adds a line to ``instructions`` instead of renaming the
server. An agent whose tool list suddenly came from ``qed-proxy`` would have to
be reconfigured to be governed, and the point is that it does not.

**Capabilities are mirrored, not claimed.** A handler is registered only when
the upstream advertises the matching capability, so the proxy never advertises
``prompts`` to a client whose upstream has none.

**Shadow mode forwards everything.** ``CheckOutcome.enforced`` is false when the
service runs in shadow (ADR-003), ``effective_decision`` is then ALLOW, and this
module reads only ``effective_decision``. The verdict still goes into the chain
with ``mode: shadow``, which is what makes "we have been observing since this
date" a provable statement rather than a claim.
"""

from __future__ import annotations

import logging
import time
from collections.abc import AsyncIterator, Sequence
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Final, Literal

import mcp.types as mcp_types
from mcp import ClientSession, StdioServerParameters, stdio_client
from mcp.client.streamable_http import streamable_http_client
from mcp.server.context import ServerRequestContext
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

from qed.adapters.common import AdapterInfo, build_proposal
from qed.adapters.mcp.intent import ToolIntent, classify
from qed.adapters.mcp.targets import DEFAULT_TEMPLATE, derive_target, validate_template
from qed.core.schemas import (
    ActionKind,
    ActionProposal,
    Assurance,
    Decision,
    Enforcement,
    Environment,
    EvidenceType,
    Mandate,
    Mode,
)
from qed.infra.secrets.broker import CredentialBroker
from qed.runtime import CheckOutcome, Session, check_proposal

__all__ = [
    "ADAPTER_NAME",
    "ProxyOptions",
    "UpstreamSpec",
    "build_tool_proposal",
    "run_proxy",
]

logger = logging.getLogger("qed.adapters.mcp")

ADAPTER_NAME: Final = "mcp-proxy/0.1.0"

#: Appended to the upstream's ``instructions`` so a capable client can tell its
#: model why a call might come back refused. Deliberately short; it lands in the
#: model's context on every session.
_INSTRUCTION_NOTE: Final = (
    "Tool calls to this server pass through QED, a policy and evidence kernel. "
    "Every call is recorded. A refused call comes back as a tool error beginning "
    "with [qed BLOCK] or [qed APPROVAL PENDING] and explains which rule applied."
)

FailMode = Literal["closed", "open"]


@dataclass(frozen=True)
class UpstreamSpec:
    """How to reach the upstream MCP server.

    Exactly one of ``command`` and ``url`` is set: stdio for a local server
    process, Streamable HTTP for a remote one.
    """

    name: str
    command: str | None = None
    args: Sequence[str] = ()
    url: str | None = None
    env: dict[str, str] | None = None
    cwd: str | None = None
    target_template: str = DEFAULT_TEMPLATE

    def __post_init__(self) -> None:
        if bool(self.command) == bool(self.url):
            raise ValueError("an upstream needs either a command (stdio) or a url, not both")
        if not self.name.strip():
            raise ValueError("an upstream needs a name; it appears in every action.name")
        validate_template(self.target_template)


@dataclass(frozen=True)
class ProxyOptions:
    """Everything the proxy needs that is not the upstream connection.

    One of ``human_hash`` and ``mandate`` must be set, and the proxy refuses to
    run without either. The reason is worth stating because it looks like an
    over-strict default:

    ``evaluate`` short-circuits to a synthetic ``AG-IDN-007`` BLOCK when a
    proposal has neither a human principal nor a mandate -- an agent acting on
    nobody's authority. That is the correct verdict, but it is reached *before*
    any rule in the bundle is evaluated. A proxy that left identity unset would
    therefore write a chain of identical identity BLOCKs in which no policy rule
    had ever run, and in shadow mode nothing would be stopped and nothing would
    look wrong. The same shape of silent degradation the week 1 review found in
    Valqore's gateway, in a different place.
    """

    environment: Environment = "dev"
    enforcement: Enforcement = Enforcement.enforcing
    token_jti: str = "mcp-proxy-local"
    #: The operator this session acts for (SPEC §10.6). Build it with
    #: ``qed.core.evidence.hashing.principal_hash``.
    human_hash: str | None = None
    #: A signed mandate, for the unattended path. Passed to the kernel as-is.
    mandate: Mandate | None = None
    agent_chain: Sequence[str] = ()
    adapter_id: str = "adp_mcp_local"
    #: How identity was established. Advisory and spoofable by design (SPEC §3.1),
    #: which is exactly the right field for "the adapter asserted this".
    identity_note: str | None = None
    #: What to do when the *kernel* raises. Upstream failures are not this.
    fail_mode: FailMode = "closed"
    #: Seconds to wait for an upstream tool call. ``None`` waits forever.
    upstream_timeout: float | None = None
    tags: Sequence[str] = ()

    def __post_init__(self) -> None:
        if self.human_hash is None and self.mandate is None:
            raise ValueError(
                "the proxy needs either a human principal or a mandate: without one every "
                "verdict is a synthetic AG-IDN-007 identity BLOCK and no policy rule is "
                "ever evaluated"
            )

    @property
    def adapter(self) -> AdapterInfo:
        return AdapterInfo(ADAPTER_NAME, self.adapter_id)


@dataclass
class ProxyStats:
    """Counters the CLI prints when the session ends."""

    calls: int = 0
    allowed: int = 0
    would_block: int = 0
    would_require_approval: int = 0
    refused: int = 0
    ungated: int = 0
    passthrough: int = 0
    #: Calls QED decided but did not hold the credential for. Worth
    #: counting separately: a session that is entirely advisory looks
    #: identical to an enforcing one in every other number here.
    advisory: int = 0
    errors: int = 0
    decisions: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------
# Proposal building -- importable on its own so tests need no live server
# --------------------------------------------------------------------------


def build_tool_proposal(
    *,
    upstream: UpstreamSpec,
    tool: str,
    arguments: object,
    options: ProxyOptions,
    mode: Mode,
    intent_text: str | None = None,
    enforcement: Enforcement | None = None,
) -> tuple[ActionProposal, ToolIntent]:
    """Turn one ``tools/call`` into a proposal. Pure apart from id and clock.

    ``enforcement`` overrides the option when the broker has answered for this
    specific action. That is the honest source: QED is enforcing for a
    call if and only if it is holding the credential for it, and an adapter
    that asserted otherwise would be putting a claim into the evidence that
    nothing backs.
    """
    hints = classify(f"{upstream.name}.{tool}", arguments)
    target = derive_target(
        server=upstream.name,
        tool=tool,
        arguments=arguments,
        environment=options.environment,
        template=upstream.target_template,
    )
    proposal = build_proposal(
        kind=ActionKind.mcp_tool,
        name=f"{upstream.name}.{tool}",
        target=target,
        params=arguments,
        adapter=options.adapter,
        environment=options.environment,
        enforcement=options.enforcement if enforcement is None else enforcement,
        mode=mode,
        token_jti=options.token_jti,
        human_hash=options.human_hash,
        agent_chain=list(options.agent_chain),
        mandate_id=None if options.mandate is None else options.mandate.id,
        client_fingerprint=options.identity_note,
        summary=_summary(upstream.name, tool, target, hints),
        intent=intent_text,
        writes=hints.writes,
        deletes=hints.deletes,
        scope=hints.scope,
        tags=list(options.tags),
    )
    return proposal, hints


def _summary(server: str, tool: str, target: str, hints: ToolIntent) -> str:
    """One line an approver can act on without reading the parameters."""
    verb = {"read": "read", "create": "create on", "update": "change", "delete": "delete on"}.get(
        hints.change_type, "call"
    )
    scope = {"single_resource": "", "multi_resource": " (more than one resource)"}.get(
        hints.scope, f" ({hints.scope}-wide)"
    )
    return f"{server}.{tool} wants to {verb} {target}{scope}"


# --------------------------------------------------------------------------
# The proxy
# --------------------------------------------------------------------------


class _Proxy:
    def __init__(
        self,
        *,
        session: Session,
        upstream: UpstreamSpec,
        client: ClientSession,
        options: ProxyOptions,
        stats: ProxyStats,
        broker: CredentialBroker | None = None,
    ) -> None:
        self.session = session
        self.upstream = upstream
        self.client = client
        self.options = options
        self.stats = stats
        #: None when no upstreams are configured, in which case the adapter
        #: keeps whatever `options.enforcement` claims -- which is what every
        #: deployment looked like before week 5.
        self.broker = broker

    # ----------------------------------------------------------------- tools

    async def on_list_tools(
        self,
        ctx: ServerRequestContext[object],
        params: mcp_types.PaginatedRequestParams | None,
    ) -> mcp_types.ListToolsResult:
        """Pass the upstream list through unchanged.

        SPEC §12.1 also filters this list by the token's ``mcp:<server>:<tool>``
        scopes. There are no tokens until week 3, and filtering against a scope
        set that does not exist yet would mean inventing one here. The list is
        forwarded whole, and every call in it is still decided.
        """
        return await self.client.list_tools(params=params)

    async def on_call_tool(
        self,
        ctx: ServerRequestContext[object],
        params: mcp_types.CallToolRequestParams,
    ) -> mcp_types.CallToolResult:
        tool = params.name
        arguments = params.arguments or {}
        self.stats.calls += 1

        try:
            outcome, proposal = self._decide(tool, arguments, _intent_of(params))
        except Exception as exc:  # the kernel failed: a bug, a full disk, a locked db
            logger.error("qed decision failed for %s.%s: %s", self.upstream.name, tool, exc)
            self.stats.errors += 1
            if self.options.fail_mode == "closed":
                return _tool_error(
                    f"[qed ERROR] the policy kernel could not decide this call ({exc}). "
                    "fail_mode is 'closed', so it was not forwarded."
                )
            self.stats.ungated += 1
            self._record_ungated(tool, exc)
            return await self._forward(tool, arguments, proposal_id=None)

        decision = outcome.effective_decision
        self.stats.decisions.append(
            f"{outcome.verdict.would_decision.value} {self.upstream.name}.{tool}"
        )
        if outcome.verdict.would_decision is Decision.BLOCK:
            self.stats.would_block += 1
        elif outcome.verdict.would_decision is Decision.REQUIRE_APPROVAL:
            self.stats.would_require_approval += 1

        if decision is Decision.BLOCK:
            self.stats.refused += 1
            return _tool_error(_block_message(outcome))
        if decision is Decision.REQUIRE_APPROVAL:
            self.stats.refused += 1
            return _tool_error(_approval_message(outcome))

        self.stats.allowed += 1
        return await self._forward(
            tool,
            arguments,
            proposal_id=proposal.id,
            enforcement=proposal.context.enforcement,
        )

    # ------------------------------------------------- resources and prompts

    async def on_list_resources(
        self,
        ctx: ServerRequestContext[object],
        params: mcp_types.PaginatedRequestParams | None,
    ) -> mcp_types.ListResourcesResult:
        self.stats.passthrough += 1
        return await self.client.list_resources(params=params)

    async def on_list_resource_templates(
        self,
        ctx: ServerRequestContext[object],
        params: mcp_types.PaginatedRequestParams | None,
    ) -> mcp_types.ListResourceTemplatesResult:
        self.stats.passthrough += 1
        return await self.client.list_resource_templates(params=params)

    async def on_read_resource(
        self,
        ctx: ServerRequestContext[object],
        params: mcp_types.ReadResourceRequestParams,
    ) -> mcp_types.ReadResourceResult:
        """Read-through, recorded, never refused (SPEC §12.1).

        The verdict is computed and written so that an operator can see what a
        rule *would* do to resource reads before v2 starts enforcing them, but
        it is not acted on here whatever the configured mode says. v1 promises
        resources are passthrough, and a BLOCK that silently started applying
        because someone flipped ``mode: enforce`` would break that promise.
        """
        self._record_only("resources/read", {"uri": str(params.uri)})
        return await self.client.read_resource(params.uri)

    async def on_list_prompts(
        self,
        ctx: ServerRequestContext[object],
        params: mcp_types.PaginatedRequestParams | None,
    ) -> mcp_types.ListPromptsResult:
        self.stats.passthrough += 1
        return await self.client.list_prompts(params=params)

    async def on_get_prompt(
        self,
        ctx: ServerRequestContext[object],
        params: mcp_types.GetPromptRequestParams,
    ) -> mcp_types.GetPromptResult:
        """Read-through, recorded, never refused. Same reasoning as resources."""
        self._record_only("prompts/get", {"name": params.name})
        return await self.client.get_prompt(params.name, params.arguments)

    # -------------------------------------------------------------- internals

    def _decide(
        self, tool: str, arguments: object, intent_text: str | None
    ) -> tuple[CheckOutcome, ActionProposal]:
        # Built twice on purpose. The broker matches on the *proposal*, and
        # the proposal carries the enforcement the broker decides -- so the
        # first build answers "which upstream is this", and the second records
        # the honest answer. Both are pure apart from the id, and the cost is
        # a dictionary walk; the alternative is a proposal whose
        # `enforcement` field was filled in before anyone knew whether it was
        # true.
        draft, _ = build_tool_proposal(
            upstream=self.upstream,
            tool=tool,
            arguments=arguments,
            options=self.options,
            mode=self.session.config.mode,
            intent_text=intent_text,
        )
        enforcement = self.options.enforcement
        if self.broker is not None:
            brokerage = self.broker.for_action(draft)
            enforcement = brokerage.enforcement
            if not brokerage.enforcing and brokerage.reason:
                self.stats.advisory += 1

        proposal, _ = build_tool_proposal(
            upstream=self.upstream,
            tool=tool,
            arguments=arguments,
            options=self.options,
            mode=self.session.config.mode,
            intent_text=intent_text,
            enforcement=enforcement,
        )
        return check_proposal(self.session, proposal, mandate=self.options.mandate), proposal

    def _record_only(self, pseudo_tool: str, arguments: dict[str, object]) -> None:
        """Decide and record a read-through call, then ignore the verdict."""
        self.stats.passthrough += 1
        try:
            self._decide(pseudo_tool, arguments, None)
        except Exception as exc:  # recording must never break a read
            logger.warning("could not record %s.%s: %s", self.upstream.name, pseudo_tool, exc)
            self.stats.errors += 1

    async def _forward(
        self,
        tool: str,
        arguments: dict[str, object],
        *,
        proposal_id: str | None,
        enforcement: Enforcement | None = None,
    ) -> mcp_types.CallToolResult:
        """Call the upstream and record what came back.

        ``enforcement`` is the value the broker derived for *this* call, taken
        off the proposal that was just decided. It is passed down rather than
        read from the options at the recording site, because the options hold
        the operator's flag and the flag is the thing that was wrong.
        """
        started = time.monotonic()
        try:
            result = await self.client.call_tool(
                tool, arguments, read_timeout_seconds=self.options.upstream_timeout
            )
        except Exception as exc:
            self._record_result(
                proposal_id,
                status="error",
                error=f"{type(exc).__name__}: {exc}",
                elapsed=time.monotonic() - started,
                enforcement=enforcement,
            )
            self.stats.errors += 1
            return _tool_error(f"[qed] the upstream server failed: {type(exc).__name__}: {exc}")

        if not isinstance(result, mcp_types.CallToolResult):
            # The SDK can return an input-required or task result for tools that
            # use those flows. Neither is a completed execution, so it is
            # recorded as such and handed back untouched.
            self._record_result(
                proposal_id,
                status="deferred",
                error=None,
                elapsed=time.monotonic() - started,
                detail=type(result).__name__,
                enforcement=enforcement,
            )
            return mcp_types.CallToolResult(
                content=[
                    mcp_types.TextContent(
                        type="text",
                        text=(
                            "[qed] the upstream returned a "
                            f"{type(result).__name__}; qed v0.1 proxies completed tool "
                            "results only. The call was recorded and not retried."
                        ),
                    )
                ],
                is_error=True,
            )

        self._record_result(
            proposal_id,
            status="error" if result.is_error else "ok",
            error=None,
            elapsed=time.monotonic() - started,
            enforcement=enforcement,
        )
        return result

    def _record_result(
        self,
        proposal_id: str | None,
        *,
        status: str,
        error: str | None,
        elapsed: float,
        detail: str | None = None,
        enforcement: Enforcement | None = None,
    ) -> None:
        """Append ``execution_result`` (SPEC §3.5, assurance per ADR-007.1).

        ``adapter`` when the proxy was enforcing, ``self`` when it was advisory.
        An advisory adapter is one the agent could have gone around, so its
        report is the agent's testimony and the chain says so.

        ``enforcement`` is the answer the broker derived for this call. It
        falls back to the option only where there is no proposal to take it
        from -- the fail-open path, where nothing was decided and nothing was
        derived. A live run of the HTTP proxy is what found this: the proposal
        recorded ``advisory`` and the result beside it recorded ``enforcing``,
        from the flag, two records apart in the same chain.
        """
        effective = self.options.enforcement if enforcement is None else enforcement
        payload: dict[str, object] = {
            "proposal_id": proposal_id,
            "status": status,
            "duration_ms": round(elapsed * 1000, 3),
        }
        if error is not None:
            payload["error"] = error
        if detail is not None:
            payload["detail"] = detail
        assurance = Assurance.adapter if effective is Enforcement.enforcing else Assurance.self_
        try:
            self.session.writer.append(
                type_=EvidenceType.execution_result,
                assurance=assurance,
                payload=payload,
                mode=self.session.config.mode,
                enforcement=effective,
                proposal_id=proposal_id,
            )
        except Exception as exc:  # pragma: no cover - disk level failure
            logger.error("could not record execution result: %s", exc)

    def _record_ungated(self, tool: str, exc: Exception) -> None:
        """A call that went through without a decision (SPEC §10, ADR-003).

        The gap is a record, not silence. An auditor reading the chain sees a
        window with a reason and a count rather than a quiet day.
        """
        try:
            self.session.writer.append(
                type_=EvidenceType.ungated_window,
                assurance=Assurance.adapter,
                payload={
                    "adapter": ADAPTER_NAME,
                    "adapter_id": self.options.adapter_id,
                    "server": self.upstream.name,
                    "tool": tool,
                    "calls": 1,
                    "reason": f"{type(exc).__name__}: {exc}",
                    "fail_mode": self.options.fail_mode,
                },
                mode=self.session.config.mode,
                enforcement=self.options.enforcement,
            )
        except Exception as inner:  # pragma: no cover - disk level failure
            logger.error("could not record the ungated window: %s", inner)


# --------------------------------------------------------------------------
# Messages the agent sees
# --------------------------------------------------------------------------


def _tool_error(message: str) -> mcp_types.CallToolResult:
    """A tool-level error, which is what a client shows to its model."""
    return mcp_types.CallToolResult(
        content=[mcp_types.TextContent(type="text", text=message)], is_error=True
    )


def _block_message(outcome: CheckOutcome) -> str:
    hits = [h for h in outcome.verdict.hits if h.verdict is Decision.BLOCK]
    ids = ", ".join(h.rule_id for h in hits) or "default verdict"
    first = hits[0] if hits else None
    text = f"[qed BLOCK] {ids}: {first.message if first else 'blocked by policy'}"
    if first is not None and first.fix:
        text += f" Fix: {first.fix}"
    return text


def _approval_message(outcome: CheckOutcome) -> str:
    hits = [h for h in outcome.verdict.hits if h.verdict is Decision.REQUIRE_APPROVAL]
    ids = ", ".join(h.rule_id for h in hits) or "default verdict"
    first = hits[0] if hits else None
    text = f"[qed APPROVAL PENDING] {ids}: {first.message if first else 'approval required'}"
    if first is not None and first.fix:
        text += f" Fix: {first.fix}"
    # SPEC §12.1 wants an approval id and an expiry in this message. The approval
    # service is week 4; until it exists, saying "id=none expires=never" would be
    # worse than saying plainly that there is nothing to wait for yet.
    return text + " No approval route is configured in this build (approvals land in week 4)."


def _intent_of(params: mcp_types.CallToolRequestParams) -> str | None:
    """``_meta.intent``, when the client sends one (SPEC §12.1)."""
    meta = params.meta
    if not isinstance(meta, dict):
        return None
    value = meta.get("intent")
    return value if isinstance(value, str) and value.strip() else None


# --------------------------------------------------------------------------
# Wiring
# --------------------------------------------------------------------------


@asynccontextmanager
async def _connect(
    upstream: UpstreamSpec, *, injected_env: dict[str, str] | None = None
) -> AsyncIterator[ClientSession]:
    """Open and initialise the upstream connection, stdio or Streamable HTTP.

    ``injected_env`` is the broker's contribution, merged over whatever the
    spec already carries. It is applied here rather than per call because a
    stdio child receives its environment once, at spawn, and no amount of
    wishing in SPEC §7.2 changes that.
    """
    if upstream.command is not None:
        env = dict(upstream.env or {})
        if injected_env:
            env.update(injected_env)
        params = StdioServerParameters(
            command=upstream.command,
            args=list(upstream.args),
            env=env or None,
            cwd=upstream.cwd,
        )
        async with (
            stdio_client(params) as (read, write),
            ClientSession(read, write, client_info=_client_info()) as client,
        ):
            await client.initialize()
            yield client
        return

    assert upstream.url is not None  # guaranteed by UpstreamSpec.__post_init__
    async with streamable_http_client(upstream.url) as streams:
        read, write = streams[0], streams[1]
        async with ClientSession(read, write, client_info=_client_info()) as client:
            await client.initialize()
            yield client


def _client_info() -> mcp_types.Implementation:
    return mcp_types.Implementation(name="qed-mcp-proxy", version="0.1.0")


def _build_server(proxy: _Proxy, client: ClientSession) -> Server[object]:
    """A server that advertises the upstream's identity and capabilities."""
    info = client.server_info
    capabilities = client.server_capabilities
    has_tools = capabilities is not None and capabilities.tools is not None
    has_resources = capabilities is not None and capabilities.resources is not None
    has_prompts = capabilities is not None and capabilities.prompts is not None

    upstream_instructions = (client.instructions or "").strip()
    instructions = (
        f"{upstream_instructions}\n\n{_INSTRUCTION_NOTE}"
        if upstream_instructions
        else _INSTRUCTION_NOTE
    )

    return Server(
        name=info.name if info is not None else proxy.upstream.name,
        version=(info.version if info is not None else None) or "",
        title=info.title if info is not None else None,
        instructions=instructions,
        on_list_tools=proxy.on_list_tools if has_tools else None,
        on_call_tool=proxy.on_call_tool if has_tools else None,
        on_list_resources=proxy.on_list_resources if has_resources else None,
        on_list_resource_templates=(proxy.on_list_resource_templates if has_resources else None),
        on_read_resource=proxy.on_read_resource if has_resources else None,
        on_list_prompts=proxy.on_list_prompts if has_prompts else None,
        on_get_prompt=proxy.on_get_prompt if has_prompts else None,
    )


async def run_proxy(
    *,
    session: Session,
    upstream: UpstreamSpec,
    options: ProxyOptions | None = None,
    stats: ProxyStats | None = None,
    broker: CredentialBroker | None = None,
) -> ProxyStats:
    """Serve the proxy on stdio until the client disconnects.

    With a ``broker``, `context.enforcement` on every proposal is derived
    from whether QED actually holds the credential for that action.
    Without one it stays whatever ``options.enforcement`` claims, which is
    what every deployment looked like before the broker existed.
    """
    opts = options if options is not None else ProxyOptions()
    counters = stats if stats is not None else ProxyStats()

    injected: dict[str, str] | None = None
    if broker is not None:
        spawn = broker.for_server(upstream.name, environment=opts.environment)
        if spawn.injection is not None and spawn.injection.env:
            injected = spawn.injection.env_values()
            logger.info(
                "upstream %s: injecting %d credential(s) from %s",
                upstream.name,
                len(injected),
                spawn.injection.upstream_id,
            )
        elif spawn.reason:
            logger.warning("upstream %s: %s", upstream.name, spawn.reason)

    async with _connect(upstream, injected_env=injected) as client:
        proxy = _Proxy(
            session=session,
            upstream=upstream,
            client=client,
            options=opts,
            stats=counters,
            broker=broker,
        )
        server = _build_server(proxy, client)
        async with stdio_server() as (read, write):
            await server.run(read, write, server.create_initialization_options())
    return counters
