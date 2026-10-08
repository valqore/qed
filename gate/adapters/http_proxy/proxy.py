"""The HTTP forward proxy (SPEC §12.3).

An ordinary HTTP forward proxy on a loopback port. Point an agent at it with
``HTTPS_PROXY=http://127.0.0.1:8888`` and every outbound call becomes an
:class:`~gate.core.schemas.ActionProposal`, decided by the same
``check_proposal`` the MCP proxy and ``gate check`` call.

Three things are worth knowing before reading the code.

**A tunnel is advisory, always.** ``CONNECT`` hands the gate ciphertext. It
can refuse to open the tunnel -- which is a real control, and the refusal is
recorded -- but it cannot see the method, the path or the body, and it cannot
replace the credential inside. So every tunnel is recorded as
``enforcement: advisory`` with the reason attached, whatever the operator
asked for on the command line. The alternative would be evidence claiming a
control the transport does not allow.

**Plain HTTP starts honest too.** Enforcing requires that the gate is holding
the credential, which means an ``http`` upstream in ``upstreams.yaml`` whose
credential resolves. With no broker there is nothing to hold, so the session
is advisory and says so at startup. The MCP proxy keeps the operator's flag in
that case because deployments existed before the broker did; this adapter has
no such history, so it has no reason to inherit the dishonesty.

**One request per connection.** v1 answers with ``Connection: close`` and
forwards with ``Connection: close``. Keep-alive and pipelining are where a
proxy and its upstream come to disagree about where one request ends, and a
smuggled second request would be the one request the gate never decided.
Correctness first; the cost is a TCP handshake per call on the plain-HTTP
path, and nothing at all on the tunnel path.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from collections.abc import AsyncIterator, Sequence
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Final, Literal
from urllib.parse import quote

from gate.adapters.common import AdapterInfo, build_proposal
from gate.adapters.http_proxy.targets import HttpIntent, action_name, classify_method, derive_target
from gate.adapters.http_proxy.targets import summary_for as _summary_for
from gate.adapters.http_proxy.wire import (
    MAX_HEADER_BLOCK,
    Headers,
    MalformedRequest,
    RequestLine,
    ResolvedTarget,
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
from gate.core.broker.injection import Injection, strip_agent_credentials
from gate.core.broker.model import Secret, UpstreamSet
from gate.core.schemas import (
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
from gate.infra.secrets.broker import Brokerage, CredentialBroker
from gate.runtime import CheckOutcome, Session, check_proposal

__all__ = [
    "ADAPTER_NAME",
    "HttpProxyOptions",
    "HttpProxyStats",
    "build_http_proposal",
    "http_upstreams",
    "run_http_proxy",
    "serving",
]

logger = logging.getLogger("gate.adapters.http")

ADAPTER_NAME: Final = "http-proxy/0.1.0"

FailMode = Literal["closed", "open"]

#: How an agent declares what it is doing, the HTTP counterpart of MCP's
#: ``_meta.intent`` (SPEC §12.1). Stripped before the request is forwarded:
#: it is for the gate, not for the upstream.
INTENT_HEADER: Final = "x-gate-intent"

#: Why a tunnel can never be enforcing. Recorded verbatim so an auditor
#: reading one advisory record does not have to find the documentation.
TUNNEL_REASON: Final = (
    "CONNECT opens a TLS tunnel: the gate decides whether the connection may be made, "
    "but the request inside it is ciphertext, so the credential cannot be replaced and "
    "the agent is using its own"
)

_CHUNK: Final = 64 * 1024


@dataclass(frozen=True)
class HttpProxyOptions:
    """Everything the proxy needs that is not the listening socket.

    One of ``human_hash`` and ``mandate`` must be set, for the same reason the
    MCP proxy insists on it: ``evaluate`` short-circuits to a synthetic
    ``AG-IDN-007`` BLOCK when a proposal has neither a human principal nor a
    mandate, *before* any rule in the bundle runs. A proxy left without
    identity would fill the chain with identical identity BLOCKs in which no
    policy rule had ever been evaluated, and in shadow mode nothing would look
    wrong.
    """

    environment: Environment = "dev"
    #: A ceiling, not a claim. ``advisory`` forces advisory; ``enforcing``
    #: permits it where the broker is actually holding the credential.
    enforcement: Enforcement = Enforcement.enforcing
    token_jti: str = "http-proxy-local"
    human_hash: str | None = None
    mandate: Mandate | None = None
    agent_chain: Sequence[str] = ()
    adapter_id: str = "adp_http_local"
    identity_note: str | None = None
    #: What to do when the *kernel* raises. An upstream that is down is not this.
    fail_mode: FailMode = "closed"
    #: Seconds to wait for the upstream TCP connection and for its first byte.
    #: After the first byte the response streams without a further deadline, so
    #: a slow download is not cut off halfway.
    upstream_timeout: float = 30.0
    #: Seconds to wait for a client to finish sending its request head.
    idle_timeout: float = 30.0
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
class HttpProxyStats:
    """Counters the CLI prints when the proxy stops."""

    requests: int = 0
    tunnels: int = 0
    allowed: int = 0
    refused: int = 0
    would_block: int = 0
    would_require_approval: int = 0
    #: Calls the gate decided without holding the credential. Every tunnel is
    #: one of these. Counted separately because a session that was entirely
    #: advisory looks identical to an enforcing one in every other number.
    advisory: int = 0
    #: Credentials the agent supplied and the gate removed, by header name.
    stripped: list[str] = field(default_factory=list)
    ungated: int = 0
    malformed: int = 0
    errors: int = 0
    bytes_to_upstream: int = 0
    bytes_to_client: int = 0
    decisions: list[str] = field(default_factory=list)

    @property
    def calls(self) -> int:
        return self.requests + self.tunnels


# --------------------------------------------------------------------------
# Proposal building -- importable on its own so tests need no listening port
# --------------------------------------------------------------------------


def build_http_proposal(
    *,
    line: RequestLine,
    target: ResolvedTarget,
    headers: Headers,
    options: HttpProxyOptions,
    mode: Mode,
    enforcement: Enforcement | None = None,
) -> tuple[ActionProposal, HttpIntent]:
    """Turn one request into a proposal. Pure apart from the id and the clock.

    ``enforcement`` overrides the option when the answer is already known for
    this request -- advisory for every tunnel, and whatever the broker said
    for a plain request. The option is only ever a ceiling.

    The query string goes into the parameters rather than into
    ``action.target``. It carries tokens, its order varies between calls that
    mean the same thing, and both of those would make a policy glob on the
    target either leaky or useless. In the parameters ``AG-DAT-001`` can still
    see it and the masking pass cleans it on the way into the chain.
    """
    intent = classify_method(line.method, target.path, connect=line.is_connect)
    if line.is_connect:
        resource = derive_target("https", target.authority)
        name = action_name(line.method, target.authority)
        params: dict[str, object] = {"host": target.host, "port": target.port}
    else:
        resource = derive_target(target.scheme, target.authority, target.path)
        name = action_name(line.method, target.path_only or "/")
        params = {
            "host": target.host,
            "path": target.path_only,
            "query": target.query,
            "content_type": get_header(headers, "content-type") or "",
            # The body is not read in `host_path` mode (SPEC §12.3), so
            # `params_hash` covers the request line and the headers that
            # describe the body, not the body itself. A rule that needs the
            # body needs `mode: mitm`, which is post-v1.
            "content_length": content_length(headers) or 0,
        }

    proposal = build_proposal(
        kind=ActionKind.http,
        name=name,
        target=resource,
        params=params,
        adapter=options.adapter,
        environment=options.environment,
        enforcement=options.enforcement if enforcement is None else enforcement,
        mode=mode,
        token_jti=options.token_jti,
        human_hash=options.human_hash,
        agent_chain=list(options.agent_chain),
        mandate_id=None if options.mandate is None else options.mandate.id,
        client_fingerprint=options.identity_note,
        summary=_summary_for(line.method, resource, intent),
        intent=get_header(headers, INTENT_HEADER) or None,
        writes=intent.writes,
        deletes=intent.deletes,
        scope=intent.scope,
        tags=list(options.tags),
        method=line.method,
    )
    return proposal, intent


def http_upstreams(upstreams: UpstreamSet) -> UpstreamSet:
    """The ``kind: http`` upstreams, which are the only ones this adapter uses.

    ``match_upstream`` does not look at ``kind``, so an upstream written for an
    MCP server with a loose ``match`` would otherwise be picked up here and the
    proxy would try to put a database URL in an HTTP header. Filtering at the
    adapter is the narrow fix; the alternative is making ``kind`` part of
    matching, which would change what the MCP proxy already does.
    """
    return UpstreamSet(upstreams=[u for u in upstreams.upstreams if u.kind == "http"])


def injection_problems(upstreams: UpstreamSet) -> list[str]:
    """Config this adapter cannot honour, found before the first request.

    An ``env`` injection means "put it in the child process's environment",
    which is the stdio MCP case and has no meaning for an HTTP request. An
    upstream configured that way would match, resolve, and then have its
    credential silently dropped -- so it is reported at startup instead,
    where somebody is still reading the output.
    """
    problems: list[str] = []
    for upstream in upstreams.upstreams:
        spec = upstream.credential
        if spec is not None and spec.inject.type == "env":
            problems.append(
                f"upstream {upstream.id} injects into the environment, which an HTTP "
                "request does not have. Use `inject: {type: header, ...}` or `query`."
            )
    return problems


# --------------------------------------------------------------------------
# The proxy
# --------------------------------------------------------------------------


class _HttpProxy:
    def __init__(
        self,
        *,
        session: Session,
        options: HttpProxyOptions,
        stats: HttpProxyStats,
        broker: CredentialBroker | None = None,
    ) -> None:
        self.session = session
        self.options = options
        self.stats = stats
        #: None when no `kind: http` upstream is configured, in which case the
        #: gate holds no credential and every request is advisory.
        self.broker = broker

    # ------------------------------------------------------------ connection

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """One client connection, one request (see the module docstring)."""
        try:
            await self._serve_one(reader, writer)
        except Exception as exc:  # pragma: no cover - last resort
            logger.error("proxy connection failed: %s: %s", type(exc).__name__, exc)
            self.stats.errors += 1
            await _send(writer, response(502, f"[gate] the proxy failed: {exc}\n"))
        finally:
            await _close(writer)

    async def _serve_one(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        head = await self._read_head(reader, writer)
        if head is None:
            return
        try:
            raw_line, raw_headers = split_head(head)
            line = parse_request_line(raw_line)
            headers = parse_headers(raw_headers)
            target = resolve_target(line, headers)
            chunked = has_chunked_body(headers)
            length = content_length(headers)
        except MalformedRequest as exc:
            self.stats.malformed += 1
            logger.info("refusing a malformed request: %s", exc)
            await _send(writer, response(exc.status, f"[gate] {exc}\n"))
            return

        if line.is_connect:
            self.stats.tunnels += 1
        else:
            self.stats.requests += 1

        if chunked:
            # A chunked request body would have to be re-framed to be
            # forwarded, and a proxy that re-frames a body is a proxy that can
            # be made to disagree with its upstream about where the request
            # ends. Refused rather than guessed at.
            self.stats.malformed += 1
            await _send(
                writer,
                response(
                    501,
                    "[gate] this proxy does not forward a chunked request body in v1. "
                    "Send the body with a Content-Length.\n",
                ),
            )
            return

        try:
            outcome, proposal, brokerage = self._decide(line, target, headers)
        except Exception as exc:
            logger.error("gate decision failed for %s %s: %s", line.method, target.host, exc)
            self.stats.errors += 1
            if self.options.fail_mode == "closed":
                await _send(
                    writer,
                    response(
                        503,
                        f"[gate ERROR] the policy kernel could not decide this request "
                        f"({exc}). fail_mode is 'closed', so it was not forwarded.\n",
                    ),
                )
                return
            self.stats.ungated += 1
            self._record_ungated(line, target, exc)
            await self._dispatch(
                reader,
                writer,
                line,
                target,
                headers,
                length,
                None,
                proposal_id=None,
                enforcement=self.options.enforcement,
            )
            return

        decision = outcome.effective_decision
        self.stats.decisions.append(
            f"{outcome.verdict.would_decision.value} {line.method} {target.authority}"
        )
        if outcome.verdict.would_decision is Decision.BLOCK:
            self.stats.would_block += 1
        elif outcome.verdict.would_decision is Decision.REQUIRE_APPROVAL:
            self.stats.would_require_approval += 1

        if decision is Decision.BLOCK:
            self.stats.refused += 1
            await _send(writer, response(403, _block_message(outcome)))
            return
        if decision is Decision.REQUIRE_APPROVAL:
            self.stats.refused += 1
            await _send(writer, response(403, _approval_message(outcome)))
            return

        self.stats.allowed += 1
        injection = None if brokerage is None else brokerage.injection
        if injection is not None and injection.needs_signing:
            # sigv4 covers the request body, so it cannot be planned ahead of
            # the send. Forwarding unsigned would mean the agent's own
            # credentials get used after all, which is the one outcome the
            # broker exists to prevent.
            self.stats.errors += 1
            self._record_result(
                proposal.id,
                status="error",
                error="signing not implemented",
                enforcement=proposal.context.enforcement,
            )
            await _send(
                writer,
                response(
                    501,
                    f"[gate] upstream {injection.upstream_id} needs request signing "
                    "(sigv4), which this build cannot do. The request was decided and "
                    "recorded, and not forwarded unsigned.\n",
                ),
            )
            return

        await self._dispatch(
            reader,
            writer,
            line,
            target,
            headers,
            length,
            injection,
            proposal_id=proposal.id,
            enforcement=proposal.context.enforcement,
        )

    async def _dispatch(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        line: RequestLine,
        target: ResolvedTarget,
        headers: Headers,
        length: int | None,
        injection: Injection | None,
        *,
        proposal_id: str | None,
        enforcement: Enforcement,
    ) -> None:
        if line.is_connect:
            await self._tunnel(
                reader, writer, target, proposal_id=proposal_id, enforcement=enforcement
            )
        else:
            await self._forward(
                reader,
                writer,
                line,
                target,
                headers,
                length,
                injection,
                proposal_id=proposal_id,
                enforcement=enforcement,
            )

    # ---------------------------------------------------------------- reading

    async def _read_head(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> bytes | None:
        """Everything up to the blank line, or None when there is no request.

        A connection that opens and closes with nothing on it is a health
        check or a port scan, not an error, and answering it with a 400 would
        put noise in the log where the real refusals are.
        """
        try:
            async with asyncio.timeout(self.options.idle_timeout):
                return await reader.readuntil(b"\r\n\r\n")
        except asyncio.IncompleteReadError as exc:
            if not exc.partial.strip():
                return None
            self.stats.malformed += 1
            await _send(writer, response(400, "[gate] the request head is incomplete\n"))
            return None
        except asyncio.LimitOverrunError:
            self.stats.malformed += 1
            await _send(
                writer,
                response(431, f"[gate] the request head exceeds {MAX_HEADER_BLOCK} bytes\n"),
            )
            return None
        except TimeoutError:
            self.stats.malformed += 1
            logger.info("a client did not finish its request head in time")
            return None

    # --------------------------------------------------------------- deciding

    def _decide(
        self, line: RequestLine, target: ResolvedTarget, headers: Headers
    ) -> tuple[CheckOutcome, ActionProposal, Brokerage | None]:
        """Decide one request, with ``enforcement`` derived rather than asserted.

        Built twice on purpose, as in the MCP proxy: the broker matches on the
        *proposal*, and the proposal carries the enforcement the broker
        decides. The first build answers "which upstream is this", the second
        records the honest answer.
        """
        draft, _ = build_http_proposal(
            line=line,
            target=target,
            headers=headers,
            options=self.options,
            mode=self.session.config.mode,
        )

        brokerage: Brokerage | None = None
        if line.is_connect or self.broker is None:
            # A tunnel is opaque and an unconfigured proxy holds nothing.
            enforcement = Enforcement.advisory
            reason = TUNNEL_REASON if line.is_connect else "no http upstream is configured"
        else:
            brokerage = self.broker.for_action(draft)
            enforcement = brokerage.enforcement
            reason = brokerage.reason
        if self.options.enforcement is Enforcement.advisory:
            # The flag is a ceiling. An operator can ask for less than the
            # broker can give, never for more.
            enforcement = Enforcement.advisory
        if enforcement is Enforcement.advisory:
            self.stats.advisory += 1
            if reason:
                logger.debug("advisory: %s %s: %s", line.method, target.authority, reason)

        proposal, _ = build_http_proposal(
            line=line,
            target=target,
            headers=headers,
            options=self.options,
            mode=self.session.config.mode,
            enforcement=enforcement,
        )
        return (
            check_proposal(self.session, proposal, mandate=self.options.mandate),
            proposal,
            brokerage if enforcement is Enforcement.enforcing else None,
        )

    # -------------------------------------------------------------- tunnelling

    async def _tunnel(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        target: ResolvedTarget,
        *,
        proposal_id: str | None,
        enforcement: Enforcement,
    ) -> None:
        """Open the TCP connection and copy bytes both ways until one side ends.

        Byte counts and duration are the only facts the gate has about a
        tunnel, so they are what the ``execution_result`` records. That is
        thin evidence and it is labelled as such; it is still the difference
        between "an agent opened a connection to this host at this time and
        moved 4 MB" and no record at all.
        """
        started = time.monotonic()
        upstream = await self._open(
            target, writer, proposal_id=proposal_id, enforcement=enforcement
        )
        if upstream is None:
            return
        up_reader, up_writer = upstream
        await _send(writer, connect_established())

        sent = [0, 0]

        async def pump(src: asyncio.StreamReader, dst: asyncio.StreamWriter, index: int) -> None:
            while chunk := await src.read(_CHUNK):
                dst.write(chunk)
                await dst.drain()
                sent[index] += len(chunk)

        tasks = [
            asyncio.create_task(pump(reader, up_writer, 0)),
            asyncio.create_task(pump(up_reader, writer, 1)),
        ]
        # First side to finish ends the tunnel. A TLS session closes both
        # directions together, so waiting for the second would only hold the
        # sockets open after the conversation is over.
        try:
            _, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for task in pending:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
        except OSError as exc:
            logger.info("tunnel to %s ended: %s", target.authority, exc)
        finally:
            self.stats.bytes_to_upstream += sent[0]
            self.stats.bytes_to_client += sent[1]
            await _close(up_writer)

        self._record_result(
            proposal_id,
            status="ok",
            error=None,
            elapsed=time.monotonic() - started,
            enforcement=enforcement,
            extra={
                "tunnel": True,
                "bytes_to_upstream": sent[0],
                "bytes_to_client": sent[1],
                # Said in the record, not only in the documentation: an
                # auditor reading one row should not have to know that
                # host_path mode cannot see inside a tunnel.
                "visibility": "host only; the request inside the tunnel is encrypted",
            },
        )

    # --------------------------------------------------------------- forwarding

    async def _forward(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        line: RequestLine,
        target: ResolvedTarget,
        headers: Headers,
        length: int | None,
        injection: Injection | None,
        *,
        proposal_id: str | None,
        enforcement: Enforcement,
    ) -> None:
        """Forward a plain request, with the agent's credentials replaced.

        Nothing is stripped when the gate is not holding a credential. An
        advisory proxy that removed the agent's own ``Authorization`` would
        break the call and replace it with nothing, which is worse than
        letting a credential the gate did not choose go to the host the agent
        was always going to reach.
        """
        started = time.monotonic()
        drop = {INTENT_HEADER}
        add: dict[str, str] = {}
        path = target.path
        if injection is not None:
            # Stripping comes before attaching. An adapter that added the
            # broker's header while leaving the agent's in place would be an
            # adapter where the agent still chooses which credential is used.
            _, removed = strip_agent_credentials(dict(headers))
            drop.update(name.lower() for name in removed)
            self.stats.stripped.extend(removed)
            add.update(injection.header_values())
            if injection.query:
                path = _with_query(path, injection.query)

        upstream = await self._open(
            target, writer, proposal_id=proposal_id, enforcement=enforcement
        )
        if upstream is None:
            return
        up_reader, up_writer = upstream
        forwarded = ResolvedTarget(
            scheme=target.scheme, host=target.host, port=target.port, path=path
        )
        try:
            up_writer.write(
                build_forward_request(
                    method=line.method,
                    target=forwarded,
                    headers=headers,
                    drop=frozenset(drop),
                    add=add,
                    body_length=length,
                )
            )
            if length:
                await _copy_exactly(reader, up_writer, length)
                self.stats.bytes_to_upstream += length
            await up_writer.drain()

            async with asyncio.timeout(self.options.upstream_timeout):
                status_line = await up_reader.readuntil(b"\r\n")
            writer.write(status_line)
            # No deadline past the first byte: a slow download is not a dead
            # upstream, and cutting one off halfway would look like a policy
            # decision to whoever was watching.
            while chunk := await up_reader.read(_CHUNK):
                writer.write(chunk)
                await writer.drain()
                self.stats.bytes_to_client += len(chunk)
            await writer.drain()
        except (OSError, asyncio.IncompleteReadError, TimeoutError) as exc:
            self.stats.errors += 1
            self._record_result(
                proposal_id,
                status="error",
                error=f"{type(exc).__name__}: {exc}",
                elapsed=time.monotonic() - started,
                enforcement=enforcement,
            )
            logger.info("forwarding to %s failed: %s", target.authority, exc)
            await _send(writer, response(502, f"[gate] the upstream failed: {exc}\n"))
            return
        finally:
            await _close(up_writer)

        self._record_result(
            proposal_id,
            status="ok",
            error=None,
            elapsed=time.monotonic() - started,
            enforcement=enforcement,
            extra={
                "http_status": _status_of(status_line),
                "credential": None if injection is None else injection.upstream_id,
                "stripped_headers": sorted(name for name in drop if name != INTENT_HEADER),
            },
        )

    async def _open(
        self,
        target: ResolvedTarget,
        writer: asyncio.StreamWriter,
        *,
        proposal_id: str | None,
        enforcement: Enforcement,
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter] | None:
        """Connect to the upstream, or answer the agent with a 502."""
        try:
            async with asyncio.timeout(self.options.upstream_timeout):
                return await asyncio.open_connection(target.host, target.port)
        except (OSError, TimeoutError) as exc:
            self.stats.errors += 1
            self._record_result(
                proposal_id,
                status="error",
                error=f"{type(exc).__name__}: {exc}",
                elapsed=0.0,
                enforcement=enforcement,
            )
            logger.info("could not reach %s: %s", target.authority, exc)
            await _send(
                writer,
                response(502, f"[gate] could not reach {target.authority}: {exc}\n"),
            )
            return None

    # ---------------------------------------------------------------- evidence

    def _record_result(
        self,
        proposal_id: str | None,
        *,
        status: str,
        error: str | None = None,
        elapsed: float = 0.0,
        enforcement: Enforcement | None = None,
        extra: dict[str, object] | None = None,
    ) -> None:
        """Append ``execution_result`` (SPEC §3.5, assurance per ADR-007.1).

        ``self`` rather than ``adapter`` on an advisory call: an advisory
        adapter is one the agent could have gone around, so its report is the
        agent's testimony and the chain says so.

        ``enforcement`` is the answer derived for *this* request, carried down
        from the proposal rather than read from the options here. The options
        hold the operator's flag, and a live run showed what reading it costs:
        a proposal recording ``advisory`` with the result two records later
        recording ``enforcing``, in the same chain, about the same call.
        """
        effective = self.options.enforcement if enforcement is None else enforcement
        payload: dict[str, object] = {
            "proposal_id": proposal_id,
            "status": status,
            "duration_ms": round(elapsed * 1000, 3),
        }
        if error is not None:
            payload["error"] = error
        payload.update(extra or {})
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

    def _record_ungated(self, line: RequestLine, target: ResolvedTarget, exc: Exception) -> None:
        """A request that went through without a decision (SPEC §10, ADR-003)."""
        try:
            self.session.writer.append(
                type_=EvidenceType.ungated_window,
                assurance=Assurance.adapter,
                payload={
                    "adapter": ADAPTER_NAME,
                    "adapter_id": self.options.adapter_id,
                    "method": line.method,
                    "host": target.authority,
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


def _block_message(outcome: CheckOutcome) -> str:
    hits = [hit for hit in outcome.verdict.hits if hit.verdict is Decision.BLOCK]
    ids = ", ".join(hit.rule_id for hit in hits) or "default verdict"
    first = hits[0] if hits else None
    text = f"[gate BLOCK] {ids}: {first.message if first else 'blocked by policy'}"
    if first is not None and first.fix:
        text += f" Fix: {first.fix}"
    return text + "\n"


def _approval_message(outcome: CheckOutcome) -> str:
    hits = [hit for hit in outcome.verdict.hits if hit.verdict is Decision.REQUIRE_APPROVAL]
    ids = ", ".join(hit.rule_id for hit in hits) or "default verdict"
    first = hits[0] if hits else None
    text = f"[gate APPROVAL PENDING] {ids}: {first.message if first else 'approval required'}"
    if first is not None and first.fix:
        text += f" Fix: {first.fix}"
    approval = outcome.verdict.approval_id
    if approval:
        text += f" id={approval}"
    return text + " Retry once it has been approved.\n"


# --------------------------------------------------------------------------
# Stream helpers
# --------------------------------------------------------------------------


def _with_query(path: str, values: dict[str, Secret]) -> str:
    """Append the broker's query parameters to the forwarded path.

    Percent-encoded, because a credential is arbitrary bytes and an
    unescaped `&` in one would split it into two parameters and send half of
    it under the wrong name.
    """
    rendered = "&".join(
        f"{quote(name, safe='')}={quote(secret.reveal(), safe='')}"
        for name, secret in values.items()
    )
    separator = "&" if "?" in path else "?"
    return f"{path}{separator}{rendered}"


def _status_of(status_line: bytes) -> int:
    parts = status_line.decode("latin-1", "replace").split(" ")
    return int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0


async def _copy_exactly(src: asyncio.StreamReader, dst: asyncio.StreamWriter, length: int) -> None:
    """Move exactly ``length`` bytes, which is what Content-Length declared."""
    remaining = length
    while remaining > 0:
        chunk = await src.read(min(_CHUNK, remaining))
        if not chunk:
            raise asyncio.IncompleteReadError(b"", length)
        dst.write(chunk)
        await dst.drain()
        remaining -= len(chunk)


async def _send(writer: asyncio.StreamWriter, payload: bytes) -> None:
    """Write to a socket that may already be gone."""
    try:
        writer.write(payload)
        await writer.drain()
    except (OSError, RuntimeError) as exc:
        logger.debug("could not answer the client: %s", exc)


async def _close(writer: asyncio.StreamWriter) -> None:
    with contextlib.suppress(OSError, RuntimeError):
        writer.close()
        await writer.wait_closed()


# --------------------------------------------------------------------------
# Wiring
# --------------------------------------------------------------------------


@asynccontextmanager
async def serving(
    *,
    session: Session,
    options: HttpProxyOptions,
    host: str = "127.0.0.1",
    port: int = 8888,
    stats: HttpProxyStats | None = None,
    broker: CredentialBroker | None = None,
) -> AsyncIterator[tuple[str, int, HttpProxyStats]]:
    """Run the proxy for as long as the block runs; yield where it is listening.

    ``port=0`` asks the operating system for a free one, which is how the
    tests get a real proxy without a fixed port.
    """
    counters = stats if stats is not None else HttpProxyStats()
    proxy = _HttpProxy(session=session, options=options, stats=counters, broker=broker)
    server = await asyncio.start_server(proxy.handle, host, port, limit=MAX_HEADER_BLOCK)
    bound = server.sockets[0].getsockname()
    try:
        yield str(bound[0]), int(bound[1]), counters
    finally:
        server.close()
        await server.wait_closed()


async def run_http_proxy(
    *,
    session: Session,
    options: HttpProxyOptions,
    host: str = "127.0.0.1",
    port: int = 8888,
    stats: HttpProxyStats | None = None,
    broker: CredentialBroker | None = None,
    ready: asyncio.Event | None = None,
) -> HttpProxyStats:
    """Serve until cancelled. ``ready`` is set once the socket is listening."""
    async with serving(
        session=session,
        options=options,
        host=host,
        port=port,
        stats=stats,
        broker=broker,
    ) as (bound_host, bound_port, counters):
        logger.info("listening on %s:%s", bound_host, bound_port)
        if ready is not None:
            ready.set()
        with contextlib.suppress(asyncio.CancelledError):
            await asyncio.Event().wait()
        return counters
