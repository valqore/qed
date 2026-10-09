"""Shared adapter library (SPEC §12, intro).

Every adapter needs the same four things: a proposal id, a hash of the real
parameters, a bounded copy of those parameters for the engine to match on, and
the input limits from SPEC §17. They live here so the MCP proxy, the coding-agent
hooks (week 6) and the HTTP proxy (week 5) cannot drift apart on any of them --
two adapters hashing parameters differently would make the same call produce two
different ``params_hash`` values in one chain.

A note on ``params_redacted``, because the name invites exactly the wrong thing:

**An adapter must not mask secrets out of it.** The field is the *bounded* view
of the parameters, not the *masked* one. Masking happens on the way into the
evidence chain (``qed/core/evidence/masking.py``), after the engine has seen
the value, because ``AG-DAT-001`` exists to BLOCK a call whose parameters carry
a private key or an ``AKIA`` access key. An adapter that masked first would hand
the engine ``"[REDACTED]"``, the rule would not fire, the call would go through,
and the chain would show a clean ALLOW. The only things this module removes are
size and types that cannot be canonicalised.
"""

from __future__ import annotations

from typing import Final

from ulid import ULID

from qed.core import jcs
from qed.core.schemas import (
    Action,
    ActionKind,
    ActionProposal,
    BlastHints,
    Context,
    CostEstimate,
    Enforcement,
    Environment,
    Mode,
    Principal,
    Scope,
    Timestamp,
    utcnow,
)

__all__ = [
    "MAX_PARAMS_BYTES",
    "MAX_PROPOSAL_BYTES",
    "OMITTED_KEY",
    "AdapterInfo",
    "bounded_params",
    "build_proposal",
    "new_proposal_id",
    "params_hash",
]

#: SPEC §17 input limits. The kernel enforces them at the API edge; adapters
#: respect them at the source so a large call is trimmed rather than rejected.
MAX_PROPOSAL_BYTES: Final = 64 * 1024
MAX_PARAMS_BYTES: Final = 16 * 1024

#: How deep ``bounded_params`` will walk before it stops describing structure.
_MAX_DEPTH: Final = 8


class AdapterInfo:
    """Which adapter build, and which registered instance of it (SPEC §12.6)."""

    __slots__ = ("adapter", "adapter_id")

    def __init__(self, adapter: str, adapter_id: str) -> None:
        self.adapter = adapter
        self.adapter_id = adapter_id


def new_proposal_id() -> str:
    """A fresh ULID. Monotonic enough to sort by, single-use by SPEC §17."""
    return str(ULID())


def params_hash(params: object) -> str:
    """``sha256(JCS(params))`` -- the hash of what the agent actually sent.

    Computed over the *full* parameters, before any trimming, so the hash still
    identifies the real call when ``params_redacted`` had to be cut down.
    """
    return jcs.sha256_hex(_canonicalisable(params, 0))


def bounded_params(params: object, *, limit: int = MAX_PARAMS_BYTES) -> dict[str, object] | None:
    """A copy of ``params`` small enough for the engine and the chain.

    Returns ``None`` for a call with no parameters, so the proposal carries
    ``params_redacted: null`` rather than an empty object -- the engine's
    predicates treat a missing field and an empty one differently.

    Values that do not survive trimming are replaced by a marker that says so.
    An auditor reading ``"[trimmed: 412 chars]"`` knows the record is partial;
    the ``params_hash`` above still covers the whole thing.
    """
    value = _canonicalisable(params, 0)
    if not isinstance(value, dict) or not value:
        return None
    if len(jcs.dumps(value)) <= limit:
        return value
    return _trim(value, limit)


def build_proposal(
    *,
    kind: ActionKind,
    name: str,
    target: str,
    params: object,
    adapter: AdapterInfo,
    environment: Environment,
    enforcement: Enforcement,
    mode: Mode,
    token_jti: str,
    human_hash: str | None = None,
    agent_chain: list[str] | None = None,
    mandate_id: str | None = None,
    client_fingerprint: str | None = None,
    summary: str = "",
    intent: str | None = None,
    writes: bool = False,
    deletes: bool = False,
    scope: Scope = "single_resource",
    tags: list[str] | None = None,
    cost: CostEstimate | None = None,
    method: str | None = None,
    proposal_id: str | None = None,
    ts: Timestamp | None = None,
) -> ActionProposal:
    """Assemble one proposal. Pure apart from the id and the clock."""
    return ActionProposal(
        id=proposal_id if proposal_id is not None else new_proposal_id(),
        ts=ts if ts is not None else utcnow(),
        principal=Principal(
            token_jti=token_jti,
            human_hash=human_hash,
            agent_chain=list(agent_chain or []),
            mandate_id=mandate_id,
            client_fingerprint=client_fingerprint,
        ),
        action=Action(
            kind=kind,
            name=name,
            target=target,
            params_hash=params_hash(params),
            params_redacted=bounded_params(params),
            method=method,
        ),
        context=Context(
            environment=environment,
            adapter=adapter.adapter,
            adapter_id=adapter.adapter_id,
            enforcement=enforcement,
            mode=mode,
            tags=list(tags or []),
            cost_estimate=cost if cost is not None else CostEstimate(),
            blast_radius_hints=BlastHints(writes=writes, deletes=deletes, scope=scope),
            intent=intent,
            summary=summary,
        ),
    )


# --------------------------------------------------------------------------
# Making arbitrary adapter input canonicalisable
# --------------------------------------------------------------------------


def _canonicalisable(value: object, depth: int) -> object:
    """Coerce adapter input into the JSON types ``jcs`` accepts.

    MCP arguments arrive as parsed JSON and need nothing. A coding-agent hook
    or the SDK can hand over a ``Path``, a ``datetime`` or a dataclass. Rather
    than raise -- which would drop the call out of the chain entirely -- those
    become their ``repr``, which is honest about being a description.
    """
    if value is None or isinstance(value, bool | int | float | str):
        return value
    if depth >= _MAX_DEPTH:
        return f"[depth limit: {type(value).__name__}]"
    if isinstance(value, dict):
        return {str(k): _canonicalisable(v, depth + 1) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [_canonicalisable(v, depth + 1) for v in value]
    return repr(value)


#: Key that records what had to be left out. Carries a colon so it cannot
#: collide with an identifier-shaped tool argument.
OMITTED_KEY: Final = "qed:omitted"


def _trim(value: dict[str, object], limit: int) -> dict[str, object]:
    """Reduce ``value`` until it fits in ``limit`` bytes of canonical JSON.

    Three stages, each giving up less than the next:

    1. Shorten the longest string, repeatedly. Usually one oversized field is
       the whole problem and everything else survives intact.
    2. Keep every key, drop every value. Which parameters were present is often
       what a rule matches on and what an approver needs to see.
    3. Drop keys too, and say how many. Reached only by a payload with
       thousands of parameters, where even the key names do not fit.

    The guarantee the caller depends on is that the result is always within the
    limit. An adapter that returned more would have the whole proposal refused
    at the API edge (SPEC §17), and the call would leave no record at all --
    the worst outcome available, worse than a lossy one.
    """
    out: dict[str, object] = dict(value)
    for _ in range(12):
        if len(jcs.dumps(out)) <= limit:
            return out
        longest = _longest_string_path(out)
        if longest is None:
            break
        out = _shorten_at(out, longest)
    if len(jcs.dumps(out)) <= limit:
        return out

    shape: dict[str, object] = {key: f"[trimmed: {type(val).__name__}]" for key, val in out.items()}
    if len(jcs.dumps(shape)) <= limit:
        return shape
    return _keep_what_fits(shape, limit)


def _keep_what_fits(shape: dict[str, object], limit: int) -> dict[str, object]:
    """Keep keys in sorted order while they fit, then record the omission.

    Sorted rather than insertion-ordered so that two adapters handed the same
    parameters produce the same record; the result goes into a hash chain, so
    "the same input gives the same bytes" has to hold.
    """
    total = len(shape)
    # Room for the marker, measured with the longest note it could carry
    # ("N of N omitted") plus one byte for the separating comma.
    reserve = len(jcs.dumps({OMITTED_KEY: _omitted_note(total, 0)})) + 1

    kept: dict[str, object] = {}
    for key in sorted(shape):
        candidate = {**kept, key: shape[key]}
        if len(jcs.dumps(candidate)) + reserve > limit:
            break
        kept = candidate
    kept[OMITTED_KEY] = _omitted_note(total, len(kept))
    return kept


def _omitted_note(total: int, kept: int) -> str:
    return (
        f"{total - kept} of {total} parameters omitted so the record fits the "
        f"{MAX_PARAMS_BYTES // 1024} KB limit; params_hash still covers all of them"
    )


def _longest_string_path(value: object, path: tuple[object, ...] = ()) -> tuple[object, ...] | None:
    """Path to the longest string, or ``None`` when shortening would not help.

    The 64-character floor stops the loop from grinding through a payload made
    of thousands of short strings, where every pass would save nothing; ``_trim``
    falls back to dropping values when that happens.
    """
    best: tuple[object, ...] | None = None
    best_len = 0
    stack: list[tuple[object, tuple[object, ...]]] = [(value, path)]
    while stack:
        current, here = stack.pop()
        if isinstance(current, str):
            if len(current) > best_len:
                best, best_len = here, len(current)
        elif isinstance(current, dict):
            stack.extend((item, (*here, key)) for key, item in current.items())
        elif isinstance(current, list):
            stack.extend((item, (*here, index)) for index, item in enumerate(current))
    return best if best_len > 64 else None


def _shorten_at(value: dict[str, object], path: tuple[object, ...]) -> dict[str, object]:
    """Replace the string at ``path`` with a truncated copy plus a marker."""

    def walk(node: object, rest: tuple[object, ...]) -> object:
        if not rest:
            if isinstance(node, str):
                head = node[:256]
                return f"{head}[trimmed: {len(node)} chars]"
            return f"[trimmed: {type(node).__name__}]"
        key, remainder = rest[0], rest[1:]
        if isinstance(node, dict) and isinstance(key, str):
            return {k: (walk(v, remainder) if k == key else v) for k, v in node.items()}
        if isinstance(node, list) and isinstance(key, int):
            return [walk(v, remainder) if i == key else v for i, v in enumerate(node)]
        return node

    result = walk(value, path)
    return result if isinstance(result, dict) else value
