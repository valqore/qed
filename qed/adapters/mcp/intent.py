"""What an MCP tool call is about to do, from the call alone.

The MCP protocol gives a proxy a tool name and a JSON argument object. Neither
is typed and neither says "this writes" or "this deletes", so the adapter has to
derive the three hints SPEC §3.1 asks it for -- ``writes``, ``deletes`` and
``scope`` -- before the kernel can score the call.

Why this module exists rather than a port of Valqore's ``mcp/gateway.py``
--------------------------------------------------------------------------

SPEC Appendix B says to port ``mcp/gateway.py``. Its blast-radius function reads:

    verb_blast = _blast_from_tool_name(tool)
    try:
        from valqore.agents.action_intent import normalize
        na = normalize({"cloud_api": {...}})
        nb, nct = na.blast_radius, na.change_type
    except Exception:
        nb, nct = "low", "unknown"

``action_intent`` imports ``valqore.codegen.validate`` at module level, which
pulls in the IaC parser and the rule engine. The Phase-0 inventory measured
import isolation with ``sys.modules``, which only sees top-level imports of
modules that were already loaded, so that chain did not show up. Ported as
written into a repo that has no ``valqore`` package, the import raises, the bare
``except`` swallows it, and the function returns ``low`` for everything. Nothing
errors. Nothing logs. Blast radius quietly degrades to matching the tool name,
and a tool called ``execute_sql`` carrying ``DROP TABLE orders`` scores low and
stops routing to approval. In shadow mode nobody would notice, and shadow is the
default every installation starts in.

So the useful half -- the verb tables, which are good and were earned on tools
agents really call -- is written out here, with no import that can fail and no
fallback to pretend it did not. ``tests/adapters/test_import_boundary.py`` holds
the line: this module may import nothing outside a fixed allowlist.

The other half of Valqore's function, mapping "sensitive" to "high", is left
out on purpose. ``qed/core/policy/blast_radius.py`` already scores the identity,
secrets and audit surface, it already reads ``params_redacted``, and it is inside
the policy hash where an auditor can replay it. Scoring it here as well would
count the same signal twice, in a place no rule can see.

What this module does read
--------------------------

The tool name *and* the argument values. Reading only the name is the specific
trap above: ``execute_sql`` is a mild verb, and ``DROP TABLE orders`` is in the
arguments. Both are deterministic text the proxy already has.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

import regex

from qed.core.schemas import Scope

__all__ = ["INTENT_TABLE_VERSION", "ToolIntent", "classify"]

INTENT_TABLE_VERSION = "1.0"

#: Verbs that destroy or detach something. Ported from Valqore's
#: ``_HIGH_BLAST_VERBS``, which was built from the tools agents actually drive
#: (kubectl, Helm, Argo, Istio, cloud CLIs) rather than from CRUD theory.
_DESTRUCTIVE: Final[frozenset[str]] = frozenset(
    {
        "delete",
        "deprovision",
        "destroy",
        "drain",
        "drop",
        "evict",
        "forcedelete",
        "kill",
        "prune",
        "purge",
        "remove",
        "revoke",
        "rm",
        "rmdir",
        "rollback",
        "teardown",
        "terminate",
        "truncate",
        "undo",
        "uninstall",
        "unlink",
        "wipe",
    }
)

#: Verbs that change state without destroying it (Valqore ``_MEDIUM_BLAST_VERBS``).
_MUTATING: Final[frozenset[str]] = frozenset(
    {
        "abort",
        "add",
        "annotate",
        "apply",
        "attach",
        "authorize",
        "cordon",
        "create",
        "deploy",
        "edit",
        "exec",
        "execute",
        "grant",
        "insert",
        "install",
        "label",
        "merge",
        "modify",
        "move",
        "patch",
        "post",
        "promote",
        "publish",
        "put",
        "rename",
        "replace",
        "restart",
        "resume",
        "rollout",
        "run",
        "scale",
        "send",
        "set",
        "suspend",
        "sync",
        "uncordon",
        "update",
        "upgrade",
        "upload",
        "write",
    }
)

#: Verbs that only read. Listed rather than inferred, so that a tool named
#: ``get_or_create`` is classified by its strongest verb and an unknown verb
#: stays unknown instead of being guessed as read-only.
_READING: Final[frozenset[str]] = frozenset(
    {
        "check",
        "describe",
        "diff",
        "download",
        "explain",
        "fetch",
        "find",
        "get",
        "head",
        "inspect",
        "list",
        "ls",
        "plan",
        "query",
        "read",
        "search",
        "show",
        "stat",
        "status",
        "tail",
        "validate",
        "view",
        "watch",
    }
)

_TOKEN_SPLIT: Final = regex.compile(r"[^a-z0-9]+")

#: Destructive statements inside argument *values*: SQL, shell and API verbs
#: that the tool name does not have to mention. ``(?:\b|_)`` rather than ``\b``
#: because the surrounding text is as likely to be ``drop_table`` as ``DROP TABLE``.
_DESTRUCTIVE_IN_ARGS: Final = regex.compile(
    r"""(?ix)
      (?:\b|_)(?: drop | truncate | delete | destroy | terminate | purge | wipe
                | revoke | deprovision | uninstall )(?=\b|_)
    | \brm\s+-[a-z]*[rf]                  # rm -rf, rm -fr, rm -r
    | \bforce[-_\ ]?push\b                # "force push", "force-push"
    | \bpush\b[^\n]{0,60}--force          # "git push --force", "push -u o m --force"
    | \bgit\b[^\n]{0,60}\breset\s+--hard  # discards work irreversibly
    """
)

#: Mutating statements inside argument values.
_MUTATING_IN_ARGS: Final = regex.compile(
    r"(?i)(?:\b|_)(?:insert\s+into|update|alter|create|grant|upsert|merge\s+into|"
    r"replace\s+into)(?=\b|_)"
)

#: Argument *values* that aim an action at everything rather than at one thing.
#: Matched per value rather than against the flattened text on purpose: a bare
#: ``\*`` anywhere in a haystack also matches ``SELECT * FROM orders``, which is
#: one query against one table, and escalating its scope would be wrong.
_WILDCARD_VALUE: Final = regex.compile(
    r"""(?ix)
      ^\s*[*%]\s*$              # the whole value is a wildcard
    | ^--all$                   # the CLI flag, passed as a value
    | [*%]$                     # a trailing glob: prod-*, orders_%
    | /\*                       # a path or ARN glob: buckets/*, repos/*/issues
    | \*/                       # a leading path glob: */secrets
    | ^0\.0\.0\.0/0$            # open to every IPv4 address
    | ^::/0$                    # open to every IPv6 address
    | ^arn:[^:]*:[^:]*:[^:]*:[^:]*:\*
    """
)

#: Argument names that select many resources at once when they carry a value.
_BULK_SELECTOR_KEYS: Final[frozenset[str]] = frozenset(
    {
        "all",
        "all_namespaces",
        "allnamespaces",
        "filter",
        "force",
        "label_selector",
        "labelselector",
        "prefix",
        "recursive",
        "selector",
        "where",
    }
)

#: Argument names whose value names the account or the whole estate.
_ACCOUNT_SCOPE_KEYS: Final[frozenset[str]] = frozenset(
    {"account", "account_id", "organization", "org", "project", "subscription", "tenant"}
)

#: How much argument text is scanned. Same budget and the same reason as
#: ``qed/core/policy/blast_radius.py``: a 16 KB body must not make hint
#: derivation the slowest part of proxying a call.
_SCAN_LIMIT: Final = 4096

#: More than this many resources named in one list argument reads as bulk.
_MULTI_RESOURCE_ITEMS: Final = 2


@dataclass(frozen=True)
class ToolIntent:
    """The three SPEC §3.1 hints, plus the reasons, for one tool call.

    ``reasons`` is for the proposal summary and for ``qed mcp --explain``. It is
    not hashed and no rule reads it; the hints are the contract.
    """

    writes: bool
    deletes: bool
    scope: Scope
    #: ``read`` | ``create`` | ``update`` | ``delete`` | ``unknown``.
    change_type: str
    reasons: tuple[str, ...]

    @property
    def read_only(self) -> bool:
        return not self.writes and not self.deletes


def classify(tool: str, arguments: object) -> ToolIntent:
    """Derive the hints for one ``tools/call``. Pure; no imports, no I/O.

    ``tool`` may be either the bare tool name or ``"<server>.<tool>"``; the
    server prefix is tokenised along with the rest, which is harmless because
    server names are nouns.
    """
    tokens = _tokens(tool)
    text = _argument_text(arguments)
    reasons: list[str] = []

    name_destructive = bool(tokens & _DESTRUCTIVE)
    name_mutating = bool(tokens & _MUTATING)
    args_destructive = bool(text) and bool(_DESTRUCTIVE_IN_ARGS.search(text))
    args_mutating = bool(text) and bool(_MUTATING_IN_ARGS.search(text))

    if name_destructive:
        reasons.append(f"destructive verb in tool name ({_first(tokens & _DESTRUCTIVE)})")
    if args_destructive:
        reasons.append("destructive statement in arguments")
    if name_mutating and not name_destructive:
        reasons.append(f"mutating verb in tool name ({_first(tokens & _MUTATING)})")
    if args_mutating and not args_destructive:
        reasons.append("mutating statement in arguments")

    deletes = name_destructive or args_destructive
    writes = deletes or name_mutating or args_mutating

    if not writes:
        if tokens & _READING:
            reasons.append(f"read-only verb in tool name ({_first(tokens & _READING)})")
            change_type = "read"
        else:
            # No verb this module knows. Saying "read" here would be a guess in
            # the agent's favour; the hints stay false and the kernel's default
            # verdict decides, which is the behaviour an operator configured.
            reasons.append("no known verb in tool name or arguments")
            change_type = "unknown"
    elif deletes:
        change_type = "delete"
    elif _is_create(tokens, text):
        change_type = "create"
    else:
        change_type = "update"

    scope = _scope(arguments, reasons)
    return ToolIntent(
        writes=writes,
        deletes=deletes,
        scope=scope,
        change_type=change_type,
        reasons=tuple(reasons),
    )


# --------------------------------------------------------------------------
# Internals
# --------------------------------------------------------------------------


def _tokens(tool: str) -> frozenset[str]:
    return frozenset(t for t in _TOKEN_SPLIT.split((tool or "").lower()) if t)


def _first(tokens: frozenset[str]) -> str:
    return sorted(tokens)[0]


def _is_create(tokens: frozenset[str], text: str) -> bool:
    if {"create", "add", "insert", "upload", "publish", "install"} & tokens:
        return True
    return bool(text) and bool(regex.search(r"(?i)\b(insert\s+into|create\s+\w+)\b", text))


def _argument_text(arguments: object) -> str:
    """Flatten argument keys and string values into one bounded haystack.

    Keys are included because ``{"force": true, "selector": "app=*"}`` says what
    the call does through its key names as much as its values.
    """
    if arguments is None:
        return ""
    pieces: list[str] = []
    budget = _SCAN_LIMIT

    def walk(value: object, depth: int) -> None:
        nonlocal budget
        if budget <= 0 or depth > 6:
            return
        if isinstance(value, str):
            chunk = value[:budget]
            pieces.append(chunk)
            budget -= len(chunk)
        elif isinstance(value, bool | int | float):
            pieces.append(str(value))
        elif isinstance(value, dict):
            for key, item in value.items():
                walk(str(key), depth + 1)
                walk(item, depth + 1)
        elif isinstance(value, list | tuple):
            for item in value:
                walk(item, depth + 1)

    walk(arguments, 0)
    return " ".join(pieces)


def _scope(arguments: object, reasons: list[str]) -> Scope:
    """How many things this call aims at, from the shape of its arguments.

    Deliberately conservative in both directions. It never returns ``global``:
    a proxy cannot tell from one JSON object that a call covers an entire
    estate, and a hint that claims it would push every wildcard call straight
    into ``AG-BLR-001``'s CRITICAL block. ``account`` is the ceiling, and a
    real global scope is for the operator's own policy or a later adapter that
    actually knows the upstream's topology.
    """
    if not isinstance(arguments, dict) or not arguments:
        return "single_resource"

    lowered = {str(k).lower(): v for k, v in arguments.items()}

    for key in _ACCOUNT_SCOPE_KEYS & lowered.keys():
        if _truthy(lowered[key]):
            reasons.append(f"argument '{key}' selects an account-level target")
            return "account"

    for key in _BULK_SELECTOR_KEYS & lowered.keys():
        if _truthy(lowered[key]):
            reasons.append(f"argument '{key}' selects more than one resource")
            return "multi_resource"

    for key, value in lowered.items():
        if isinstance(value, list) and len(value) >= _MULTI_RESOURCE_ITEMS:
            reasons.append(f"argument '{key}' names {len(value)} resources")
            return "multi_resource"

    wildcard = _wildcard_argument(arguments)
    if wildcard is not None:
        reasons.append(f"argument '{wildcard}' is a wildcard")
        return "multi_resource"

    return "single_resource"


def _wildcard_argument(arguments: object, path: str = "") -> str | None:
    """Name of the first argument whose value is a wildcard, or ``None``."""
    if isinstance(arguments, str):
        return path if _WILDCARD_VALUE.search(arguments) else None
    if isinstance(arguments, dict):
        for key, value in arguments.items():
            found = _wildcard_argument(value, f"{path}.{key}" if path else str(key))
            if found is not None:
                return found
        return None
    if isinstance(arguments, list | tuple):
        for index, value in enumerate(arguments):
            found = _wildcard_argument(value, f"{path}[{index}]")
            if found is not None:
                return found
    return None


def _truthy(value: object) -> bool:
    """A selector counts only when it carries something.

    ``{"all": false}`` and ``{"selector": ""}`` are the caller saying *no*, and
    treating either as a bulk selector would escalate every call that merely
    has the key present.
    """
    if value is None or value is False:
        return False
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, dict | list | tuple):
        return bool(value)
    return True
