"""The SDK client and the `@guard` decorator (SPEC §12.4).

Deliberately small. Everything about *deciding* lives in the kernel and is
reached over HTTP; what is here is the proposal shape, the signature, the
retry policy and the decorator. If this file ever needs to know what a rule
is, something has gone wrong.
"""

from __future__ import annotations

import contextlib
import functools
import json
import os
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any, Final, Literal, TypeVar

import httpx

from qed.adapters.common import AdapterInfo, build_proposal
from qed.adapters.signing import (
    HEADER_ADAPTER,
    HEADER_NONCE,
    HEADER_SIGNATURE,
    HEADER_TIMESTAMP,
    canonical_string,
    sign,
)
from qed.core.evidence.hashing import principal_hash
from qed.core.schemas import (
    ActionKind,
    Enforcement,
    Environment,
    Mode,
    Scope,
    rfc3339_ms,
    utcnow,
)

__all__ = [
    "DEFAULT_TIMEOUT",
    "Qed",
    "QedApprovalPending",
    "QedBlocked",
    "QedError",
    "QedUnavailable",
    "Verdict",
    "guard",
]

#: Seconds. Short on purpose: this call sits in front of the application's own
#: work, so a QED that is slow has to fail rather than make every request slow.
DEFAULT_TIMEOUT: Final = 5.0

#: How long `wait` polls an approval by default. SPEC §12.4's example uses 600.
DEFAULT_WAIT: Final = 600.0

FailMode = Literal["closed", "open"]

T = TypeVar("T")


class QedError(Exception):
    """Base class, so one `except` can cover the SDK."""


class QedUnavailable(QedError):
    """QED could not be reached or could not answer.

    Separate from a refusal on purpose. "The policy says no" and "I could not
    find out what the policy says" are different facts, and an application
    that treats them the same will eventually treat an outage as permission.
    """


@dataclass(frozen=True)
class Verdict:
    """What the kernel answered. A thin view over the JSON, not a re-model.

    Re-modelling the verdict here would mean a second schema to keep in step
    with ``qed.core.schemas``, and the two would drift the first time a field
    was added. The raw document is kept so that anything not surfaced as an
    attribute is still reachable.
    """

    decision: str
    proposal_id: str
    raw: dict[str, Any] = field(default_factory=dict)
    evidence_seq: list[int] = field(default_factory=list)

    @property
    def allowed(self) -> bool:
        return self.decision == "ALLOW"

    @property
    def approval_id(self) -> str | None:
        value = self.raw.get("approval_id")
        return str(value) if value else None

    @property
    def rule_ids(self) -> list[str]:
        hits = self.raw.get("hits")
        if not isinstance(hits, list):
            return []
        return [str(hit.get("rule_id")) for hit in hits if isinstance(hit, dict)]

    @property
    def blast_radius(self) -> int:
        value = self.raw.get("blast_radius")
        return int(value) if isinstance(value, int | float) else 0

    def explain(self) -> str:
        """One line for a log or an exception message."""
        rules = ", ".join(self.rule_ids) or "no rule"
        first = ""
        hits = self.raw.get("hits")
        if isinstance(hits, list) and hits and isinstance(hits[0], dict):
            first = f": {hits[0].get('message', '')}"
            fix = hits[0].get("fix")
            if fix:
                first += f" Fix: {fix}"
        return f"[qed {self.decision}] {rules}{first}"


class QedBlocked(QedError):
    """The policy refused the action. It did not run."""

    def __init__(self, verdict: Verdict) -> None:
        self.verdict = verdict
        super().__init__(verdict.explain())


class QedApprovalPending(QedError):
    """A person has to agree first. The action did not run.

    ``verdict.approval_id`` names the open request; :meth:`Qed.wait` polls it.
    """

    def __init__(self, verdict: Verdict) -> None:
        self.verdict = verdict
        super().__init__(verdict.explain())


@dataclass
class Qed:
    """A client for one QED instance.

    ``adapter_secret`` is the shared secret the instance registered this
    adapter with (SPEC §12.6). It is not an evidence signing key and cannot
    sign a record; the worst a leaked one does is let somebody submit
    proposals as this adapter, which the chain then attributes to it.
    """

    url: str
    adapter_id: str
    adapter_secret: str
    environment: Environment = "dev"
    #: Who the actions are for. One of this and `mandate_id` is required: with
    #: neither, every verdict is a synthetic AG-IDN-007 identity BLOCK reached
    #: before any rule runs, which looks like a policy that hates you.
    human: str | None = None
    issuer: str = "local"
    mandate_id: str | None = None
    token_jti: str = "qed-sdk"
    #: Advisory by default (ADR-001 class A): whoever can edit the code can
    #: delete the decorator. Say `enforcing` only when the function's
    #: credential comes from the broker.
    enforcement: Enforcement = Enforcement.advisory
    #: Closed by default, unlike the coding-agent hook. An application has no
    #: human watching, so a QED it cannot reach must stop the action.
    fail_mode: FailMode = "closed"
    timeout: float = DEFAULT_TIMEOUT
    client: httpx.Client | None = None
    tags: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.url:
            raise QedError(
                "no QED url. Set QED_URL, or pass url=..., or run `qed serve` and point "
                "at it. The SDK is a client: it does not decide locally, because that "
                "would mean an evidence signing key in every application process."
            )
        self.url = self.url.rstrip("/")
        if self.human is None and self.mandate_id is None:
            raise QedError(
                "give human= or mandate_id=. With neither, every proposal has no "
                "principal and no delegated authority, the engine answers a synthetic "
                "AG-IDN-007 identity BLOCK before any rule is evaluated, and every call "
                "you make looks refused for a reason no rule explains."
            )
        if not self.adapter_id or not self.adapter_secret:
            raise QedError(
                "give adapter_id= and adapter_secret=, or set QED_ADAPTER_ID and "
                "QED_ADAPTER_SECRET. Register the adapter on the instance first "
                "(SPEC §12.6); an unknown adapter is refused with AG-IDN-005."
            )

    # ------------------------------------------------------------------ setup

    @classmethod
    def from_env(cls, **overrides: Any) -> Qed:
        """Read the environment (SPEC §12.4). Explicit arguments win.

        ``QED_URL`` ``QED_ADAPTER_ID`` ``QED_ADAPTER_SECRET`` ``QED_HUMAN``
        ``QED_ENV`` ``QED_MANDATE_ID``.
        """
        settings: dict[str, Any] = {
            "url": os.environ.get("QED_URL", ""),
            "adapter_id": os.environ.get("QED_ADAPTER_ID", ""),
            "adapter_secret": os.environ.get("QED_ADAPTER_SECRET", ""),
            "human": os.environ.get("QED_HUMAN") or None,
            "mandate_id": os.environ.get("QED_MANDATE_ID") or None,
        }
        environment = os.environ.get("QED_ENV")
        if environment in {"dev", "staging", "prod"}:
            settings["environment"] = environment
        settings.update(overrides)
        return cls(**settings)

    @property
    def _http(self) -> httpx.Client:
        if self.client is None:
            self.client = httpx.Client(timeout=self.timeout)
        return self.client

    def close(self) -> None:
        if self.client is not None:
            self.client.close()
            self.client = None

    def __enter__(self) -> Qed:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    @property
    def _principal_hash(self) -> str | None:
        return None if self.human is None else principal_hash(self.human, issuer=self.issuer)

    # ------------------------------------------------------------- the request

    def _post(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        raw = json.dumps(body).encode("utf-8")
        timestamp = rfc3339_ms(utcnow())
        headers = {
            "content-type": "application/json",
            HEADER_ADAPTER: self.adapter_id,
            HEADER_TIMESTAMP: timestamp,
            HEADER_NONCE: "",
            HEADER_SIGNATURE: sign(
                self.adapter_secret,
                canonical_string(method="POST", path=path, timestamp=timestamp, nonce="", body=raw),
            ),
        }
        try:
            response = self._http.post(f"{self.url}{path}", content=raw, headers=headers)
        except httpx.HTTPError as exc:
            raise QedUnavailable(f"could not reach QED at {self.url}: {exc}") from exc
        return self._parse(response, path)

    def _get(self, path: str) -> dict[str, Any]:
        timestamp = rfc3339_ms(utcnow())
        headers = {
            HEADER_ADAPTER: self.adapter_id,
            HEADER_TIMESTAMP: timestamp,
            HEADER_NONCE: "",
            HEADER_SIGNATURE: sign(
                self.adapter_secret,
                canonical_string(method="GET", path=path, timestamp=timestamp, nonce="", body=b""),
            ),
        }
        try:
            response = self._http.get(f"{self.url}{path}", headers=headers)
        except httpx.HTTPError as exc:
            raise QedUnavailable(f"could not reach QED at {self.url}: {exc}") from exc
        return self._parse(response, path)

    def _parse(self, response: httpx.Response, path: str) -> dict[str, Any]:
        try:
            document = response.json()
        except ValueError:
            document = {}
        if response.status_code >= 400:
            # RFC 9457 problem+json. `detail` is written for a person, so it is
            # what the exception carries rather than a status code.
            detail = document.get("detail") or document.get("title") or response.text[:200]
            raise QedUnavailable(f"QED answered {response.status_code} for {path}: {detail}")
        return document if isinstance(document, dict) else {}

    # -------------------------------------------------------------- the verbs

    def propose(
        self,
        *,
        kind: str = "custom",
        name: str,
        target: str,
        params: object = None,
        intent: str | None = None,
        summary: str = "",
        writes: bool = False,
        deletes: bool = False,
        scope: Scope = "single_resource",
        method: str | None = None,
    ) -> Verdict:
        """Ask whether this action may happen. Raises nothing on a refusal.

        Returns the verdict either way, so a caller who wants to branch rather
        than catch can. :func:`guard` is the catching version.
        """
        proposal = build_proposal(
            kind=ActionKind(kind),
            name=name,
            target=target,
            params=params,
            adapter=AdapterInfo(f"qed-sdk/{_version()}", self.adapter_id),
            environment=self.environment,
            enforcement=self.enforcement,
            # The service's own mode is authoritative and the API applies it;
            # this is what the adapter believes, which is what SPEC §3.1 asks
            # for ("mode: service-level, as seen by adapter").
            mode=Mode.enforce,
            token_jti=self.token_jti,
            human_hash=self._principal_hash,
            mandate_id=self.mandate_id,
            client_fingerprint=None if self.human is None else f"sdk:{self.issuer}",
            summary=summary or f"{name} on {target}",
            intent=intent,
            writes=writes,
            deletes=deletes,
            scope=scope,
            tags=list(self.tags),
            method=method,
        )
        document = self._post("/v1/proposals", json.loads(proposal.model_dump_json()))
        verdict = document.get("verdict") or {}
        return Verdict(
            decision=str(verdict.get("decision", "")),
            proposal_id=proposal.id,
            raw=verdict if isinstance(verdict, dict) else {},
            evidence_seq=[int(s) for s in document.get("evidence_seq", []) if isinstance(s, int)],
        )

    def report(
        self,
        proposal_id: str,
        *,
        status: str,
        error: str | None = None,
        http_status: int | None = None,
        duration_ms: float | None = None,
    ) -> None:
        """Say what happened when the action ran (SPEC §13).

        Never raises. A report is the last thing to happen in a `guard`ed
        call, and an exception here would replace the application's own result
        -- or its own exception -- with a reporting failure, which is the
        wrong thing to show anybody.
        """
        body: dict[str, Any] = {"status": status}
        if error is not None:
            body["error"] = error
        if http_status is not None:
            body["http_status"] = http_status
        if duration_ms is not None:
            body["duration_ms"] = round(duration_ms, 3)
        # Deliberately suppressed, and the only place in the SDK that does.
        # The action already happened; losing the report loses a row in the
        # chain, and raising here would replace the application's own result --
        # or its own exception -- with a reporting failure.
        with contextlib.suppress(QedError):
            self._post(f"/v1/proposals/{proposal_id}/result", body)

    def wait(
        self,
        approval_id: str,
        *,
        timeout: float = DEFAULT_WAIT,
        interval: float = 2.0,
    ) -> str:
        """Poll an approval until somebody decides it (SPEC §12.4).

        Returns the status: ``approved``, ``denied`` or ``expired``. Raises
        :class:`QedUnavailable` on a timeout, because "nobody answered in ten
        minutes" is not an approval and must not be mistaken for one by a
        caller checking truthiness.
        """
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            document = self._get(f"/v1/approvals/{approval_id}")
            status = str(document.get("status", ""))
            if status in {"approved", "denied", "expired"}:
                return status
            time.sleep(interval)
        raise QedUnavailable(
            f"approval {approval_id} was still pending after {timeout:.0f}s. Nobody "
            "answering is not the same as somebody approving."
        )

    # ----------------------------------------------------------------- helpers

    def check(self, **kwargs: Any) -> Verdict:
        """:meth:`propose`, but raises on anything other than ALLOW.

        What :func:`guard` uses, and what to call directly when the action is
        not one function.
        """
        try:
            verdict = self.propose(**kwargs)
        except QedUnavailable:
            if self.fail_mode == "closed":
                raise
            return Verdict(decision="ALLOW", proposal_id="", raw={"ungated": True})
        if verdict.decision == "BLOCK":
            raise QedBlocked(verdict)
        if verdict.decision == "REQUIRE_APPROVAL":
            raise QedApprovalPending(verdict)
        return verdict


def _version() -> str:
    from qed import __version__

    return __version__


# --------------------------------------------------------------------------
# The decorator
# --------------------------------------------------------------------------


def guard(
    qed: Qed,
    *,
    kind: str = "custom",
    target: str | Callable[..., str],
    name: str | None = None,
    summary: Callable[..., str] | str | None = None,
    intent: Callable[..., str] | str | None = None,
    params: Callable[..., object] | None = None,
    writes: bool = True,
    deletes: bool = False,
    scope: Scope = "single_resource",
) -> Callable[[Callable[..., T]], Callable[..., T]]:
    """Govern one function (SPEC §12.4).

    ``target``, ``summary``, ``intent`` and ``params`` may each be a callable
    taking the wrapped function's own arguments, so the proposal can describe
    the specific call rather than the function in general: an approver needs
    to know *which* account is being deleted.

    ``writes=True`` by default. A function worth wrapping is a function that
    changes something, and a hint that under-reports the damage is worse than
    one that over-reports it: the first routes a destructive call past the
    blast-radius score, the second asks a person about a harmless one.

    The wrapped function's own exception is never replaced. A failure is
    reported and re-raised.
    """

    def decorate(function: Callable[..., T]) -> Callable[..., T]:
        action_name = name or f"{function.__module__}.{function.__qualname__}"

        @functools.wraps(function)
        def wrapper(*args: Any, **kwargs: Any) -> T:
            verdict = qed.check(
                kind=kind,
                name=action_name,
                target=_resolve(target, args, kwargs),
                params=params(*args, **kwargs)
                if callable(params)
                else _default_params(args, kwargs),
                summary=_resolve(summary, args, kwargs) if summary is not None else "",
                intent=_resolve(intent, args, kwargs) if intent is not None else None,
                writes=writes,
                deletes=deletes,
                scope=scope,
            )
            started = time.monotonic()
            try:
                result = function(*args, **kwargs)
            except Exception as exc:
                qed.report(
                    verdict.proposal_id,
                    status="error",
                    error=f"{type(exc).__name__}: {exc}",
                    duration_ms=(time.monotonic() - started) * 1000,
                )
                # Re-raised untouched. The application's failure is the
                # application's to handle; QED's job was to record it.
                raise
            qed.report(
                verdict.proposal_id,
                status="ok",
                duration_ms=(time.monotonic() - started) * 1000,
            )
            return result

        return wrapper

    return decorate


def _resolve(value: Any, args: tuple[Any, ...], kwargs: dict[str, Any]) -> Any:
    return value(*args, **kwargs) if callable(value) else value


def _default_params(args: tuple[Any, ...], kwargs: Mapping[str, Any]) -> dict[str, Any]:
    """The call's own arguments, as the engine will see them.

    Positional arguments are named ``arg0``, ``arg1`` rather than dropped: a
    rule matching ``params_redacted.arg0`` is ugly, and a parameter the engine
    never saw is worse. ``adapters/common.bounded_params`` does the trimming
    and ``core/evidence/masking`` the redaction, both after the engine has
    looked -- which is why nothing is masked here (see that module's note).
    """
    out: dict[str, Any] = {f"arg{index}": value for index, value in enumerate(args)}
    out.update(kwargs)
    return out
