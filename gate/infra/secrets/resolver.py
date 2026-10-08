"""Credential resolution with a TTL cache (SPEC §7.2).

One rule governs this whole module: **a credential may exist in memory and
nowhere else**. Every error path here is written with that in mind — the
exceptions carry the *reference*, never the value, and the reference is
already in the operator's config file.
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field
from pathlib import Path

from gate.core.broker.model import CredentialSpec, Secret

logger = logging.getLogger(__name__)

__all__ = ["CredentialResolver", "SecretNotAvailable", "SecretResolutionError"]

#: How long a resolved credential is reused. Short enough that a rotated
#: secret or a revoked Vault lease takes effect within a minute; long enough
#: that a busy gate is not asking Vault on every single action.
DEFAULT_TTL_SECONDS = 60.0


class SecretResolutionError(RuntimeError):
    """The reference could not be resolved. Carries the ref, never the value."""


class SecretNotAvailable(SecretResolutionError):
    """The source is reachable but holds nothing at that reference."""


@dataclass
class _Entry:
    secret: Secret
    at: float


@dataclass
class CredentialResolver:
    """Resolves `env:`, `file:` and `vault:` references, with a cache.

    ``vault_client`` is injected rather than constructed here so the tests do
    not need a Vault, and so an operator using AppRole versus Kubernetes auth
    configures that once at startup instead of per call.
    """

    ttl_seconds: float = DEFAULT_TTL_SECONDS
    vault_client: object | None = None
    #: Overrides the process environment. Only the tests pass this.
    environ: dict[str, str] | None = None
    _cache: dict[str, _Entry] = field(default_factory=dict, repr=False)

    def resolve(self, spec: CredentialSpec, *, now: float | None = None) -> Secret:
        current = time.monotonic() if now is None else now
        key = f"{spec.source}:{spec.ref}"
        cached = self._cache.get(key)
        if cached is not None and (current - cached.at) < self.ttl_seconds:
            return cached.secret

        if spec.source == "env":
            secret = self._from_env(spec.ref)
        elif spec.source == "file":
            secret = self._from_file(spec.ref)
        else:
            secret = self._from_vault(spec.ref)

        self._cache[key] = _Entry(secret, current)
        return secret

    def forget(self, spec: CredentialSpec | None = None) -> None:
        """Drop cached values, so the next action re-reads the source.

        Called on rotation and on shutdown. Clearing the dict does not scrub
        the strings from memory -- Python gives no way to -- but it does stop
        the gate handing out a credential that was revoked a minute ago.
        """
        if spec is None:
            self._cache.clear()
        else:
            self._cache.pop(f"{spec.source}:{spec.ref}", None)

    # ------------------------------------------------------------- sources

    def _env(self) -> dict[str, str]:
        return self.environ if self.environ is not None else dict(os.environ)

    def _from_env(self, ref: str) -> Secret:
        value = self._env().get(ref)
        if value is None:
            raise SecretNotAvailable(
                f"${ref} is not set, so this upstream has no credential to inject"
            )
        if not value:
            raise SecretNotAvailable(
                f"${ref} is set but empty, which is almost always a deployment "
                "mistake rather than an intentionally empty credential"
            )
        return Secret(value)

    def _from_file(self, ref: str) -> Secret:
        path = Path(ref)
        try:
            raw = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise SecretNotAvailable(f"could not read {ref}: {exc}") from exc
        # A trailing newline is what every `echo secret > file` produces and
        # what every "why is my token invalid" hour is spent on.
        value = raw.strip()
        if not value:
            raise SecretNotAvailable(f"{ref} is empty")
        return Secret(value)

    def _from_vault(self, ref: str) -> Secret:
        """``secret/data/gate/postgres#DATABASE_URL`` -- path, then field."""
        if self.vault_client is None:
            raise SecretResolutionError(
                f"{ref} is a Vault reference but no Vault client is configured. "
                "Install the extra (`pip install valqore-gate[vault]`) and set "
                "`broker.vault` in the config."
            )
        path, _, field_name = ref.partition("#")
        try:
            read = self.vault_client.secrets.kv.v2.read_secret_version  # type: ignore[attr-defined]
            response = read(path=path.removeprefix("secret/data/"))
        except Exception as exc:  # hvac raises a family of unrelated types
            raise SecretResolutionError(f"Vault refused {path}: {exc}") from exc

        data = ((response or {}).get("data") or {}).get("data") or {}
        if field_name:
            if field_name not in data:
                raise SecretNotAvailable(f"Vault has {path} but no field {field_name!r} in it")
            value = data[field_name]
        else:
            if len(data) != 1:
                raise SecretResolutionError(
                    f"{path} holds {len(data)} fields, so the reference has to name "
                    f"one: {path}#<field>"
                )
            value = next(iter(data.values()))
        if not value:
            raise SecretNotAvailable(f"Vault returned an empty value for {ref}")
        return Secret(str(value))
