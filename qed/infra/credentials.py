"""Where the CLI keeps the one long-lived secret it holds (SPEC §6.3).

A refresh token is a credential: anyone who reads it can mint access tokens as
that person until it is revoked. So it goes to the OS keychain when there is
one, and to a 0600 file with a warning when there is not — which is the common
case on a headless Linux box, where `keyring` finds no backend.

Two things it is deliberately **not** stored beside:

* the evidence directory, because a chain and the credentials that can write to
  it should not be copied together by accident, and
* the evidence itself, because a chain that held credentials would be a chain
  nobody could safely hand to an auditor.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

__all__ = ["CredentialStore", "StoredLogin"]

SERVICE = "valqore-qed"
FILE_NAME = "credentials.json"


@dataclass(frozen=True)
class StoredLogin:
    issuer: str
    client_id: str
    refresh_token: str
    subject: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "issuer": self.issuer,
            "client_id": self.client_id,
            "refresh_token": self.refresh_token,
            "subject": self.subject,
        }


class CredentialStore:
    """Keychain when available, 0600 file when not.

    ``directory`` is only used by the file fallback. It defaults to the user's
    config directory rather than QED directory for the reason in the
    module docstring.
    """

    def __init__(self, directory: Path | None = None, *, use_keyring: bool = True) -> None:
        self.directory = directory or _default_directory()
        self.use_keyring = use_keyring

    # ------------------------------------------------------------- keychain

    def _keyring(self) -> Any | None:
        if not self.use_keyring:
            return None
        try:
            import keyring
            from keyring.errors import NoKeyringError
        except ImportError:  # pragma: no cover - keyring is a declared dependency
            return None
        try:
            backend = keyring.get_keyring()
        except Exception:  # pragma: no cover - a broken backend is a missing one
            return None
        name = type(backend).__name__
        if "fail" in name.lower() or isinstance(backend, type(None)):
            return None
        # `keyring` only raises NoKeyringError on use, not on lookup, so the
        # probe below is what actually tells us whether this box has one.
        try:
            keyring.get_password(SERVICE, "__probe__")
        except NoKeyringError:
            return None
        except Exception:  # pragma: no cover - backend present but unhappy
            return None
        return keyring

    # ----------------------------------------------------------------- file

    def _path(self) -> Path:
        return self.directory / FILE_NAME

    def _read_file(self) -> dict[str, Any]:
        path = self._path()
        if not path.exists():
            return {}
        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
        return loaded if isinstance(loaded, dict) else {}

    def _write_file(self, data: dict[str, Any]) -> None:
        path = self._path()
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(".tmp")
        temporary.write_text(json.dumps(data, indent=2), encoding="utf-8")
        _restrict(temporary)
        temporary.replace(path)
        logger.warning(
            "no OS keychain is available, so the refresh token is in %s with "
            "0600 permissions. Anyone who can read that file can act as you "
            "until the token is revoked.",
            path,
        )

    # ------------------------------------------------------------------ api

    def save(self, login: StoredLogin) -> None:
        store = self._keyring()
        if store is not None:
            store.set_password(SERVICE, login.issuer, json.dumps(login.as_dict()))
            return
        data = self._read_file()
        data[login.issuer] = login.as_dict()
        self._write_file(data)

    def load(self, issuer: str) -> StoredLogin | None:
        store = self._keyring()
        if store is not None:
            raw = store.get_password(SERVICE, issuer)
            if raw:
                return _from_dict(json.loads(raw))
            return None
        entry = self._read_file().get(issuer)
        return _from_dict(entry) if isinstance(entry, dict) else None

    def forget(self, issuer: str) -> bool:
        store = self._keyring()
        if store is not None:
            try:
                store.delete_password(SERVICE, issuer)
                return True
            except Exception:
                return False
        data = self._read_file()
        if issuer not in data:
            return False
        del data[issuer]
        self._write_file(data)
        return True

    @property
    def backend(self) -> str:
        """``keychain`` or ``file``. Reported by `qed login` so the person
        knows which one holds their credential."""
        return "keychain" if self._keyring() is not None else "file"


def _from_dict(data: dict[str, Any]) -> StoredLogin | None:
    try:
        return StoredLogin(
            issuer=str(data["issuer"]),
            client_id=str(data["client_id"]),
            refresh_token=str(data["refresh_token"]),
            subject=data.get("subject"),
        )
    except (KeyError, TypeError):
        return None


def _default_directory() -> Path:
    override = os.environ.get("GATE_CREDENTIALS_DIR")
    if override:
        return Path(override)
    if os.name == "nt":
        base = os.environ.get("APPDATA") or str(Path.home())
        return Path(base) / "valqore-qed"
    xdg = os.environ.get("XDG_CONFIG_HOME")
    return Path(xdg or (Path.home() / ".config")) / "valqore-qed"


def _restrict(path: Path) -> None:
    # Windows and some mounts carry no POSIX mode. `qed doctor` is what
    # reports the resulting posture; failing the login over it would be worse.
    with contextlib.suppress(OSError):
        path.chmod(0o600)
