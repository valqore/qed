"""File-backed Ed25519 keys (SPEC §10.5).

There is no generated-on-the-fly key and no built-in development key. If the
signing key is missing, every caller here raises; `qed serve` will report
``readyz=false`` for the same reason (SPEC §17). A chain signed by a key the
operator did not create is worth nothing to an auditor, so "convenient default"
is the wrong trade here.

``key_id`` is derived from the public key, so the same key always has the same
id and an operator cannot label one key as another.

Public keys are written to ``<dir>/public/`` with ``:`` replaced by ``_`` in the
filename — ``ed25519:ab…`` is not a legal path on Windows.
"""

from __future__ import annotations

import contextlib
import os
import stat
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
    load_pem_public_key,
)

from qed.core.evidence.signing import ALG, b64u_encode, key_id_for
from qed.core.schemas import SigningKeyInfo, utcnow

__all__ = [
    "PRIVATE_KEY_NAME",
    "PUBLIC_DIR_NAME",
    "FileSigner",
    "MissingSigningKey",
    "init_keys",
    "load_public_keys",
    "load_signer",
    "public_key_filename",
]

PRIVATE_KEY_NAME = "evidence-key.pem"
PUBLIC_DIR_NAME = "public"


class MissingSigningKey(RuntimeError):
    """No usable signing key. qed must not run without one."""


def public_key_filename(key_id: str) -> str:
    return f"{key_id.replace(':', '_')}.pem"


class FileSigner:
    """A :class:`qed.core.evidence.signing.Signer` backed by a PEM file."""

    def __init__(self, private_key: Ed25519PrivateKey) -> None:
        self._private = private_key
        self._public = private_key.public_key()
        self._key_id = key_id_for(self._public)

    @property
    def key_id(self) -> str:
        return self._key_id

    @property
    def public_pem(self) -> str:
        return self._public.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self._public

    def sign(self, message: bytes) -> str:
        return b64u_encode(self._private.sign(message))

    def info(self) -> SigningKeyInfo:
        return SigningKeyInfo(
            key_id=self.key_id, public_pem=self.public_pem, alg=ALG, source="file"
        )

    # ------------------------------------------------------------------ files

    @classmethod
    def generate(cls) -> FileSigner:
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def load(cls, path: Path) -> FileSigner:
        if not path.exists():
            raise MissingSigningKey(f"no signing key at {path}; run `qed keys init`")
        key = load_pem_private_key(path.read_bytes(), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise MissingSigningKey(
                f"{path} is a {type(key).__name__}; qed signs evidence with Ed25519 only"
            )
        return cls(key)

    def save_private(self, path: Path, *, overwrite: bool = False) -> None:
        if path.exists() and not overwrite:
            raise FileExistsError(f"{path} already exists; refusing to overwrite a signing key")
        path.parent.mkdir(parents=True, exist_ok=True)
        pem = self._private.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
        path.write_bytes(pem)
        _restrict(path)

    def save_public(self, directory: Path) -> Path:
        directory.mkdir(parents=True, exist_ok=True)
        target = directory / public_key_filename(self.key_id)
        target.write_text(self.public_pem, encoding="utf-8")
        return target


def _restrict(path: Path) -> None:
    """Best-effort 0600. On Windows the POSIX bits are advisory, so this is
    documented in `qed doctor` output rather than relied upon."""
    # Platform dependent; `qed doctor` reports posture rather than assuming it.
    with contextlib.suppress(OSError):
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)


def init_keys(directory: Path, *, overwrite: bool = False) -> SigningKeyInfo:
    """Create the evidence key pair under ``directory``."""
    signer = FileSigner.generate()
    signer.save_private(directory / PRIVATE_KEY_NAME, overwrite=overwrite)
    signer.save_public(directory / PUBLIC_DIR_NAME)
    return signer.info().model_copy(update={"created_at": utcnow()})


def load_signer(directory: Path) -> FileSigner:
    return FileSigner.load(directory / PRIVATE_KEY_NAME)


def load_public_keys(directory: Path) -> dict[str, Ed25519PublicKey]:
    """Map ``key_id`` to public key for every PEM in ``directory``.

    The id is recomputed from the key material, not taken from the filename, so
    a renamed file cannot make a record appear to verify under the wrong key.
    """
    keys: dict[str, Ed25519PublicKey] = {}
    if not directory.is_dir():
        return keys
    for pem in sorted(directory.glob("*.pem")):
        loaded = load_pem_public_key(pem.read_bytes())
        if isinstance(loaded, Ed25519PublicKey):
            keys[key_id_for(loaded)] = loaded
    return keys
