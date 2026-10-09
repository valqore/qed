"""Invariant §1.4.4: Ed25519 only; no HMAC path exists.

An HMAC-signed chain is worthless to an auditor: verifying it requires the same
secret that produced it, so the party being audited can forge any record, and a
successful verification proves only that somebody holding the secret agreed.
Evidence a third party can check without trusting the party that produced it is
the whole claim of this product, so the absence of an HMAC path is an invariant
rather than a preference, and this is the test that makes it one.

Scope is the kernel and the verifier. Adapter request authentication (SPEC §13)
legitimately uses an HMAC, and so do licence keys; neither signs evidence.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCANNED = sorted(
    [
        *(ROOT / "qed" / "core").rglob("*.py"),
        *(ROOT / "qed" / "infra").rglob("*.py"),
        *(ROOT / "packages" / "qed-verify" / "qed_verify").rglob("*.py"),
    ]
)


@pytest.mark.parametrize("path", SCANNED, ids=lambda p: p.name)
def test_no_hmac_import(path: Path) -> None:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)
            imported.update(f"{node.module}.{a.name}" for a in node.names)
    offenders = {name for name in imported if "hmac" in name.lower()}
    assert not offenders, f"{path.name} imports {sorted(offenders)}"


@pytest.mark.parametrize("path", SCANNED, ids=lambda p: p.name)
def test_no_hmac_call(path: Path) -> None:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    offenders = [
        rendered
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute | ast.Name)
        and "hmac" in (rendered := ast.unparse(node)).lower()
    ]
    assert not offenders, f"{path.name}: {offenders}"


def test_the_signer_protocol_exposes_no_secret_material() -> None:
    """A symmetric path would need a shared secret on this interface."""
    from qed.core.evidence.signing import Signer

    members = {name for name in dir(Signer) if not name.startswith("_")}
    assert members == {"key_id", "public_pem", "sign"}, sorted(members)


def test_signing_refuses_a_non_ed25519_key(tmp_path: Path) -> None:
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
    )

    from qed.infra.keys.file import FileSigner, MissingSigningKey

    path = tmp_path / "rsa.pem"
    path.write_bytes(
        rsa.generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
            Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
        )
    )
    with pytest.raises(MissingSigningKey, match="Ed25519 only"):
        FileSigner.load(path)


def test_there_is_no_development_fallback_key(tmp_path: Path) -> None:
    from qed.infra.keys.file import MissingSigningKey, load_signer

    with pytest.raises(MissingSigningKey, match="qed keys init"):
        load_signer(tmp_path / "empty")
