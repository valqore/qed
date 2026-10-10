"""Signed control catalogues, and the air-gap import (SPEC §11).

Week 8 shipped ten catalogues inside the package, which is the honest default:
the thing an auditor reads was built and reviewed in the open repository they
can check. This module is for the other case -- a catalogue somebody else
maintains, arriving as a file.

The whole module exists to make one question answerable: **who vouches for
these control titles?** A catalogue decides what `qed packs list` reports and
what an OSCAL finding's `control-label` says, so an unsigned catalogue dropped
into a directory is a way to put words in front of an auditor with nobody
behind them. So:

* a bundle is signed with a **pack key**, which is not the evidence key. The
  evidence key says what this instance did; a pack key says what a publisher
  published. One key doing both would mean an instance could sign its own
  catalogue and the signature would prove nothing about its provenance;
* the signature covers everything except itself, `key_id` included, so a
  bundle cannot be relabelled as signed by a different key;
* an import is **recorded in the chain** as an `admin_action`, because it
  changes what later exports claim and "the catalogue said so" has to be
  traceable to a moment and a key;
* importing **unsigned** is possible and loud: it takes a flag, it is recorded
  as unsigned, and `policy_loaded` carries `unsigned: true` from then on
  (SPEC §11). Refusing outright would just push people to edit the installed
  files by hand, where nothing would record it at all;
* a bundle older than the one already installed is **refused**, because
  serving an old bundle is how you take a control mapping away from somebody
  without them noticing.

Nothing here reaches the network. `qed packs import FILE` reads a file, which
is the air-gap case and also the only case week 9 implements; the `remote.packs
url` fetch is the same verification with a download in front of it.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Final

import yaml
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from qed.compliance.loader import canonical_framework
from qed.compliance.packs import Pack
from qed.core.evidence.signing import ALG, key_id_for, verify_signature
from qed.core.jcs import canonicalize, sha256_hex
from qed.core.schemas import rfc3339_ms, utcnow

__all__ = [
    "BUNDLE_FORMAT",
    "Bundle",
    "BundleRejected",
    "bundle_payload",
    "installed_dir",
    "load_bundle_file",
    "read_installed",
    "sign_bundle",
    "would_break",
    "write_installed",
]

#: The envelope's own version, in the file. A format that cannot say which
#: version it is cannot be changed later without guessing.
BUNDLE_FORMAT: Final = "qed-pack-bundle/1"

#: Where an imported catalogue lands, under the state directory. Not beside the
#: ones that ship with the package: a wheel is replaced on upgrade, and an
#: import that wrote into `site-packages` would vanish with it.
INSTALLED_SUBDIR: Final = "packs"

#: The file that records which bundle is installed, so a later import can
#: refuse an older one.
MANIFEST_NAME: Final = "bundle.json"


class BundleRejected(ValueError):
    """A bundle that will not be imported, and why.

    Always a sentence an operator can act on. "Invalid signature" is not one:
    which key was expected, which key signed it, and what to do next are.
    """


@dataclass(frozen=True)
class Bundle:
    """A signed set of catalogues, as it arrived."""

    format: str
    issuer: str
    issued_at: str
    packs: tuple[Pack, ...]
    #: Absent on an unsigned bundle, which is a thing somebody must opt into.
    key_id: str | None
    alg: str | None
    signature: str | None
    #: The envelope as parsed, so the signature can be checked over exactly
    #: what was in the file rather than over a re-serialised model. A model
    #: round-trip drops any field this version does not know about, and the
    #: publisher signed the file.
    raw: dict[str, Any]

    @property
    def signed(self) -> bool:
        return self.signature is not None

    @property
    def frameworks(self) -> tuple[str, ...]:
        return tuple(item.framework for item in self.packs)

    @property
    def bundle_hash(self) -> str:
        """`sha256(JCS(envelope))`, the whole file including its signature.

        Identifies *this* bundle rather than its contents: two bundles with the
        same catalogues and different signatures are different things to an
        auditor asking which one was installed.
        """
        return sha256_hex(self.raw)

    def describe(self) -> dict[str, object]:
        """What the `admin_action` record and `qed packs list` report."""
        return {
            "format": self.format,
            "issuer": self.issuer,
            "issued_at": self.issued_at,
            "bundle_hash": self.bundle_hash,
            "frameworks": list(self.frameworks),
            "controls": sum(len(item.controls) for item in self.packs),
            "signed": self.signed,
            "key_id": self.key_id,
        }


#: `imported` is set by the loader from *where a file was read*, never from a
#: file's contents, so it has no place in a bundle or in an installed
#: catalogue. A bundle that could declare itself shipped would be a bundle that
#: could hide where the control titles an auditor reads came from.
_NOT_IN_A_FILE: Final = {"imported"}


def _as_file(item: Pack) -> dict[str, Any]:
    return item.model_dump(mode="json", exclude_defaults=True, exclude=_NOT_IN_A_FILE)


def bundle_payload(envelope: dict[str, Any]) -> bytes:
    """The bytes a pack key signs: the envelope without `signature`.

    Everything else is covered, `key_id` included. A signature over the packs
    alone would let anyone restate which key signed a bundle, or change its
    `issued_at` to defeat the rollback check, without breaking anything.
    """
    return canonicalize({key: value for key, value in envelope.items() if key != "signature"})


def _parse(envelope: dict[str, Any], *, source: str) -> Bundle:
    if not isinstance(envelope, dict):
        raise BundleRejected(f"{source} is not a pack bundle: the top level is not an object")

    declared = envelope.get("format")
    if declared != BUNDLE_FORMAT:
        raise BundleRejected(
            f"{source} declares format {declared!r}; this build reads {BUNDLE_FORMAT!r}. "
            "A newer bundle needs a newer qed -- importing it under the wrong reader "
            "would install catalogues nobody has verified the shape of."
        )

    raw_packs = envelope.get("packs")
    if not isinstance(raw_packs, list) or not raw_packs:
        raise BundleRejected(f"{source} carries no catalogues")

    packs: list[Pack] = []
    for index, entry in enumerate(raw_packs):
        try:
            packs.append(Pack.model_validate(entry))
        except Exception as exc:  # pydantic's message names the field
            raise BundleRejected(f"{source}: catalogue {index} is malformed: {exc}") from exc

    seen: set[str] = set()
    for item in packs:
        if item.framework in seen:
            raise BundleRejected(
                f"{source} carries two catalogues for {item.framework!r}. Which one wins "
                "would decide what a control reference resolves to, so neither does."
            )
        seen.add(item.framework)

    issued_at = envelope.get("issued_at")
    if not isinstance(issued_at, str) or not issued_at:
        raise BundleRejected(
            f"{source} has no `issued_at`. Without one, an old bundle cannot be told "
            "from a new one, and replaying an old bundle is how a control mapping is "
            "taken away quietly."
        )

    return Bundle(
        format=BUNDLE_FORMAT,
        issuer=str(envelope.get("issuer") or "unknown"),
        issued_at=issued_at,
        packs=tuple(packs),
        key_id=envelope.get("key_id") if isinstance(envelope.get("key_id"), str) else None,
        alg=envelope.get("alg") if isinstance(envelope.get("alg"), str) else None,
        signature=envelope.get("signature") if isinstance(envelope.get("signature"), str) else None,
        raw=envelope,
    )


def load_bundle_file(path: Path) -> Bundle:
    """Parse a bundle file. **Does not verify it** -- see :func:`verify`.

    Parsing and verifying are separate so `qed packs verify` can show an
    operator what a bundle contains before anybody decides to trust it.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise BundleRejected(f"cannot read {path}: {exc}") from exc
    try:
        envelope = json.loads(text)
    except json.JSONDecodeError as exc:
        raise BundleRejected(
            f"{path} is not JSON: {exc}. A pack bundle is a single signed JSON "
            "envelope; the catalogues inside it are the same shape as the YAML files "
            "that ship with qed."
        ) from exc
    return _parse(envelope, source=str(path))


def verify(bundle: Bundle, public_key: Ed25519PublicKey) -> None:
    """Raise :class:`BundleRejected` unless `bundle` was signed by `public_key`."""
    if not bundle.signed:
        raise BundleRejected(
            "this bundle carries no signature. Import it with `--unsigned` if you "
            "accept that, which records it as unsigned in the chain and sets "
            "`unsigned: true` on every later `policy_loaded`."
        )
    if bundle.alg not in (None, ALG):
        raise BundleRejected(
            f"the bundle declares alg {bundle.alg!r}; qed signs and verifies {ALG} only "
            "(SPEC 10.2, invariant 1.4.4). There is no other code path to fall back to."
        )

    expected = key_id_for(public_key)
    if bundle.key_id is not None and bundle.key_id != expected:
        raise BundleRejected(
            f"the bundle says it was signed by key {bundle.key_id}, and the key you "
            f"gave is {expected}. Get the right public key from the publisher rather "
            "than the bundle -- a bundle naming its own key proves nothing."
        )

    if not verify_signature(public_key, bundle_payload(bundle.raw), bundle.signature or ""):
        raise BundleRejected(
            f"the signature on this bundle does not verify under key {expected}. Either "
            "it was modified after signing or it was signed by a different key. Do not "
            "import it."
        )


def load_public_key(path: Path) -> Ed25519PublicKey:
    """Read a PEM public key, refusing anything that is not Ed25519."""
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise BundleRejected(f"cannot read the public key at {path}: {exc}") from exc
    try:
        loaded = load_pem_public_key(raw)
    except Exception as exc:
        raise BundleRejected(f"{path} is not a PEM public key: {exc}") from exc
    if not isinstance(loaded, Ed25519PublicKey):
        raise BundleRejected(
            f"{path} is a {type(loaded).__name__}; qed verifies {ALG} only. A pack signed "
            "with anything else cannot be checked by this build."
        )
    return loaded


# ---------------------------------------------------------------- installation


def installed_dir(state_dir: Path) -> Path:
    """Where imported catalogues live for this instance."""
    return state_dir / INSTALLED_SUBDIR


def read_installed(state_dir: Path) -> dict[str, Any] | None:
    """The manifest of the currently installed bundle, if there is one."""
    manifest = installed_dir(state_dir) / MANIFEST_NAME
    if not manifest.exists():
        return None
    try:
        loaded = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        # A manifest we cannot read must not block an import: the catalogues
        # beside it are still readable, and refusing to proceed would leave an
        # operator with no way forward but deleting files by hand.
        return None
    return loaded if isinstance(loaded, dict) else None


def check_not_older(bundle: Bundle, state_dir: Path) -> None:
    """Refuse a bundle issued before the one already installed.

    Replaying an old bundle is how a control mapping is taken away without
    anybody noticing: the import succeeds, the coverage report drops a
    framework, and nothing says why. Comparing `issued_at` is enough because it
    is inside the signature.
    """
    current = read_installed(state_dir)
    if not current:
        return
    previous = current.get("issued_at")
    if not isinstance(previous, str):
        return
    if bundle.issued_at < previous:
        raise BundleRejected(
            f"this bundle was issued {bundle.issued_at} and the installed one "
            f"{previous}. Importing it would roll the catalogues back, which takes "
            "control mappings away silently. Pass `--allow-rollback` if that is what "
            "you mean."
        )


def would_break(bundle: Bundle, rules: Iterable[Any]) -> list[tuple[str, str, str]]:
    """`(rule_id, framework, control)` for mappings this bundle would orphan.

    **The check that stops an import from stopping the kernel.** An imported
    catalogue replaces the shipped one for its framework, so a bundle that
    simply does not list a control some installed rule cites leaves that rule
    citing nothing -- and an uncatalogued control is a lint *error*, and the
    engine refuses to decide against a bundle with errors. The import succeeds
    and the instance governs nothing.

    That was not a thought experiment: a test bundle with three DORA articles
    replaced the shipped catalogue's one, and the next `qed check` answered
    "the policy bundle has errors; refusing to decide against a broken bundle".

    So this runs **before anything is written**, against the rules as loaded,
    and the import refuses. The alternative -- making an unknown control a
    warning when the catalogue was imported -- would put the untraceable OSCAL
    line back, which is the thing the error exists to prevent. A catalogue that
    does not fit the rules is a mismatch for somebody to resolve, not something
    to paper over; refusing before writing leaves the instance exactly as it
    was.
    """
    replacing = {item.framework: item for item in bundle.packs}
    orphaned: list[tuple[str, str, str]] = []
    for rule in rules:
        for ref in getattr(rule, "compliance", None) or ():
            canonical = canonical_framework(ref.framework) or ref.framework
            candidate = replacing.get(canonical)
            if candidate is None:
                continue  # this bundle does not touch that framework
            if not candidate.has(ref.control):
                orphaned.append((rule.rule_id, canonical, ref.control))
    return orphaned


def write_installed(bundle: Bundle, state_dir: Path) -> list[Path]:
    """Write the bundle's catalogues and its manifest. Returns the files written.

    The catalogues go out as YAML, in the same shape as the ones that ship with
    the package, so that `qed/compliance/packs.py` reads both with one loader
    and an operator can diff an imported catalogue against a shipped one.
    """
    target = installed_dir(state_dir)
    target.mkdir(parents=True, exist_ok=True)

    written: list[Path] = []
    for item in bundle.packs:
        path = target / f"{item.framework}.yaml"
        path.write_text(
            "# Imported, not shipped. Written by `qed packs import`; the bundle it came\n"
            f"# from is recorded in {MANIFEST_NAME} beside this file and in the evidence\n"
            "# chain as an `admin_action`. Editing it by hand breaks that trail.\n"
            + yaml.safe_dump(
                _as_file(item),
                sort_keys=False,
                allow_unicode=False,
                width=88,
            ),
            encoding="utf-8",
        )
        written.append(path)

    manifest = target / MANIFEST_NAME
    manifest.write_text(
        json.dumps({**bundle.describe(), "installed_at": rfc3339_ms(utcnow())}, indent=2) + "\n",
        encoding="utf-8",
    )
    written.append(manifest)
    return written


# ------------------------------------------------------------------- authoring


def sign_bundle(
    packs: list[Pack],
    *,
    issuer: str,
    issued_at: datetime,
    sign: Any,
    key_id: str,
) -> dict[str, Any]:
    """Build a signed envelope. Used by the tests and by whoever publishes one.

    `sign` takes the payload bytes and returns the base64url signature -- the
    same shape as :class:`~qed.core.evidence.signing.Signer`, so a publisher
    can hold its pack key however it likes and qed never sees the private half.
    """
    envelope: dict[str, Any] = {
        "format": BUNDLE_FORMAT,
        "issuer": issuer,
        "issued_at": rfc3339_ms(issued_at),
        "key_id": key_id,
        "alg": ALG,
        "packs": [_as_file(item) for item in packs],
    }
    envelope["signature"] = sign(bundle_payload(envelope))
    return envelope
