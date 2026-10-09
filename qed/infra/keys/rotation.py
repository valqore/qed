"""Rotating the evidence signing key (SPEC §10.5, ADR-0010).

Rotation is the one operation that changes who the chain's signature belongs to
while the chain carries on. Three facts shape all of it.

**The `key_rotated` record is signed by the retiring key.** That signature is
what makes rotation a *continuous* chain rather than two chains that happen to
share a database: an auditor holding the old public key can verify the record
that introduces the new one, and so on back to genesis. `qed-verify` enforces
it, and so does :class:`~qed.infra.chain_writer.ChainWriter` at write time.

**The order is: record first, then the file.** If the key file were swapped
first and the append then failed, the chain would be on the old key and the
next record would be signed by the new one, with nothing in between saying so --
a discontinuity that looks exactly like a forged chain. Doing it the other way
round leaves a worse-understood but *detectable* state, and the new private key
is written durably before the record is appended so that nothing is ever lost
between the two steps.

**The old private key is deleted.** Rotation exists because a key might have
leaked, and a rotation that leaves the old key on disk has not reduced
anything. The threat is not re-signing an existing record -- `hash` covers
`payload_hash` and the next record's `prev_hash` covers `hash`, so an edit
breaks linkage -- it is fabricating a whole alternative history that verifies
under a key an auditor still trusts for the period before the rotation. The old
*public* key is kept, and must be: without it the chain before the rotation
cannot be verified at all.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from qed.infra.keys.file import (
    PRIVATE_KEY_NAME,
    PUBLIC_DIR_NAME,
    FileSigner,
    MissingSigningKey,
    public_key_filename,
)

__all__ = ["PENDING_SUFFIX", "RotationPlan", "finish_rotation", "stage_rotation"]

#: Where the incoming private key waits while the record is appended. A
#: distinctive name because a leftover one is a half-finished rotation, and
#: `qed doctor` says so rather than leaving somebody to guess.
PENDING_SUFFIX = ".incoming"


@dataclass(frozen=True)
class RotationPlan:
    """A rotation that has been prepared but not yet committed."""

    old: FileSigner
    new: FileSigner
    directory: Path

    @property
    def pending_path(self) -> Path:
        return self.directory / (PRIVATE_KEY_NAME + PENDING_SUFFIX)

    @property
    def active_path(self) -> Path:
        return self.directory / PRIVATE_KEY_NAME

    @property
    def payload(self) -> dict[str, object]:
        """The `key_rotated` record's payload (SPEC §10.5).

        `new_public_pem` travels in the record on purpose: an auditor who was
        given only the old public key can still read the new one out of the
        chain, and check that the key they were later handed is the one the
        rotation actually introduced.
        """
        return {
            "old_key_id": self.old.key_id,
            "new_key_id": self.new.key_id,
            "new_public_pem": self.new.public_pem,
        }


def stage_rotation(directory: Path) -> RotationPlan:
    """Generate the next key and write it where it survives a crash.

    Nothing about the chain changes here, and nothing about which key is
    active. Calling this twice simply discards the first unused key.
    """
    active = directory / PRIVATE_KEY_NAME
    if not active.exists():
        raise MissingSigningKey(
            f"no signing key at {active}; there is nothing to rotate. "
            "`qed keys init` creates the first one."
        )
    old = FileSigner.load(active)
    new = FileSigner.generate()

    plan = RotationPlan(old=old, new=new, directory=directory)
    # The public half goes in before the private half is activated. A public
    # key on disk grants nothing, and leaving it until after the swap would
    # mean a crash between the two produced records nobody could verify.
    new.save_public(directory / PUBLIC_DIR_NAME)
    new.save_private(plan.pending_path, overwrite=True)
    return plan


def finish_rotation(plan: RotationPlan) -> None:
    """Make the new key active and destroy the old private key.

    Called only after the `key_rotated` record is in the chain. `os.replace`
    is atomic on both POSIX and Windows, so there is no moment at which
    `evidence-key.pem` is absent or partly written -- a reader either gets the
    old key or the new one.
    """
    os.replace(plan.pending_path, plan.active_path)
    # `os.replace` already overwrote the old key's bytes in place, so there is
    # no separate file to unlink. The assertion is that the active key is now
    # the new one, because every later signature depends on it.
    reloaded = FileSigner.load(plan.active_path)
    if reloaded.key_id != plan.new.key_id:  # pragma: no cover - defensive
        raise MissingSigningKey(
            f"after rotation the active key is {reloaded.key_id}, expected {plan.new.key_id}"
        )


def pending_rotation(directory: Path) -> Path | None:
    """A staged key that was never activated, if there is one.

    Reported by `qed doctor`. It means a rotation was interrupted: either the
    record was never appended -- in which case the file is safe to delete -- or
    it was, and the chain now expects a key that is not active, which
    `ChainWriter` refuses to write against.
    """
    candidate = directory / (PRIVATE_KEY_NAME + PENDING_SUFFIX)
    return candidate if candidate.exists() else None


def retired_public_keys(directory: Path, *, active_key_id: str) -> list[str]:
    """Key ids with a public key on disk that are not the active one.

    An auditor needs all of them. A chain that spans a rotation cannot be
    verified from the active key alone, and the usual way that goes wrong is
    somebody sending `public/` after pruning it to one file.
    """
    public = directory / PUBLIC_DIR_NAME
    if not public.is_dir():
        return []
    active = public_key_filename(active_key_id)
    return sorted(
        path.stem.replace("_", ":") for path in public.glob("*.pem") if path.name != active
    )
