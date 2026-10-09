"""Publishing a checkpoint to a directory (SPEC §10.4).

The simplest anchor and the one worth having first, because it works
everywhere and makes the pattern concrete: one file per checkpoint, named so
the set sorts, with the canonical record as its contents.

On its own a directory on the same disk as the chain anchors nothing — an
operator who can rewrite one can rewrite the other. It becomes an anchor when
the directory is somewhere the instance does not control: a read-only-after-
write volume, a share with its own retention, a path a backup job copies off
the host. The publisher cannot tell the difference, so `qed doctor` prints the
path and leaves the operator to know which they configured.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

from qed.core.schemas import EvidenceRecord, utcnow
from qed.infra.publishers.model import (
    PublicationError,
    Receipt,
    checkpoint_bytes,
    checkpoint_name,
)

__all__ = ["FilePublisher"]


class FilePublisher:
    kind = "file"

    def __init__(self, directory: Path, *, read_only: bool = True) -> None:
        self.directory = directory
        #: Whether to drop the write bits after writing. Default on: a
        #: published anchor that the publishing process can still edit is a
        #: weaker claim than one it cannot, and the cost is one chmod. POSIX
        #: permissions are advisory against root and absent on Windows, which
        #: is why this is one layer and not the whole story.
        self.read_only = read_only

    @classmethod
    def from_config(cls, options: dict[str, object]) -> FilePublisher:
        path = options.get("path")
        if not path:
            raise PublicationError(
                "a `file` checkpoint publisher needs a `path`. Point it somewhere the "
                "instance does not control -- a directory on the same disk as the chain "
                "anchors nothing."
            )
        return cls(Path(str(path)), read_only=bool(options.get("read_only", True)))

    def describe(self) -> str:
        return f"file: {self.directory}"

    def publish(self, record: EvidenceRecord) -> Receipt:
        target = self.directory / checkpoint_name(record)
        body = checkpoint_bytes(record)
        try:
            self.directory.mkdir(parents=True, exist_ok=True)
            # Refuse to overwrite. Two anchors for one sequence number should
            # be impossible, and if it happens the right outcome is a visible
            # failure rather than a silently replaced anchor.
            if target.exists():
                return Receipt(
                    publisher=self.kind,
                    target=str(target),
                    ok=False,
                    error=f"{target.name} already exists; refusing to replace an anchor",
                )
            # Written to a temporary name and moved, so a reader never sees a
            # partial anchor and a crash leaves no half-file that looks like one.
            staging = target.with_suffix(target.suffix + ".part")
            staging.write_bytes(body)
            os.replace(staging, target)
            if self.read_only:
                self._drop_write_bits(target)
        except OSError as exc:
            return Receipt(publisher=self.kind, target=str(target), ok=False, error=str(exc))

        return Receipt(
            publisher=self.kind,
            target=str(target),
            ok=True,
            at=utcnow(),
            proof={
                "sha256": hashlib.sha256(body).hexdigest(),
                "bytes": len(body),
            },
        )

    @staticmethod
    def _drop_write_bits(path: Path) -> None:
        import contextlib
        import stat

        with contextlib.suppress(OSError):
            os.chmod(path, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
