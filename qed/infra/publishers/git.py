"""Publishing a checkpoint as a git tag (SPEC §10.4).

The anchor for operators who already have a repository other people can read.
A tag whose message carries the checkpoint record, pushed to a remote the
instance does not own, is a timestamp somebody else holds — and if the tag is
GPG-signed, one that names who created it.

What this is not: a copy of the chain. One tag per checkpoint, carrying one
record. A repository full of evidence payloads would be an evidence store with
none of the properties this project claims for the real one.

Why `git` rather than a library: `git` is the thing the operator's remote,
credentials, SSH agent and signing key are already configured for. A library
would need all of it configured a second time, and would be a second
implementation of the one part that has to interoperate exactly.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Final

from qed.core.schemas import EvidenceRecord, utcnow
from qed.infra.publishers.model import PublicationError, Receipt, checkpoint_bytes

__all__ = ["GitTagPublisher"]

#: Long enough for a slow remote, short enough that a hung push does not hold
#: the maintenance tick. The chain is already written at this point; a missed
#: publication is a receipt with `ok=False`, not lost evidence.
TIMEOUT: Final = 60.0


class GitTagPublisher:
    kind = "git-tag"

    def __init__(
        self,
        repository: Path,
        *,
        remote: str = "origin",
        push: bool = True,
        sign: bool = False,
        prefix: str = "qed-checkpoint-",
    ) -> None:
        self.repository = repository
        self.remote = remote
        #: Pushing is what makes it an anchor. A local tag is as rewritable as
        #: the chain beside it, so this defaults on and a receipt says whether
        #: the push happened.
        self.push = push
        self.sign = sign
        self.prefix = prefix

    @classmethod
    def from_config(cls, options: dict[str, object]) -> GitTagPublisher:
        repository = options.get("repository") or options.get("path")
        if not repository:
            raise PublicationError(
                "a `git-tag` checkpoint publisher needs a `repository`: a checkout whose "
                "remote is somewhere the instance does not control."
            )
        path = Path(str(repository))
        if not (path / ".git").exists() and not path.name.endswith(".git"):
            raise PublicationError(f"{path} is not a git repository")
        return cls(
            path,
            remote=str(options.get("remote", "origin")),
            push=bool(options.get("push", True)),
            sign=bool(options.get("sign", False)),
            prefix=str(options.get("prefix", "qed-checkpoint-")),
        )

    def describe(self) -> str:
        pushing = f"-> {self.remote}" if self.push else "local only"
        return f"git-tag: {self.repository} {pushing}{' (signed)' if self.sign else ''}"

    def publish(self, record: EvidenceRecord) -> Receipt:
        tag = f"{self.prefix}{record.seq:010d}"
        message = checkpoint_bytes(record).decode("utf-8")

        # The message comes in on stdin (`-F -`) rather than `-m`: the record is
        # JSON, and passing it as an argument would put it through one more
        # layer of quoting for no benefit.
        create = ["git", "tag", "-a", tag, "-F", "-"]
        if self.sign:
            create.insert(2, "-s")

        result = self._run(create, stdin=message)
        if result is None or result.returncode != 0:
            return Receipt(
                publisher=self.kind,
                target=tag,
                ok=False,
                error=_reason(result, f"could not create tag {tag}"),
            )

        proof: dict[str, object] = {"tag": tag, "signed": self.sign}
        commit = self._run(["git", "rev-list", "-n", "1", tag])
        if commit is not None and commit.returncode == 0:
            proof["commit"] = commit.stdout.strip()

        if not self.push:
            return Receipt(
                publisher=self.kind,
                target=tag,
                ok=True,
                at=utcnow(),
                proof={**proof, "pushed": False},
                error="not pushed, so this anchor lives only beside the chain it anchors",
            )

        pushed = self._run(["git", "push", self.remote, tag])
        if pushed is None or pushed.returncode != 0:
            # The tag exists locally and the push failed. Reported as a
            # failure, because the local tag is not the thing that anchors --
            # and left in place, because the next attempt can push it.
            return Receipt(
                publisher=self.kind,
                target=tag,
                ok=False,
                proof={**proof, "pushed": False},
                error=_reason(pushed, f"created {tag} but could not push it to {self.remote}"),
            )

        return Receipt(
            publisher=self.kind,
            target=tag,
            ok=True,
            at=utcnow(),
            proof={**proof, "pushed": True, "remote": self.remote},
        )

    def _run(
        self, command: list[str], *, stdin: str | None = None
    ) -> subprocess.CompletedProcess[str] | None:
        try:
            return subprocess.run(
                command,
                cwd=self.repository,
                input=stdin,
                capture_output=True,
                text=True,
                timeout=TIMEOUT,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return None


def _reason(result: subprocess.CompletedProcess[str] | None, fallback: str) -> str:
    """git's own message, trimmed. Never a traceback: this goes in the chain."""
    if result is None:
        return f"{fallback} (git did not run -- not installed, or it timed out)"
    detail = (result.stderr or result.stdout or "").strip().splitlines()
    return f"{fallback}: {detail[0][:200]}" if detail else fallback
