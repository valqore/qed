"""Every `helm` command in the documentation is run (SPEC §24).

Written because one was wrong the moment the chart changed. Adding the
adapter precondition made `README.md`'s HA example a release the chart
refuses, and nothing failed: no template is invalid, no assertion covers the
prose, and the only thing that found it was a `grep` for `helm install` while
looking for something else. The next reader would have found it by pasting it.

So the documentation's commands are the test input. Each one is extracted from
the tracked Markdown, turned into `helm template`, and rendered. A command
that the chart would refuse is a failing test here rather than a support
question, and a *new* precondition on the chart now breaks every example that
does not satisfy it -- which is the point, because that is what it does to a
reader.

`helm install` is rewritten to `helm template` so this neither contacts a
cluster nor needs one; both run the same templates through the same
`validate.yaml`, which is where a refusal comes from.

Skipped without `helm` on PATH.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

HELM = shutil.which("helm")
ROOT = Path(__file__).resolve().parents[2]
CHART = ROOT / "deploy" / "helm" / "qed"

pytestmark = pytest.mark.skipif(HELM is None, reason="helm is not installed")

#: Markdown that tells a reader what to run. A file added here is a file whose
#: commands are checked; one not here is one nobody promised anything about.
PAGES = (
    "README.md",
    "docs/deployment.md",
    "docs/validation.md",
    "deploy/helm/qed/README.md",
)

#: `helm install <release> <chart> ...` or `helm template <release> <chart> ...`
COMMAND = re.compile(r"^\s*helm\s+(?:install|template|upgrade)\s+.*", re.MULTILINE)


def commands() -> list[tuple[str, int, list[str]]]:
    """Every helm invocation in PAGES, with line continuations joined."""
    found: list[tuple[str, int, list[str]]] = []
    for page in PAGES:
        path = ROOT / page
        if not path.exists():  # pragma: no cover - PAGES is checked below
            continue
        # Join `\`-continued lines first, keeping a line number for the message.
        text = path.read_text(encoding="utf-8")
        lines = text.splitlines()
        joined: list[tuple[int, str]] = []
        buffer, start = "", 0
        for number, line in enumerate(lines, start=1):
            stripped = line.rstrip()
            if not buffer:
                start = number
            if stripped.endswith("\\"):
                buffer += stripped[:-1] + " "
                continue
            joined.append((start, buffer + stripped))
            buffer = ""
        for number, line in joined:
            if COMMAND.match(line):
                found.append((page, number, line.split()))
    return found


def ids() -> list[str]:
    return [f"{page}:{number}" for page, number, _ in commands()]


class TestEveryDocumentedHelmCommandRenders:
    def test_there_is_at_least_one(self) -> None:
        """A parametrised suite with no parameters passes silently, which is
        the vacuous green this repository has shipped before."""
        assert commands(), f"no helm commands found in {PAGES}; the regex or the pages moved"

    @pytest.mark.parametrize(("page", "line", "argv"), commands(), ids=ids())
    def test_it_renders(self, page: str, line: int, argv: list[str]) -> None:
        # `install` and `upgrade` both go through `template`: same templates,
        # same validate.yaml, no cluster.
        rewritten = ["template" if part in {"install", "upgrade"} else part for part in argv[1:]]
        # A release name may be absent (`helm template <chart>`), and flags
        # that only mean something against a cluster are dropped.
        rewritten = [part for part in rewritten if part not in {"--dry-run", "--atomic", "--wait"}]
        # The chart path in the docs is relative to the repository root.
        resolved = [
            str(CHART) if part.rstrip("/").endswith("deploy/helm/qed") else part
            for part in rewritten
        ]
        result = subprocess.run(
            [str(HELM), *resolved],
            capture_output=True,
            text=True,
            check=False,
            cwd=ROOT,
        )
        assert result.returncode == 0, (
            f"{page}:{line} is a command the chart refuses, so a reader who pastes it "
            f"gets this:\n\n{result.stderr.strip()}\n\n"
            "Either the documentation is stale or the new precondition needs a default."
        )
