"""Shipping source may not promise a week (SPEC §22).

The twelve weeks of the §22 build order are complete, so a sentence in the
source saying something "arrives in week 3" or "is week 10 hardening" is not a
plan any more. It is a false statement about the build a reader is holding, and
there were eighteen of them -- written true in week 1 or 2, never revisited,
and found by reading the repository as somebody evaluating it rather than as
the person who wrote it.

Three of the eighteen were not comments:

* `qed mcp` told an agent `No approval route is configured in this build
  (approvals land in week 4)` on every REQUIRE_APPROVAL, ten weeks after the
  approval service shipped -- moments after the kernel had filed a request and
  written `approval_requested` with its id, and while the HTTP proxy and the
  Claude Code hook were both already reporting that id. A test asserted the
  stale sentence and was green.
* `--token-jti`'s help text read `(week 3: real)`.
* `qed mcp` without `--human` said `Verified identity from an IdP arrives in
  week 3`.

A reader cannot tell a stale promise from a real limitation, so each one costs
exactly as much credibility as a real gap -- while hiding the real gaps in the
noise. This test is cheaper than reading 122 files again.

It does not forbid naming a week in the past tense ("the week-1 bug", "moved
here in week 6"). Those are history and they are true. It forbids the future
tense, in a repository where there is no future week left.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

#: Sources that ship to a user: the wheel, and the verifier an auditor runs.
#: Planning documents, ADRs and the changelog legitimately speak in weeks.
SHIPPING = (ROOT / "qed", ROOT / "packages")

PROMISE = re.compile(
    r"""(
        until\s+week\s*[-\s]?\d          # "there are no tokens until week 3"
      | arriv\w*[^.\n]{0,60}?in\s+week\s*[-\s]?\d  # "arrive on a bearer in week 3"
      | land\w*\s+in\s+week\s*[-\s]?\d   # "approvals land in week 4"
      | \bis\s+week\s*[-\s]?\d           # "enforcement is week 10"
      | \bare\s+week\s*[-\s]?\d          # "control packs are week 8"
      | week\s*[-\s]?\d\s*:\s*real       # "(week 3: real)"
      | week\s*[-\s]?\d\s+(brings|adds|makes|replaces|flips|moves|implements)\b
    )""",
    re.IGNORECASE | re.VERBOSE,
)

#: The one line allowed to contain a promise: the comment in
#: `qed/adapters/mcp/proxy.py` that quotes the sentence it replaced, so the next
#: reader learns what the bug was. Quoting a false statement in order to
#: correct it is the opposite of making one.
ALLOWED = ('approval route is configured in this build (approvals land in week 4)"),',)


def test_nothing_in_the_wheel_promises_a_week() -> None:
    offenders: list[str] = []
    for tree in SHIPPING:
        for path in sorted(tree.rglob("*.py")):
            if "__pycache__" in path.parts:
                continue
            for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                if any(allowed in line for allowed in ALLOWED):
                    continue
                if PROMISE.search(line):
                    offenders.append(
                        f"{path.relative_to(ROOT).as_posix()}:{number}: {line.strip()}"
                    )
    assert not offenders, (
        "every week of the build order is complete, so each of these promises a "
        "thing that already exists or blames a week for a gap that is simply "
        "open — say which it is instead:\n  " + "\n  ".join(offenders)
    )


def test_the_pattern_still_catches_what_it_was_written_for() -> None:
    """A guard that matches nothing passes forever."""
    for sentence in (
        "There are no tokens until week 3, and filtering",
        "approvals land in week 4",
        "Enforcement is week 10, and the only thing",
        "Control *packs* are week 8.",
        "Token id to attribute calls to (week 3: real).",
        "Week 6 replaces this with the IdP's own claims",
        "Humans and admins arrive on an OIDC bearer in week 3",
    ):
        assert PROMISE.search(sentence), f"the pattern no longer catches: {sentence!r}"


def test_the_pattern_leaves_history_alone() -> None:
    """The other direction. Flagging these would make the guard a nuisance and
    the next person would delete it."""
    for sentence in (
        "a week-1 bug worth not repeating",
        "The store moved to qed.infra.storage.store in week 6 when it gained a",
        "the same shape of silent degradation the week 1 review found",
        "so the disclosure bar was set in week 3.",
        "Week 8 shipped ten catalogues inside the package",
        "the week-7 p95 target has to defend",
    ):
        assert not PROMISE.search(sentence), f"the pattern now flags history: {sentence!r}"
