"""A governed CrewAI tool (SPEC §12.4).

The same pattern as `langgraph_tool.py`, with one difference worth showing: a
CrewAI agent usually runs unattended, so this one **waits** on an approval
rather than handing the id back. A crew with nobody watching has nowhere to
return a "come back later" to.

    python examples/sdk/crewai_tool.py

Runs whether or not CrewAI is installed. Needs QED_URL, QED_ADAPTER_ID,
QED_ADAPTER_SECRET and either QED_HUMAN or QED_MANDATE_ID.
"""

from __future__ import annotations

import os
import sys

from qed.sdk import Qed, QedApprovalPending, QedBlocked, QedError, QedUnavailable, guard

#: How long an unattended crew will hold while it waits for a person. Short
#: here so the example finishes; a real one would match the rule's own timeout.
WAIT_SECONDS = float(os.environ.get("DEMO_WAIT_SECONDS", "30"))


def build_client() -> Qed:
    try:
        # A crew acting on nobody's behalf needs a mandate rather than a
        # human (SPEC §6.5): `QED_MANDATE_ID` is the unattended path, and
        # AG-IDN-007 refuses a proposal that has neither.
        return Qed.from_env()
    except QedError as exc:
        print(f"qed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc


qed = build_client()


@guard(
    qed,
    kind="custom",
    target=lambda table, **_: f"db:prod/{table}",
    summary=lambda table, **_: f"run the nightly compaction on {table}",
    writes=True,
    scope="multi_resource",
)
def compact_table(table: str) -> str:
    return f"compacted {table}"


def compact_table_tool(table: str) -> str:
    """What the crew binds.

    The approval branch waits. That is the right call for an unattended run and
    the wrong one for an interactive agent, which should hand the id back and
    let the person get on with something else.
    """
    try:
        return compact_table(table)
    except QedBlocked as refused:
        return str(refused)
    except QedApprovalPending as pending:
        approval = pending.verdict.approval_id
        if approval is None:  # pragma: no cover - a verdict without an id
            return str(pending)
        print(f"qed: waiting up to {WAIT_SECONDS:.0f}s for approval {approval}")
        try:
            status = qed.wait(approval, timeout=WAIT_SECONDS, interval=2.0)
        except QedUnavailable as timed_out:
            # Not an approval. A caller that treated a timeout as a yes would
            # be the whole control undone by a slow afternoon.
            return f"not approved: {timed_out}"
        if status != "approved":
            return f"not approved: the request was {status}"
        # Approved, so the same call now carries a window and goes through.
        return compact_table(table)


def main() -> int:
    table = os.environ.get("DEMO_TABLE", "events")

    try:
        from crewai.tools import tool

        bound = tool("compact_table")(compact_table_tool)
        print("crewai is installed; calling through the bound tool")
        answer = bound.run(table=table)
    except ImportError:
        print("crewai is not installed; calling the same function directly")
        answer = compact_table_tool(table)

    print(answer)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
