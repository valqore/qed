"""A governed LangGraph tool (SPEC §12.4).

Runs whether or not LangGraph is installed. The point is not the framework: a
LangGraph tool is an ordinary Python function, and an ordinary Python function
is what ``@guard`` wraps. If the import fails the same function is called
directly, and the governed path is identical.

    python examples/sdk/langgraph_tool.py

Needs QED_URL, QED_ADAPTER_ID, QED_ADAPTER_SECRET and QED_HUMAN; see the
README beside this file.
"""

from __future__ import annotations

import os
import sys

from qed.sdk import Qed, QedApprovalPending, QedBlocked, QedError, guard


def build_client() -> Qed:
    try:
        return Qed.from_env()
    except QedError as exc:
        print(f"qed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc


qed = build_client()


# The tool a LangGraph node would call. `target` and `summary` are callables so
# the proposal describes *this* deletion rather than the function in general --
# an approver needs to know which account.
@guard(
    qed,
    kind="custom",
    target=lambda account_id, **_: f"crm:accounts/{account_id}",
    summary=lambda account_id, **_: f"delete CRM account {account_id}",
    deletes=True,
    scope="single_resource",
)
def delete_account(account_id: str) -> str:
    """Pretend to delete an account. Never reached when the policy refuses."""
    return f"deleted {account_id}"


def delete_account_tool(account_id: str) -> str:
    """What the graph actually binds.

    The refusal is returned as the tool's *result* rather than raised, because
    a model that is told why it was refused can propose the staging run itself.
    An exception escaping into the framework usually ends the run instead.
    """
    try:
        return delete_account(account_id)
    except QedBlocked as refused:
        return str(refused)
    except QedApprovalPending as pending:
        approval = pending.verdict.approval_id
        return (
            f"{pending}\nA person has to agree. Approval {approval} is open; it can be "
            "decided with `qed approve` or in the web queue, and the same call will go "
            "through afterwards."
        )


def main() -> int:
    account = os.environ.get("DEMO_ACCOUNT", "8812")

    try:
        from langchain_core.tools import tool

        bound = tool(delete_account_tool)
        print("langchain_core is installed; calling through the bound tool")
        answer = bound.invoke({"account_id": account})
    except ImportError:
        print("langchain_core is not installed; calling the same function directly")
        answer = delete_account_tool(account)

    print(answer)
    # Whatever happened, it is in the chain:
    print("\n`qed export | qed-verify --keys <dir>/public` to check the record.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
