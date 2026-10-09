# Governing an agent framework with the SDK

SPEC §12.4. Two examples, one pattern.

```bash
qed keys init
qed serve &                      # register an adapter first; see docs/api.md
export QED_URL=http://127.0.0.1:8710
export QED_ADAPTER_ID=adp_sdk_local
export QED_ADAPTER_SECRET="$(python -c 'import secrets;print(secrets.token_hex(24))')"
export QED_HUMAN=you@example.com
export QED_ENV=prod

python examples/sdk/langgraph_tool.py
python examples/sdk/crewai_tool.py
```

Both run **without LangGraph or CrewAI installed.** They import them if they
are there and fall back to calling the same function directly if they are not,
because the point being demonstrated is not the framework — it is that the
tool a framework calls is an ordinary Python function, and an ordinary Python
function is what `@guard` wraps.

That is the whole integration story, and it is why there is no
`qed-langgraph` package: a framework adapter would be a layer that has to
track somebody else's API, and the thing worth tracking is already stable.

## The pattern

```python
from qed.sdk import Qed, QedApprovalPending, QedBlocked, guard

qed = Qed.from_env()


@guard(
    qed,
    kind="custom",
    target=lambda account_id, **_: f"crm:accounts/{account_id}",
    summary=lambda account_id, **_: f"delete account {account_id}",
    deletes=True,
)
def delete_account(account_id: str) -> None: ...
```

Three things to copy:

**Make `target` and `summary` callables.** An approver needs to know *which*
account is being deleted, and a static target tells them which *function* was
called. The callables take the tool's own arguments.

**Catch the two refusals separately.** `QedBlocked` means the policy said no
and the agent should be told so it can do something else. `QedApprovalPending`
means a person has to agree — hand the agent the approval id and let the run
continue elsewhere, or poll with `qed.wait(...)` if the run has nowhere else
to go.

**Do not catch `QedUnavailable` to keep going.** "The policy says no" and "I
could not find out what the policy says" are different facts, and an
application that treats them the same will eventually treat an outage as
permission. The SDK fails closed by default for that reason; if you set
`fail_mode="open"` you are saying an unreachable QED should not stop the agent,
which is a decision to make deliberately and write down.

## What the agent sees

A `QedBlocked` message is written to be read by a model:

```
[qed BLOCK] AG-BLR-003, AG-BLR-005: Destructive change to a production
resource. Fix: Run it against staging first, or request approval with an
explicit intent.
```

Returning that string as the tool's result is usually better than letting the
exception escape: the agent then knows what happened and can propose the
staging run itself. Both examples do that.

## It is advisory

The SDK is ADR-001's class A — whoever can edit the code can delete the
decorator — so records say `enforcement: advisory` and the chain never claims
the action could not have happened. Pass `enforcement="enforcing"` only when
the credential the function needs comes from the broker, so that going around
QED leaves the function with nothing to authenticate with.
