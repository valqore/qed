"""``qed demo`` — the kernel end to end, in one command (SPEC §14).

Nothing here is new machinery. The proposals are built with
:func:`qed.adapters.common.build_proposal`, the same function the MCP and HTTP
adapters use, and decided through :func:`qed.runtime.check_proposal`, the same
path a real adapter takes. A demo that reached past those into the engine would
be a demo of code nobody runs.

Three properties it has to keep, because each one is a way a demo turns into a
liability:

**It writes to a throwaway directory and marks every record ``dev``.** A
demo chain that looks like evidence is worse than no demo. ``dev: true`` is in
the record, not in the prose around it, so an export of this chain says what it
is wherever it ends up.

**It exits 0 even though it contains a BLOCK.** The exit code of `qed check`
is the verdict (SPEC §12.5); the exit code of a demo is whether the demo ran.
Anyone who pastes this into a pipeline to see what it does should not have the
pipeline fail.

**What it claims the pack decides is asserted in the test suite, not here.**
Each scene carries the decision the shipped baseline pack gives it today
(:class:`Scene`'s ``expect``), and ``tests/cli/test_demo.py`` checks every one
against the real pack. If a rule changes, that test fails — rather than a
stranger's first run printing something this file promised it would not.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Final

from qed.adapters.common import AdapterInfo, build_proposal
from qed.core.evidence.hashing import principal_hash
from qed.core.schemas import (
    ActionKind,
    ActionProposal,
    CostEstimate,
    Decision,
    Enforcement,
    Mode,
)

if TYPE_CHECKING:  # `qed.runtime` pulls in the store and the chain writer.
    # The scenes are importable without any of that -- `tests/cli/test_demo.py`
    # decides them through the engine alone -- so the runtime is a type-only
    # import here and a local one inside `run`.
    from qed.runtime import CheckOutcome, Session

__all__ = ["CONFIG_YAML", "SCENES", "Scene", "Step", "prepare", "run"]

#: The adapter identity on every demo proposal. A real adapter id is registered
#: with `qed adapters add`; this one decides locally and never authenticates to
#: an API, which is why the demo needs no secret.
ADAPTER: Final = AdapterInfo("qed-demo/1.0", "adp_demo")

#: One demo human, hashed the way every other component hashes a subject
#: (SPEC §10.6) rather than with a plausible-looking literal — the point of the
#: chain is that the same person hashes the same way everywhere.
HUMAN: Final = principal_hash("ali@example.com", issuer="https://idp.example.com")

#: One delegation token across all the scenes, so the budget story is one story.
TOKEN_JTI: Final = "01JBDEMO00000000000000TOKEN"

#: Caps for that token, seeded into the ledger before the first decision.
#: Not passed per call: an explicit `budget=` overrides the ledger, which would
#: show a budget that never depletes. Seeding the caps is what `qed token`
#: does, so the five scenes spend one real budget -- and it keeps AG-BUD-005
#: ("production action against an uncapped token") off every prod scene, which
#: is a true finding about a laptop and noise in a demo.
DEMO_BUDGET_STEPS: Final = 50
DEMO_BUDGET_MONEY_CENTS: Final = 5_000

CONFIG_YAML: Final = """\
# Written by `qed demo`. A real deployment's reference is SPEC 16 and
# `docs/deployment.md`; this is the smallest file that makes a decision.
instance_id: qed-demo
# `enforce`, so a BLOCK below is a BLOCK. A new instance should start in
# `shadow` -- see docs/onboarding-shadow-to-enforce.md, which is the whole
# argument for why.
mode: enforce
"""


@dataclass(frozen=True)
class Scene:
    """One proposal, and what it is in the demo to show."""

    key: str
    #: What the agent is trying to do, in the operator's words.
    headline: str
    #: Why this scene is in the demo. One line, shown under the verdict.
    teaches: str
    #: What the shipped pack decides. Asserted in the tests, not trusted here.
    expect: Decision
    build: Callable[[], ActionProposal]
    #: Set when the decision and `would_decision` differ, i.e. a shadow-mode
    #: rule fired: then `expect` is what happened and this is what would have
    #: happened with that rule promoted to enforce.
    expect_would: Decision | None = None


def _dev_read() -> ActionProposal:
    return build_proposal(
        kind=ActionKind.mcp_tool,
        name="github.list_issues",
        target="repo:acme/payments",
        params={"state": "open", "labels": ["bug"]},
        adapter=ADAPTER,
        environment="dev",
        enforcement=Enforcement.enforcing,
        mode=Mode.enforce,
        token_jti=TOKEN_JTI,
        human_hash=HUMAN,
        agent_chain=["claude-code@laptop-ali"],
        intent="Find open bugs to triage.",
        summary="claude-code wants to list open bug issues on repo:acme/payments",
        cost=CostEstimate(tokens=1200),
    )


def _prod_drop() -> ActionProposal:
    return build_proposal(
        kind=ActionKind.mcp_tool,
        name="postgres.execute_sql",
        target="db:prod/orders",
        params={"sql": "DROP TABLE orders_archive;"},
        adapter=ADAPTER,
        environment="prod",
        enforcement=Enforcement.enforcing,
        mode=Mode.enforce,
        token_jti=TOKEN_JTI,
        human_hash=HUMAN,
        agent_chain=["claude-code@laptop-ali", "sub:planner"],
        intent="Clean up the archive table left over from the September migration.",
        summary="claude-code wants to DROP TABLE orders_archive on db:prod/orders",
        writes=True,
        deletes=True,
        tags=["migration", "cleanup"],
    )


def _open_ingress() -> ActionProposal:
    return build_proposal(
        kind=ActionKind.http,
        name="PUT /ec2/security-groups/sg-0a1b2c",
        target="aws:ec2:sg-0a1b2c",
        params={"cidr": "0.0.0.0/0", "port": 22, "protocol": "tcp"},
        adapter=ADAPTER,
        environment="prod",
        enforcement=Enforcement.enforcing,
        mode=Mode.enforce,
        token_jti=TOKEN_JTI,
        human_hash=HUMAN,
        agent_chain=["claude-code@laptop-ali", "sub:remediation"],
        method="PUT",
        intent="Open SSH so the on-call engineer can reach the host during incident 4821.",
        summary="the agent wants to allow 0.0.0.0/0 on port 22 for sg-0a1b2c in prod",
        writes=True,
        tags=["incident-4821"],
    )


def _egress() -> ActionProposal:
    return build_proposal(
        kind=ActionKind.http,
        # `METHOD path`, the shape `qed proxy` writes (SPEC §12.3).
        name="POST /v1/exports",
        target="https://api.vendor.example/v1/exports",
        params={"body": '{"rows": 4821}'},
        adapter=ADAPTER,
        environment="prod",
        enforcement=Enforcement.enforcing,
        mode=Mode.enforce,
        token_jti=TOKEN_JTI,
        human_hash=HUMAN,
        agent_chain=["claude-code@laptop-ali"],
        method="POST",
        intent="Send the weekly export to the vendor's ingest endpoint.",
        summary="the agent wants to POST an export to api.vendor.example",
        writes=True,
    )


def _unattended() -> ActionProposal:
    return build_proposal(
        kind=ActionKind.mcp_tool,
        name="k8s.scale_deployment",
        target="k8s:prod/checkout",
        params={"replicas": 12},
        adapter=ADAPTER,
        environment="prod",
        enforcement=Enforcement.enforcing,
        mode=Mode.enforce,
        token_jti=TOKEN_JTI,
        # No human, and no mandate either. This is the scene.
        human_hash=None,
        agent_chain=["svc:sre-agent"],
        intent="Scale checkout for the traffic spike.",
        summary="an unattended agent wants to scale k8s:prod/checkout to 12 replicas",
        writes=True,
    )


#: The arc: an allow, an approval, a block, a shadow rule, and an agent nobody
#: authorised. Five is enough to show the shape of the thing and short enough
#: that the whole run fits on one screen.
SCENES: Final[tuple[Scene, ...]] = (
    Scene(
        key="01-dev-read",
        headline="a read in dev",
        teaches="Most actions are fine. A gate that stops work does not stay installed.",
        expect=Decision.ALLOW,
        build=_dev_read,
    ),
    Scene(
        key="02-prod-drop",
        headline="DROP TABLE on a production database",
        teaches="Not refused -- routed to a human, with the blast radius already computed.",
        expect=Decision.REQUIRE_APPROVAL,
        build=_prod_drop,
    ),
    Scene(
        key="03-open-ingress",
        headline="ingress opened to the whole internet",
        teaches="Some actions have no approval path. This one is simply refused.",
        expect=Decision.BLOCK,
        build=_open_ingress,
    ),
    Scene(
        key="04-egress",
        headline="an export to a host nobody allow-listed",
        teaches="A shadow rule records what it would have done and lets the action through.",
        expect=Decision.ALLOW,
        expect_would=Decision.REQUIRE_APPROVAL,
        build=_egress,
    ),
    Scene(
        key="05-unattended",
        headline="an unattended agent with no mandate",
        teaches="No human, no mandate, no action -- decided before any rule runs.",
        expect=Decision.BLOCK,
        build=_unattended,
    ),
)


@dataclass(frozen=True)
class Step:
    """A scene that has been decided."""

    scene: Scene
    proposal: ActionProposal
    outcome: CheckOutcome
    #: Where the proposal was written, so the follow-up commands have a file.
    path: Path


def prepare(directory: Path) -> Path:
    """Create the state directory, its keys and its `qed.yaml`. Returns the config path.

    Safe to run twice over the same directory: an existing signing key is kept
    rather than replaced, because a new key mid-chain is a key discontinuity and
    the writer is right to refuse it (ADR-0010). A second `qed demo` into the
    same directory therefore extends the chain instead of breaking it.
    """
    from qed.infra.keys.file import PRIVATE_KEY_NAME, init_keys

    directory.mkdir(parents=True, exist_ok=True)
    if not (directory / PRIVATE_KEY_NAME).exists():
        init_keys(directory)
    config_path = directory / "qed.yaml"
    config_path.write_text(CONFIG_YAML, encoding="utf-8")
    # A demo that leaves a signing key and a chain inside somebody's repository
    # must not be committable by accident.
    (directory / ".gitignore").write_text("# Written by `qed demo`.\n*\n", encoding="utf-8")
    return config_path


def run(directory: Path) -> tuple[list[Step], Session]:
    """Decide every scene against a fresh instance in ``directory``.

    Returns the steps and the open session, which the caller closes after
    reading whatever it wants off the chain. The session stays open on purpose:
    the summary line an operator wants -- record count, policy hash, key id --
    comes from the instance that just made the decisions, not from a second
    one opened over the same files.
    """
    from qed.core.schemas import Budget
    from qed.runtime import check_proposal, open_session

    config_path = prepare(directory)
    proposals_dir = directory / "proposals"
    proposals_dir.mkdir(exist_ok=True)

    # `dev=True` marks every record as a development record, in the record
    # itself. It is the one line that stops this chain being mistaken for
    # evidence after it is exported and mailed to somebody.
    session = open_session(directory=directory, config_path=config_path, dev=True)
    session.store.upsert_budget_caps(
        TOKEN_JTI,
        Budget(steps=DEMO_BUDGET_STEPS, money_cents=DEMO_BUDGET_MONEY_CENTS),
    )
    steps: list[Step] = []
    for scene in SCENES:
        proposal = scene.build()
        path = proposals_dir / f"{scene.key}.json"
        path.write_text(proposal.model_dump_json(indent=2), encoding="utf-8")
        steps.append(
            Step(
                scene=scene,
                proposal=proposal,
                outcome=check_proposal(session, proposal),
                path=path,
            )
        )
    return steps, session
