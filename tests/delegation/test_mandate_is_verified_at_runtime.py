"""A forged mandate is refused by the runtime, not just by `verify_mandate`.

This file exists because of a specific bug, and the bug is the interesting part.

`verify_mandate` was written in week 3 and unit-tested in `test_mandates.py`
from that day: tamper with a mandate, assert it raises. Those tests passed for
eight weeks. **Nothing called the function.** Every consumer -- `qed check`, the
hook, the MCP and HTTP proxies, `POST /v1/proposals` -- parsed a mandate with
`Mandate.model_validate_json`, which validates the schema and not the
signature, and handed it straight to the engine.

What made that a forgery rather than an omission is how two correct decisions
composed, which is the same shape as ADR-0012's remote kill switch:

* `AG-IDN-007` BLOCKs a proposal with no `human_hash` and no mandate -- an
  unattended action needs an authority.
* `compute_derived` reports `present: true` for any mandate it is given, and
  `mandate_validity` deliberately checks only the window and revocation
  ("signature verification is the token layer's job").

So the mandate was the whole authority for unattended action, and the token
layer was not checking it. Measured before the fix: the same proposal decided
**BLOCK** with no mandate and **REQUIRE_APPROVAL** with a mandate whose
signature was 86 `A`s -- deriving identically to the genuine one.

The unit tests could not see this and neither could a coverage number.
`verify_mandate` was covered. The assertion that was missing is the one here:
that the path an operator actually uses calls it.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

import pytest

from qed.core.mandates import MANDATE_ALG, MandateError, signing_payload
from qed.core.schemas import ActionProposal, Mandate, MandateSignature
from qed.infra.keys.file import FileSigner, init_keys
from qed.runtime import Session, check_proposal, open_session

EXAMPLE = Path(__file__).parents[2] / "examples/mandates/sre-agent.json"
ROOT = Path(__file__).parents[2]

#: An unattended action: no `human_hash`, so a mandate is the only authority it
#: can have. With none at all this is a BLOCK under AG-IDN-007.
UNATTENDED = {
    "schema_version": "1.0",
    "id": "01JB0000000000000000MANDAT1",
    "ts": "2026-10-10T09:14:22.431Z",
    "principal": {
        "token_jti": "01JB000000000000000000JTIM",
        "human_hash": None,
        "agent_chain": ["sre-agent@unattended"],
        "mandate_id": "md_01JB00000000000000000001",
        "client_fingerprint": "sha256:advisory-only",
    },
    "action": {
        "kind": "http",
        "name": "PUT /ec2/instances/i-123/stop",
        "target": "aws:ec2:i-123",
        "params_hash": "3f786850e387550fdab836ed7e6dc881de23001b4e9b1c0b2a0e9f0bb6f1c2d3",
        "params_redacted": {},
        "method": "PUT",
    },
    "context": {
        "environment": "prod",
        "tags": [],
        "adapter": "cli/0.1.0",
        "adapter_id": "adp_sre",
        "enforcement": "advisory",
        "mode": "shadow",
        "cost_estimate": {"tokens": 0, "money_cents": 0, "currency": "USD", "known": True},
        "blast_radius_hints": {"writes": True, "deletes": False, "scope": "single_resource"},
        "intent": "Stop an idle instance.",
        "summary": "sre-agent wants to stop i-123",
    },
}


def proposal(suffix: str) -> ActionProposal:
    """A fresh id each time: ids are single-use, and reusing one is a 409 that
    writes nothing -- which silently empties whatever the test asserted next
    (`docs/validation.md`)."""
    document = json.loads(json.dumps(UNATTENDED))
    document["id"] = f"01JB0000000000000000MANDA{suffix}"
    return ActionProposal.model_validate(document)


def sign(mandate: Mandate, signer: FileSigner) -> Mandate:
    """The same helper `test_mandates.py` has, kept local for the same reason:
    signing a mandate is something the CLI does, not a library function."""
    return mandate.model_copy(
        update={
            "signature": MandateSignature(
                key_id=signer.key_id, alg=MANDATE_ALG, sig=signer.sign(signing_payload(mandate))
            )
        }
    )


@pytest.fixture
def session(tmp_path: Path) -> Iterator[Session]:
    init_keys(tmp_path)
    opened = open_session(directory=tmp_path, strict_policy=False)
    try:
        yield opened
    finally:
        opened.close()


@pytest.fixture
def signed(session: Session) -> Mandate:
    """The genuine article, signed by this instance's own key."""
    unsigned = Mandate.model_validate_json(EXAMPLE.read_text(encoding="utf-8"))
    return sign(unsigned, session.signer)


@pytest.fixture
def forged(signed: Mandate) -> Mandate:
    """The signature replaced wholesale. Schema-valid, cryptographically junk.

    Replacing the signature rather than editing a field on purpose: an edit
    could be caught by something other than signature verification, and then
    this test would pass for the wrong reason.
    """
    document = signed.model_dump(mode="json", by_alias=True)
    document["signature"]["sig"] = "A" * 86
    altered = Mandate.model_validate(document)
    assert altered.signature is not None
    assert altered.signature.sig != signed.signature.sig if signed.signature else True
    return altered


class TestTheRuntimeVerifies:
    def test_a_forged_mandate_is_refused(self, session: Session, forged: Mandate) -> None:
        """The regression. Before the fix this decided REQUIRE_APPROVAL."""
        with pytest.raises(MandateError) as caught:
            check_proposal(session, proposal("F1"), mandate=forged)
        assert "does not match its signature" in str(caught.value)

    def test_the_refusal_says_something(self, session: Session, forged: Mandate) -> None:
        """`InvalidSignature` stringifies to nothing, so interpolating it gave
        "does not match its signature: " with an empty tail -- on the one
        refusal where an operator most needs to be told what happened."""
        with pytest.raises(MandateError) as caught:
            check_proposal(session, proposal("F2"), mandate=forged)
        message = str(caught.value)
        assert not message.rstrip().endswith(":")
        assert "changed after it was signed" in message

    def test_an_unsigned_mandate_is_refused(self, session: Session) -> None:
        unsigned = Mandate.model_validate_json(EXAMPLE.read_text(encoding="utf-8"))
        with pytest.raises(MandateError) as caught:
            check_proposal(session, proposal("U1"), mandate=unsigned)
        assert "carries no signature" in str(caught.value)

    def test_a_mandate_signed_by_an_unheld_key_is_refused(
        self, session: Session, tmp_path: Path
    ) -> None:
        """An unknown `key_id` is a failure, not a skip. A mandate this instance
        cannot vouch for must not be treated as "probably fine"."""
        stranger = FileSigner.generate()
        unsigned = Mandate.model_validate_json(EXAMPLE.read_text(encoding="utf-8"))
        with pytest.raises(MandateError) as caught:
            check_proposal(session, proposal("K1"), mandate=sign(unsigned, stranger))
        assert "does not hold" in str(caught.value)

    def test_the_genuine_mandate_still_decides(self, session: Session, signed: Mandate) -> None:
        """The other half. A fix that refused everything would pass every test
        above and break every unattended agent."""
        outcome = check_proposal(session, proposal("G1"), mandate=signed)
        assert outcome.verdict.decision is not None
        hits = {hit.rule_id for hit in outcome.verdict.hits}
        assert "AG-IDN-007" not in hits, "the mandate was not accepted as an authority"

    def test_without_a_mandate_the_unattended_action_blocks(self, session: Session) -> None:
        """The contrast that makes the forgery a forgery: this is what the
        forged mandate was converting into a decision."""
        from qed.core.schemas import Decision

        outcome = check_proposal(session, proposal("N1"))
        assert outcome.verdict.decision is Decision.BLOCK
        assert "AG-IDN-007" in {hit.rule_id for hit in outcome.verdict.hits}

    def test_nothing_was_written_for_the_refused_proposal(
        self, session: Session, forged: Mandate
    ) -> None:
        """A refused mandate must not leave a half-decided proposal behind.

        Verification happens before the proposal record is appended, so the id
        stays unused and the agent can retry with a real mandate. If it ran
        after the append, the retry would be a 409 on an id that was never
        decided.
        """
        with pytest.raises(MandateError):
            check_proposal(session, proposal("W1"), mandate=forged)
        assert not session.store.proposal_exists("01JB0000000000000000MANDAW1")


class TestEveryEntryPointGoesThroughIt:
    """`check_proposal` is the choke point, and this asserts it stays the only
    way in.

    Seven places parse a mandate from untrusted bytes. Verifying at each of them
    is seven chances to forget, and the eighth caller would be the one that got
    it wrong -- so the check lives at the single function all of them call.
    """

    #: Modules that may build an `EvalContext` with a mandate without
    #: verifying it, each with the reason. Both hold no keys, and both are
    #: dry-runs that write nothing to the chain. Anything else added here needs
    #: an argument for why an unverified mandate is acceptable in it.
    EXEMPT = {
        # `qed policy explain` takes no `--dir`, so there is no `public/`
        # directory to check against. It now prints a warning saying the
        # signature was not verified, which is the honest version: its JSON
        # reports `"mandate": {"present": true}` either way.
        "qed/cli.py": "policy explain is a dry-run with no keys, and says so",
        # Policy test fixtures. `qed policy test` is about rule logic, and
        # requiring a real signature on every fixture mandate would mean
        # shipping a private key with the test cases.
        "qed/core/policy/cases.py": "policy test fixtures are unsigned by design",
    }

    def test_no_consumer_builds_a_verdict_around_check_proposal(self) -> None:
        """Nothing may call `evaluate` with a mandate except via the runtime.

        `evaluate` is pure and holds no keys, so a caller that reaches past
        `check_proposal` into the engine with an `EvalContext(mandate=...)`
        bypasses verification entirely. Only `qed/runtime.py` builds one with a
        mandate in it, plus the two keyless dry-runs in `EXEMPT`.

        This found both of those on its first run, which is the point: the fix
        went into `check_proposal` and two other paths were still reaching past
        it.
        """
        offenders = []
        for path in sorted((ROOT / "qed").rglob("*.py")):
            if path.name == "runtime.py":
                continue
            relative = path.relative_to(ROOT).as_posix()
            if relative in self.EXEMPT:
                continue
            text = path.read_text(encoding="utf-8")
            if "EvalContext(" in text and "mandate=" in text:
                offenders.append(relative)
        assert not offenders, (
            "these modules build an EvalContext with a mandate, bypassing "
            f"signature verification in check_proposal: {offenders}"
        )

    def test_the_exemptions_are_still_real(self) -> None:
        """An exemption for a file that no longer qualifies is a hole.

        If one of these stops building an `EvalContext` with a mandate, the
        entry should go -- otherwise it silently covers whatever that file does
        next.
        """
        for relative in self.EXEMPT:
            text = (ROOT / relative).read_text(encoding="utf-8")
            assert "EvalContext(" in text and "mandate=" in text, (
                f"{relative} is exempt and no longer builds an unverified "
                "EvalContext; remove it from EXEMPT"
            )

    def test_explain_admits_it_did_not_verify(self) -> None:
        """The exemption above is only acceptable because of this sentence."""
        text = (ROOT / "qed" / "cli.py").read_text(encoding="utf-8")
        assert "was NOT verified" in text

    def test_the_cli_reports_it_as_an_operator_error(self) -> None:
        """Not a traceback. A forged mandate is the most load-bearing refusal
        the CLI makes, and a stack trace would make it look like a crash --
        which this project has shipped twice already (`docs/validation.md`)."""
        from qed.cli import OPERATOR_ERRORS

        assert MandateError in OPERATOR_ERRORS
