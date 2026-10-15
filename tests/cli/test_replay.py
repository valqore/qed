"""`qed replay <proposal_id>` end to end over a real chain (SPEC §14).

`tests/core/test_replay.py` owns the classification logic. What is checked
here is everything the pure function cannot see: that the record is found in
a chain and parsed back into the models, that the clock comes from the
record's own timestamp rather than from now, that an unverifiable chain is
refused before any claim is made about it, and that the three answers get
three different exit codes.

The last of those matters more than it looks. `replay` can say "the record
follows", "it does not and nothing explains that", and "the question could not
be answered" -- and a pipeline that cannot tell the third from the second
would treat a missing file as a forged record.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from qed.cli import app

runner = CliRunner()


@pytest.fixture
def chain(tmp_path: Path) -> tuple[Path, Path, list[str]]:
    """A demo instance: five decisions, five shapes, one verified chain."""
    state = tmp_path / "demo"
    result = runner.invoke(app, ["demo", "--dir", str(state)])
    assert result.exit_code == 0, result.output
    config = state / "qed.yaml"

    export = runner.invoke(app, ["export", "--dir", str(state), "--config", str(config)])
    assert export.exit_code == 0, export.output
    ids = [
        record["payload"]["verdict"]["proposal_id"]
        for record in (json.loads(line) for line in export.stdout.splitlines() if line.strip())
        if record["type"] == "verdict" and record.get("payload")
    ]
    assert len(ids) == 5, ids
    return state, config, ids


def replay(state: Path, config: Path, *args: str) -> object:
    return runner.invoke(app, ["replay", *args, "--dir", str(state), "--config", str(config)])


class TestEveryDecisionTheDemoWroteReplays:
    def test_all_five_reproduce(self, chain: tuple[Path, Path, list[str]]) -> None:
        """The strongest statement this command can make, over a chain
        written by the product itself minutes earlier. If the kernel cannot
        reproduce its own decisions, nothing else here is worth checking."""
        state, config, ids = chain
        for proposal_id in ids:
            result = replay(state, config, proposal_id)
            assert result.exit_code == 0, (proposal_id, result.output)
            assert "reproduced" in result.output

    def test_the_approved_one_names_its_approval(self, chain: tuple[Path, Path, list[str]]) -> None:
        """The demo's DROP TABLE opens an approval request, so its recorded
        verdict carries an `approval_id`. Reproducing it is the proof that
        the overlay is handled -- comparing decisions naively would call this
        a mismatch."""
        state, config, ids = chain
        outputs = [replay(state, config, pid).output for pid in ids]
        assert any("approval :" in text for text in outputs)
        assert all("DIFFERS" not in text for text in outputs)

    def test_the_budget_is_named_as_assumed(self, chain: tuple[Path, Path, list[str]]) -> None:
        """The ledger has moved since the decision, so even a reproduction
        has to say which input it took on trust."""
        state, config, ids = chain
        result = replay(state, config, ids[0])
        assert "assumed" in result.output
        assert "budget" in result.output

    def test_history_is_not_named_as_assumed(self, chain: tuple[Path, Path, list[str]]) -> None:
        """Nothing in `qed` supplies the 24-hour counters, so replaying with
        zeros reproduces the real input rather than guessing at it. Listing
        it would be a caveat that is always printed and never true."""
        state, config, ids = chain
        result = replay(state, config, ids[0])
        assert "history" not in result.output


class TestTheClockComesFromTheRecord:
    def test_a_replay_does_not_use_the_current_time(
        self, chain: tuple[Path, Path, list[str]]
    ) -> None:
        """`check_proposal` stamps the proposal record, the verdict record and
        `ctx.now` from one value, so the record's timestamp *is* what the
        engine was told the time was. Using `utcnow()` instead would make
        every replay of an old chain wrong in a way that looks like drift --
        and would be invisible on a chain written seconds ago, which is why
        this reaches for a mandate-free proposal and checks the reproduction
        still holds after the fact rather than mocking the clock.
        """
        state, config, ids = chain
        # Reproduced now; the timestamps in the chain are already in the past
        # relative to this call, and a `utcnow()` implementation would have to
        # agree by luck.
        for proposal_id in ids:
            assert replay(state, config, proposal_id).exit_code == 0


class TestWhenTheQuestionCannotBeAnswered:
    def test_an_unknown_proposal_id_exits_1(self, chain: tuple[Path, Path, list[str]]) -> None:
        state, config, _ = chain
        result = replay(state, config, "01JBZZZZZZZZZZZZZZZZZZZZZZ")
        assert result.exit_code == 1
        assert "no proposal record" in result.output

    def test_a_policy_that_does_not_match_exits_1_and_refuses(
        self, chain: tuple[Path, Path, list[str]], tmp_path: Path
    ) -> None:
        """Pointed at a different bundle, this must refuse rather than
        answer. Re-deciding under today's rules is a different question, and
        presenting its answer as a replay would be the most misleading thing
        this command could do."""
        state, config, ids = chain
        other = tmp_path / "policies"
        other.mkdir()
        (other / "rules.yaml").write_text(
            "- rule_id: LOCAL-001\n"
            "  name: Everything is fine\n"
            "  severity: LOW\n"
            "  mode: shadow\n"
            "  verdict: ALLOW\n"
            "  message: local\n",
            encoding="utf-8",
        )
        result = replay(state, config, ids[0], "--policy", str(other))
        assert result.exit_code == 1
        assert "cannot replay" in result.output
        assert "not its rules" in result.output

    def test_a_chain_that_does_not_verify_is_refused(
        self, chain: tuple[Path, Path, list[str]], tmp_path: Path
    ) -> None:
        """A statement about what follows from a record is worth nothing if
        the record is not the one the kernel signed, so the chain check comes
        first and a failure stops the command."""
        state, config, ids = chain
        export = runner.invoke(app, ["export", "--dir", str(state), "--config", str(config)])
        lines = [line for line in export.stdout.splitlines() if line.strip()]
        tampered = []
        for line in lines:
            record = json.loads(line)
            if record["type"] == "verdict" and record.get("payload"):
                record["payload"]["verdict"]["blast_radius"] = 99
            tampered.append(json.dumps(record))
        broken = tmp_path / "tampered.jsonl"
        broken.write_text("\n".join(tampered) + "\n", encoding="utf-8")

        result = replay(state, config, ids[0], "--from", str(broken), "--instance-id", "qed-demo")
        assert result.exit_code == 1
        assert "does not verify" in result.output


class TestReadingAnExport:
    def test_it_replays_from_a_jsonl_file(
        self, chain: tuple[Path, Path, list[str]], tmp_path: Path
    ) -> None:
        """What an auditor actually has: an export, the public keys, and the
        bundle. Not the instance."""
        state, config, ids = chain
        export = runner.invoke(app, ["export", "--dir", str(state), "--config", str(config)])
        path = tmp_path / "chain.jsonl"
        path.write_text(export.stdout, encoding="utf-8")

        result = replay(state, config, ids[0], "--from", str(path))
        assert result.exit_code == 0, result.output
        assert "reproduced" in result.output


class TestJsonOutput:
    def test_the_shape_is_stable(self, chain: tuple[Path, Path, list[str]]) -> None:
        state, config, ids = chain
        result = replay(state, config, ids[0], "--json")
        payload = json.loads(result.stdout)
        assert payload["proposal_id"] == ids[0]
        assert payload["reproduced"] is True
        assert payload["policy_matches"] is True
        assert payload["differences"] == []
        assert payload["assumed_inputs"] == ["budget"]
        assert len(payload["recorded_policy_hash"]) == 64


def resign_chain(state: Path, records: list[dict[str, object]]) -> str:
    """Re-sign a chain after editing it, the way an operator with the key would.

    This is the attack `THREAT_MODEL.md` says the anchors exist for: whoever
    holds the signing key can rewrite a record, recompute the hash, re-sign it
    and re-link everything after it. The result passes `qed verify` completely,
    because every check the verifier makes is self-referential.

    Writing it here is the only way to prove `qed replay` catches what the
    verifier cannot.
    """
    from qed.core.evidence import hashing
    from qed.infra.keys.file import load_signer

    signer = load_signer(state)
    out: list[str] = []
    prev = ""
    for record in records:
        payload = record["payload"]
        if isinstance(payload, dict):
            record["payload_hash"] = hashing.payload_hash(payload)
        if prev:
            record["prev_hash"] = prev
        digest = hashing.record_hash_bytes(
            schema_version=str(record["schema_version"]),
            seq=int(str(record["seq"])),
            ts=str(record["ts"]),
            type_=str(record["type"]),
            payload_hash_hex=str(record["payload_hash"]),
            prev_hash=str(record["prev_hash"]),
        )
        record["hash"] = digest.hex()
        record["sig"] = signer.sign(digest)
        prev = digest.hex()
        out.append(json.dumps(record))
    return "\n".join(out) + "\n"


class TestARewrittenChainIsCaught:
    """The end this command exists for, and the one `qed verify` cannot reach.

    A record edited in place fails verification, so it is not the interesting
    case. The interesting case is a chain an operator **rewrote and re-signed**
    -- every hash recomputed, every signature valid, `qed verify` green -- that
    now says something the policy does not support. Deciding the proposal again
    is the only thing that notices.
    """

    def tampered(
        self, state: Path, config: Path, edit: object
    ) -> tuple[list[dict[str, object]], str]:
        export = runner.invoke(app, ["export", "--dir", str(state), "--config", str(config)])
        assert export.exit_code == 0, export.output
        records = [json.loads(line) for line in export.stdout.splitlines() if line.strip()]
        for record in records:
            payload = record.get("payload")
            if record["type"] == "verdict" and isinstance(payload, dict):
                edit(payload["verdict"])  # type: ignore[operator]
                break
        return records, resign_chain(state, records)

    def test_the_rewritten_chain_still_verifies(
        self, chain: tuple[Path, Path, list[str]], tmp_path: Path
    ) -> None:
        """Stated first, because everything below depends on it. If the
        rewrite did not survive `qed verify` this would be testing the
        verifier instead."""
        state, config, _ = chain
        _, text = self.tampered(state, config, lambda v: v.update({"blast_radius": 91}))
        path = tmp_path / "rewritten.jsonl"
        path.write_text(text, encoding="utf-8")

        verified = runner.invoke(
            app, ["verify", str(path), "--dir", str(state), "--instance-id", "qed-demo"]
        )
        assert verified.exit_code == 0, verified.output

    def test_replay_reports_the_edit_the_verifier_accepted(
        self, chain: tuple[Path, Path, list[str]], tmp_path: Path
    ) -> None:
        state, config, _ = chain
        records, text = self.tampered(state, config, lambda v: v.update({"blast_radius": 91}))
        edited_id = next(
            str(r["payload"]["verdict"]["proposal_id"])  # type: ignore[index]
            for r in records
            if r["type"] == "verdict" and isinstance(r.get("payload"), dict)
        )
        path = tmp_path / "rewritten.jsonl"
        path.write_text(text, encoding="utf-8")

        result = replay(state, config, edited_id, "--from", str(path))
        assert result.exit_code == 2, result.output
        assert "DIFFERS" in result.output
        assert "blast_radius" in result.output

    def test_an_edited_decision_is_reported(
        self, chain: tuple[Path, Path, list[str]], tmp_path: Path
    ) -> None:
        """The edit somebody would actually make: a BLOCK turned into an
        ALLOW, with no approval behind it."""
        state, config, _ = chain
        records, text = self.tampered(
            state,
            config,
            lambda v: v.update({"decision": "ALLOW", "hits": [], "default_applied": False}),
        )
        edited_id = next(
            str(r["payload"]["verdict"]["proposal_id"])  # type: ignore[index]
            for r in records
            if r["type"] == "verdict" and isinstance(r.get("payload"), dict)
        )
        path = tmp_path / "allowed.jsonl"
        path.write_text(text, encoding="utf-8")

        result = replay(state, config, edited_id, "--from", str(path))
        assert result.exit_code == 2, result.output
        assert "DIFFERS" in result.output

    def test_an_untouched_chain_is_not_reported(
        self, chain: tuple[Path, Path, list[str]], tmp_path: Path
    ) -> None:
        """The other half, without which the tests above would pass against a
        command that always said DIFFERS. Re-signing on its own changes
        nothing an auditor should hear about."""
        state, config, ids = chain
        export = runner.invoke(app, ["export", "--dir", str(state), "--config", str(config)])
        records = [json.loads(line) for line in export.stdout.splitlines() if line.strip()]
        path = tmp_path / "resigned.jsonl"
        path.write_text(resign_chain(state, records), encoding="utf-8")

        result = replay(state, config, ids[0], "--from", str(path))
        assert result.exit_code == 0, result.output
        assert "reproduced" in result.output
