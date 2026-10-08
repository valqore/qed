"""The week 1 exit criterion, as a test (SPEC §22).

`gate check proposal.json` -> signed chain -> `gate-verify` passes.

Everything here goes through the real CLI, the real SQLite store and the real
standalone verifier. No mocks: the thing being asserted is that the pieces fit
together, and a mock cannot fail in the way they would.
"""

from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from gate.cli import app
from gate.core.schemas import Decision

runner = CliRunner()
EXAMPLE = Path(__file__).resolve().parents[2] / "examples" / "proposals" / "prod-db-drop.json"

ALLOW_EXIT, APPROVAL_EXIT, BLOCK_EXIT, ERROR_EXIT = 0, 2, 3, 1


def write_proposal(path: Path, patch: dict[str, object] | None = None) -> Path:
    from tests.conftest import BASE_PROPOSAL, deep_merge

    path.write_text(json.dumps(deep_merge(BASE_PROPOSAL, patch or {})), encoding="utf-8")
    return path


def config(path: Path, **values: object) -> Path:
    import yaml

    path.write_text(yaml.safe_dump(values), encoding="utf-8")
    return path


class TestKeysInit:
    def test_creates_a_key_pair(self, tmp_path: Path) -> None:
        result = runner.invoke(app, ["keys", "init", "--dir", str(tmp_path / "g")])
        assert result.exit_code == 0, result.output
        assert "key_id : ed25519:" in result.output
        assert (tmp_path / "g" / "evidence-key.pem").exists()
        assert list((tmp_path / "g" / "public").glob("*.pem"))

    def test_the_public_key_filename_is_path_safe(self, tmp_path: Path) -> None:
        """`key_id` contains a colon, which is not a legal Windows filename."""
        runner.invoke(app, ["keys", "init", "--dir", str(tmp_path / "g")])
        names = [p.name for p in (tmp_path / "g" / "public").glob("*.pem")]
        assert names and all(":" not in name for name in names)

    def test_refuses_to_overwrite_an_existing_key(self, tmp_path: Path) -> None:
        directory = str(tmp_path / "g")
        runner.invoke(app, ["keys", "init", "--dir", directory])
        result = runner.invoke(app, ["keys", "init", "--dir", directory])
        assert result.exit_code == ERROR_EXIT
        assert "refusing to overwrite" in result.output

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX mode bits are advisory on Windows")
    def test_the_private_key_is_not_world_readable(self, tmp_path: Path) -> None:
        runner.invoke(app, ["keys", "init", "--dir", str(tmp_path / "g")])
        mode = os.stat(tmp_path / "g" / "evidence-key.pem").st_mode
        assert not mode & (stat.S_IRGRP | stat.S_IROTH)

    def test_export_public_prints_a_pem(self, tmp_path: Path) -> None:
        directory = str(tmp_path / "g")
        runner.invoke(app, ["keys", "init", "--dir", directory])
        result = runner.invoke(app, ["keys", "export-public", "--dir", directory])
        assert result.exit_code == 0
        assert "BEGIN PUBLIC KEY" in result.output


class TestCheck:
    def test_refuses_to_run_without_a_signing_key(self, tmp_path: Path) -> None:
        proposal = write_proposal(tmp_path / "p.json")
        result = runner.invoke(app, ["check", str(proposal), "--dir", str(tmp_path / "nokeys")])
        assert result.exit_code == ERROR_EXIT
        assert "gate keys init" in result.output

    def test_a_read_in_dev_is_allowed(self, gate_dir: Path, tmp_path: Path) -> None:
        proposal = write_proposal(tmp_path / "p.json")
        result = runner.invoke(app, ["check", str(proposal), "--dir", str(gate_dir)])
        assert result.exit_code == ALLOW_EXIT, result.output
        assert "ALLOW" in result.output

    def test_shadow_mode_records_but_does_not_enforce(self, gate_dir: Path, tmp_path: Path) -> None:
        proposal = write_proposal(
            tmp_path / "p.json",
            {"action": {"params_redacted": {"cidr": "0.0.0.0/0"}}},
        )
        result = runner.invoke(app, ["check", str(proposal), "--dir", str(gate_dir)])
        assert "BLOCK" in result.output
        assert "shadow mode" in result.output
        assert result.exit_code == ALLOW_EXIT

    def test_enforce_mode_returns_the_block_exit_code(self, gate_dir: Path, tmp_path: Path) -> None:
        proposal = write_proposal(
            tmp_path / "p.json",
            {"action": {"params_redacted": {"cidr": "0.0.0.0/0"}}},
        )
        cfg = config(tmp_path / "gate.yaml", mode="enforce", instance_id="t")
        result = runner.invoke(
            app,
            ["check", str(proposal), "--dir", str(gate_dir), "--config", str(cfg)],
        )
        assert result.exit_code == BLOCK_EXIT, result.output
        assert "shadow mode" not in result.output

    def test_approval_has_its_own_exit_code(self, gate_dir: Path, tmp_path: Path) -> None:
        proposal = write_proposal(
            tmp_path / "p.json",
            {
                "context": {
                    "environment": "prod",
                    "blast_radius_hints": {"deletes": True},
                }
            },
        )
        cfg = config(tmp_path / "gate.yaml", mode="enforce", instance_id="t")
        result = runner.invoke(
            app,
            ["check", str(proposal), "--dir", str(gate_dir), "--config", str(cfg)],
        )
        assert result.exit_code == APPROVAL_EXIT, result.output

    def test_json_output_carries_the_verdict_and_the_evidence_sequence(
        self, gate_dir: Path, tmp_path: Path
    ) -> None:
        proposal = write_proposal(tmp_path / "p.json")
        result = runner.invoke(app, ["check", str(proposal), "--dir", str(gate_dir), "--json"])
        payload = json.loads(result.output)
        assert payload["verdict"]["decision"] == Decision.ALLOW.value
        assert payload["effective_decision"] == Decision.ALLOW.value
        assert payload["enforced"] is False
        # policy_loaded, proposal, verdict -> genesis is 0
        assert payload["evidence_seq"] == [2, 3]

    def test_the_same_proposal_id_cannot_be_decided_twice(
        self, gate_dir: Path, tmp_path: Path
    ) -> None:
        proposal = write_proposal(tmp_path / "p.json")
        first = runner.invoke(app, ["check", str(proposal), "--dir", str(gate_dir)])
        assert first.exit_code == ALLOW_EXIT
        second = runner.invoke(app, ["check", str(proposal), "--dir", str(gate_dir)])
        assert second.exit_code == ERROR_EXIT
        assert "already been decided" in second.output

    def test_a_broken_policy_file_stops_the_decision(self, gate_dir: Path, tmp_path: Path) -> None:
        policy = tmp_path / "policy"
        policy.mkdir()
        (policy / "bad.yaml").write_text(
            "- rule_id: TT-BAD-001\n"
            "  name: Bad\n"
            "  message: Bad\n"
            "  verdict: BLOCK\n"
            "  when: {field: action.nmae, equals: x}\n",
            encoding="utf-8",
        )
        proposal = write_proposal(tmp_path / "p.json")
        result = runner.invoke(
            app,
            ["check", str(proposal), "--dir", str(gate_dir), "--policy", str(policy)],
        )
        assert result.exit_code == ERROR_EXIT
        assert "unknown field path" in result.output
        assert "refusing to decide" in result.output

    def test_a_missing_proposal_file_is_a_clean_error(self, gate_dir: Path) -> None:
        result = runner.invoke(app, ["check", "nope.json", "--dir", str(gate_dir)])
        assert result.exit_code == ERROR_EXIT
        assert "cannot read proposal" in result.output

    def test_the_shipped_example_decides_as_documented(self, gate_dir: Path) -> None:
        result = runner.invoke(app, ["check", str(EXAMPLE), "--dir", str(gate_dir), "--json"])
        payload = json.loads(result.output)
        assert payload["verdict"]["decision"] == Decision.REQUIRE_APPROVAL.value
        assert payload["verdict"]["blast_radius"] == 75
        hits = {h["rule_id"] for h in payload["verdict"]["hits"]}
        # AG-BUD-005 is a shadow hit: the demo token carries no budget, which
        # is worth saying in production and does not change the decision. The
        # two enforce hits are what the verdict rests on.
        assert hits == {"AG-BLR-003", "AG-BLR-005", "AG-BUD-005"}


class TestPolicy:
    def test_lint_passes_on_the_shipped_pack(self) -> None:
        result = runner.invoke(app, ["policy", "lint"])
        assert result.exit_code == 0, result.output
        assert "46 rules (46 active)" in result.output
        assert "ok" in result.output

    def test_lint_fails_on_a_broken_rule(self, tmp_path: Path) -> None:
        (tmp_path / "bad.yaml").write_text(
            "- rule_id: TT-BAD-001\n  name: n\n  message: m\n  verdict: ALLOW\n",
            encoding="utf-8",
        )
        result = runner.invoke(app, ["policy", "lint", "--policy", str(tmp_path)])
        assert result.exit_code == 1
        assert "allow_rule" in result.output

    def test_explain_shows_the_blast_radius_arithmetic(self, tmp_path: Path) -> None:
        proposal = write_proposal(tmp_path / "p.json", {"context": {"environment": "prod"}})
        result = runner.invoke(app, ["policy", "explain", str(proposal)])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.output)
        reasons = [c["reason"] for c in payload["blast_radius_contributions"]]
        assert "environment=prod" in reasons
        assert payload["verdict"]["blast_radius"] == 25

    def test_explain_writes_nothing_to_the_chain(self, gate_dir: Path, tmp_path: Path) -> None:
        proposal = write_proposal(tmp_path / "p.json")
        runner.invoke(app, ["policy", "explain", str(proposal)])
        assert not (gate_dir / "gate.db").exists()


class TestExportAndVerify:
    def _decide(self, gate_dir: Path, tmp_path: Path) -> None:
        for i in range(3):
            proposal = write_proposal(
                tmp_path / f"p{i}.json", {"id": f"01JB000000000000000000000{i}"}
            )
            runner.invoke(app, ["check", str(proposal), "--dir", str(gate_dir)])

    def test_export_then_verify_round_trip(self, gate_dir: Path, tmp_path: Path) -> None:
        self._decide(gate_dir, tmp_path)
        out = tmp_path / "chain.jsonl"
        export = runner.invoke(app, ["export", "--dir", str(gate_dir), "--out", str(out)])
        assert export.exit_code == 0, export.output
        lines = out.read_text(encoding="utf-8").splitlines()
        assert len(lines) == 8  # genesis + policy_loaded + 3 x (proposal, verdict)

        from gate_verify.cli import main as verify_main

        assert verify_main([str(out), "--keys", str(gate_dir / "public"), "--json"]) == 0

    def test_gate_verify_wrapper_verifies_the_local_chain(
        self, gate_dir: Path, tmp_path: Path
    ) -> None:
        self._decide(gate_dir, tmp_path)
        result = runner.invoke(app, ["verify", "--dir", str(gate_dir)])
        assert result.exit_code == 0, result.output
        assert "OK" in result.output

    def test_verify_fails_on_a_tampered_export(self, gate_dir: Path, tmp_path: Path) -> None:
        self._decide(gate_dir, tmp_path)
        out = tmp_path / "chain.jsonl"
        runner.invoke(app, ["export", "--dir", str(gate_dir), "--out", str(out)])
        lines = out.read_text(encoding="utf-8").splitlines()
        index, record = next(
            (i, json.loads(line))
            for i, line in enumerate(lines)
            if json.loads(line)["type"] == "verdict"
        )
        assert record["payload"]["verdict"]["decision"] != "BLOCK"
        record["payload"]["verdict"]["decision"] = "BLOCK"
        lines[index] = json.dumps(record)
        out.write_text("\n".join(lines) + "\n", encoding="utf-8")

        result = runner.invoke(app, ["verify", str(out), "--dir", str(gate_dir)])
        assert result.exit_code == 1
        assert "payload_tampered" in result.output

    def test_csv_export_has_a_header_and_one_row_per_record(
        self, gate_dir: Path, tmp_path: Path
    ) -> None:
        self._decide(gate_dir, tmp_path)
        result = runner.invoke(app, ["export", "--dir", str(gate_dir), "--format", "csv"])
        rows = result.output.strip().splitlines()
        assert rows[0].startswith("seq,ts,type")
        assert len(rows) == 9

    def test_an_unsupported_export_format_is_refused(self, gate_dir: Path) -> None:
        result = runner.invoke(app, ["export", "--dir", str(gate_dir), "--format", "sarif"])
        assert result.exit_code == ERROR_EXIT
        assert "jsonl, csv or oscal" in result.output

    def test_oscal_export_is_a_parseable_assessment_results_document(
        self, gate_dir: Path, tmp_path: Path
    ) -> None:
        self._decide(gate_dir, tmp_path)
        result = runner.invoke(app, ["export", "--dir", str(gate_dir), "--format", "oscal"])
        assert result.exit_code == 0, result.output
        document = json.loads(result.output)["assessment-results"]
        assert document["metadata"]["oscal-version"] == "1.1.2"
        assert len(document["results"][0]["observations"]) == 8
        assert document["results"][0]["findings"]

    def test_oscal_export_is_byte_identical_when_repeated(
        self, gate_dir: Path, tmp_path: Path
    ) -> None:
        """Derived UUIDs, so two auditors with two copies agree (SPEC 10.8)."""
        self._decide(gate_dir, tmp_path)
        first = runner.invoke(app, ["export", "--dir", str(gate_dir), "--format", "oscal"])
        second = runner.invoke(app, ["export", "--dir", str(gate_dir), "--format", "oscal"])
        one = json.loads(first.output)["assessment-results"]
        two = json.loads(second.output)["assessment-results"]
        # `last-modified` is the one value taken from the clock.
        one["metadata"].pop("last-modified")
        two["metadata"].pop("last-modified")
        assert json.dumps(one, sort_keys=True) == json.dumps(two, sort_keys=True)

    def test_status_reports_the_chain_and_the_policy(self, gate_dir: Path, tmp_path: Path) -> None:
        self._decide(gate_dir, tmp_path)
        result = runner.invoke(app, ["status", "--dir", str(gate_dir)])
        payload = json.loads(result.output)
        assert payload["records"] == 8
        assert payload["rules_active"] == 46
        assert payload["mode"] == "shadow"
        assert payload["key_id"].startswith("ed25519:")

    def test_checkpoint_then_verify(self, gate_dir: Path, tmp_path: Path) -> None:
        self._decide(gate_dir, tmp_path)
        made = runner.invoke(app, ["checkpoint", "--dir", str(gate_dir), "--force"])
        assert made.exit_code == 0, made.output
        assert "checkpoint seq 8" in made.output
        assert runner.invoke(app, ["verify", "--dir", str(gate_dir)]).exit_code == 0


def test_a_policy_loaded_record_is_written_once_per_bundle(gate_dir: Path, tmp_path: Path) -> None:
    for i in range(2):
        proposal = write_proposal(tmp_path / f"p{i}.json", {"id": f"01JB00000000000000000000A{i}"})
        runner.invoke(app, ["check", str(proposal), "--dir", str(gate_dir)])
    out = tmp_path / "chain.jsonl"
    runner.invoke(app, ["export", "--dir", str(gate_dir), "--out", str(out)])
    types = [json.loads(line)["type"] for line in out.read_text(encoding="utf-8").splitlines()]
    assert types.count("policy_loaded") == 1


def test_config_reports_the_sections_it_does_not_honour_yet(tmp_path: Path) -> None:
    from gate.config import load_config

    cfg = config(
        tmp_path / "gate.yaml",
        instance_id="acme",
        mode="enforce",
        identity={"provider": "okta"},
        ui={"enabled": True},
    )
    loaded = load_config(cfg)
    assert loaded.config.instance_id == "acme"
    # `approvals` left this list in week 4 and `broker` in week 5: both are
    # honoured now, and a section reported as ignored while it is in force
    # would be worse than silence.
    assert loaded.ignored_sections == ["identity", "ui"]
