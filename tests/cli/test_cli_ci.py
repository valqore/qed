"""``qed check`` in CI (SPEC §12.5).

Three things a pipeline depends on, and none of them is the verdict text:

* **the exit code**, because that is what fails the build;
* **`--server`**, so the decision and its evidence live on the team's instance
  rather than in a workspace that is deleted with the job;
* **`--evidence-out`**, for when there is no server and the chain would
  otherwise vanish with the runner.

The `--server` tests start a real `qed serve` subprocess and run the real CLI
against it over a loopback socket. A mock would assert that the code calls the
function it calls; what is in question here is whether a signed request built
by the CLI is one the API accepts, which only two processes can answer.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from collections.abc import Iterator
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from qed.cli import app
from qed.infra.keys.file import init_keys
from tests.api.test_serve import STARTUP_TIMEOUT, free_port, wait_for

runner = CliRunner()
REPO = Path(__file__).resolve().parents[2]

# SPEC §12.5, written out rather than imported: a CI job writes these numbers
# out too, so changing the constants has to fail a test rather than quietly
# agree with itself.
ALLOW_EXIT, BLOCK_EXIT, APPROVAL_EXIT, ERROR_EXIT = 0, 2, 3, 1

ADAPTER_ID = "adp_ci"
SECRET_ENV = "QED_TEST_CI_SECRET"
SECRET = "c" * 48


def write_proposal(path: Path, patch: dict[str, object] | None = None) -> Path:
    from tests.conftest import BASE_PROPOSAL, deep_merge

    path.write_text(json.dumps(deep_merge(BASE_PROPOSAL, patch or {})), encoding="utf-8")
    return path


#: A world-open security group: an unconditional BLOCK in the baseline pack, so
#: the enforce cases below exit 2 rather than landing on an approval.
OPEN_TO_THE_WORLD: dict[str, object] = {
    "action": {"params_redacted": {"cidr": "0.0.0.0/0"}},
}

#: Scores high enough in production to need a human, which is exit 3.
PROD_DROP: dict[str, object] = {
    "action": {
        "name": "postgres.execute_sql",
        "target": "db:prod/orders",
        "params_redacted": {"sql": "DROP TABLE orders_archive;"},
    },
    "context": {
        "environment": "prod",
        "blast_radius_hints": {"writes": True, "deletes": True, "scope": "single_resource"},
    },
}


# --------------------------------------------------------------------------
# Exit codes
# --------------------------------------------------------------------------


class TestTheExitCodesAreTheContract:
    """SPEC §12.5: 0 ALLOW, 2 BLOCK, 3 REQUIRE_APPROVAL, 1 error.

    These numbers end up inside somebody's `if [ $? -eq 2 ]`, so they are
    tested as values rather than as "nonzero".
    """

    def test_allow_is_zero(self, qed_dir: Path, tmp_path: Path) -> None:
        proposal = write_proposal(tmp_path / "p.json", {"action": {"name": "list_buckets"}})
        result = runner.invoke(app, ["check", str(proposal), "--dir", str(qed_dir)])
        assert result.exit_code == ALLOW_EXIT, result.output

    def test_block_is_two(self, qed_dir: Path, tmp_path: Path) -> None:
        config = tmp_path / "qed.yaml"
        config.write_text(yaml.safe_dump({"mode": "enforce"}), encoding="utf-8")
        proposal = write_proposal(tmp_path / "p.json", OPEN_TO_THE_WORLD)
        result = runner.invoke(
            app, ["check", str(proposal), "--dir", str(qed_dir), "--config", str(config)]
        )
        assert result.exit_code == BLOCK_EXIT, result.output
        assert "BLOCK" in result.output

    def test_an_approval_is_three(self, qed_dir: Path, tmp_path: Path) -> None:
        """Its own code, not 2. A build stopped because a person has to look at
        it is a different state from one stopped because a policy said no, and
        a pipeline that wants to wait rather than fail needs to tell them
        apart."""
        config = tmp_path / "qed.yaml"
        config.write_text(yaml.safe_dump({"mode": "enforce"}), encoding="utf-8")
        proposal = write_proposal(tmp_path / "p.json", PROD_DROP)
        result = runner.invoke(
            app, ["check", str(proposal), "--dir", str(qed_dir), "--config", str(config)]
        )
        assert result.exit_code == APPROVAL_EXIT, result.output

    def test_a_malfunction_is_one_and_not_a_refusal(self, tmp_path: Path) -> None:
        """The distinction a pipeline cannot do without. A runner with no
        signing key has not been refused anything, and treating that as a
        BLOCK would report a policy violation no policy produced -- while
        treating it as 0 would let a misconfigured runner look like a policy
        that allows everything."""
        proposal = write_proposal(tmp_path / "p.json")
        result = runner.invoke(app, ["check", str(proposal), "--dir", str(tmp_path / "nokeys")])
        assert result.exit_code == ERROR_EXIT, result.output

    def test_an_unreadable_proposal_is_also_one(self, qed_dir: Path, tmp_path: Path) -> None:
        bad = tmp_path / "p.json"
        bad.write_text("{not json", encoding="utf-8")
        result = runner.invoke(app, ["check", str(bad), "--dir", str(qed_dir)])
        assert result.exit_code == ERROR_EXIT

    def test_shadow_mode_does_not_fail_the_build(self, qed_dir: Path, tmp_path: Path) -> None:
        """Otherwise shadow mode would be useless for its one purpose: finding
        out what a policy would do before anybody depends on it."""
        config = tmp_path / "qed.yaml"
        config.write_text(yaml.safe_dump({"mode": "shadow"}), encoding="utf-8")
        proposal = write_proposal(tmp_path / "p.json", PROD_DROP)
        result = runner.invoke(
            app, ["check", str(proposal), "--dir", str(qed_dir), "--config", str(config)]
        )
        assert result.exit_code == ALLOW_EXIT, result.output
        assert "shadow mode" in result.output


# --------------------------------------------------------------------------
# --evidence-out
# --------------------------------------------------------------------------


class TestTheEvidenceArtifact:
    def test_the_exported_chain_verifies(self, qed_dir: Path, tmp_path: Path) -> None:
        """The point of the flag. A workspace is deleted with the build, so the
        evidence for a decision that gated a deployment has to leave as a file
        an auditor can check without this repo."""
        from qed_verify.verify import load_jsonl, verify_records

        from qed.infra.keys.file import PUBLIC_DIR_NAME, load_public_keys

        proposal = write_proposal(tmp_path / "p.json")
        out = tmp_path / "artifacts" / "qed-evidence.jsonl"
        result = runner.invoke(
            app, ["check", str(proposal), "--dir", str(qed_dir), "--evidence-out", str(out)]
        )
        assert result.exit_code in {ALLOW_EXIT, BLOCK_EXIT, APPROVAL_EXIT}, result.output
        assert out.exists(), "the directory was not created"

        report = verify_records(
            load_jsonl(out.read_text(encoding="utf-8")),
            load_public_keys(qed_dir / PUBLIC_DIR_NAME),
        )
        assert report.ok, report.summary()

    def test_it_holds_the_whole_chain_and_not_just_this_verdict(
        self, qed_dir: Path, tmp_path: Path
    ) -> None:
        """`qed-verify` walks linkage from genesis, so a file holding only the
        last two records is a file that cannot be verified."""
        proposal = write_proposal(tmp_path / "p.json")
        out = tmp_path / "e.jsonl"
        runner.invoke(
            app, ["check", str(proposal), "--dir", str(qed_dir), "--evidence-out", str(out)]
        )
        types = [json.loads(line)["type"] for line in out.read_text(encoding="utf-8").splitlines()]
        assert types[0] == "genesis"
        assert types[-1] == "verdict"

    def test_the_path_is_reported(self, qed_dir: Path, tmp_path: Path) -> None:
        proposal = write_proposal(tmp_path / "p.json")
        out = tmp_path / "e.jsonl"
        result = runner.invoke(
            app, ["check", str(proposal), "--dir", str(qed_dir), "--evidence-out", str(out)]
        )
        assert "e.jsonl" in result.output

    def test_an_unwritable_path_does_not_change_the_verdict(
        self, qed_dir: Path, tmp_path: Path
    ) -> None:
        """The exit code is about the policy, not about a full disk."""
        proposal = write_proposal(tmp_path / "p.json", {"action": {"name": "list_buckets"}})
        # A directory where a file is expected: refused on every platform.
        clash = tmp_path / "taken"
        clash.mkdir()
        result = runner.invoke(
            app, ["check", str(proposal), "--dir", str(qed_dir), "--evidence-out", str(clash)]
        )
        assert result.exit_code == ALLOW_EXIT, result.output
        assert "could not write" in result.output


# --------------------------------------------------------------------------
# --server
# --------------------------------------------------------------------------


class ServedInstance:
    def __init__(self, base: str, process: subprocess.Popen[bytes], log: Path) -> None:
        self.base = base
        self.process = process
        self.log = log

    @property
    def output(self) -> str:
        return self.log.read_text(encoding="utf-8", errors="replace")


@pytest.fixture
def instance(tmp_path: Path) -> Iterator[ServedInstance]:
    """A real `qed serve` with one registered adapter, in enforce mode.

    Enforce mode on purpose: `--server` has to carry back a verdict that fails
    a build, and a shadow instance would make every case below exit 0.
    """
    directory = tmp_path / "server"
    init_keys(directory)
    config = tmp_path / "server.yaml"
    config.write_text(
        yaml.safe_dump(
            {
                "mode": "enforce",
                "instance_id": "qed-ci",
                "adapters": [{"adapter_id": ADAPTER_ID, "secret_env": SECRET_ENV, "kind": "mcp"}],
            }
        ),
        encoding="utf-8",
    )

    port = free_port()
    log = tmp_path / "serve.log"
    environment = {**os.environ, SECRET_ENV: SECRET}
    with log.open("wb") as sink:
        process = subprocess.Popen(
            [
                sys.executable,
                "-c",
                "from qed.cli import main; main()",
                "serve",
                "--dir",
                str(directory),
                "--config",
                str(config),
                "--host",
                "127.0.0.1",
                "--port",
                str(port),
            ],
            cwd=str(REPO),
            env=environment,
            stdout=sink,
            stderr=subprocess.STDOUT,
        )
        base = f"http://127.0.0.1:{port}"
        try:
            status, _ = wait_for(f"{base}/readyz", deadline=time.monotonic() + STARTUP_TIMEOUT)
            assert status == 200, log.read_text(encoding="utf-8", errors="replace")
            yield ServedInstance(base, process, log)
        finally:
            process.terminate()
            try:
                process.wait(timeout=20)
            except subprocess.TimeoutExpired:  # pragma: no cover
                process.kill()
                process.wait(timeout=10)


def remote(instance: ServedInstance, proposal: Path, *extra: str) -> object:
    return runner.invoke(
        app,
        ["check", str(proposal), "--server", instance.base, "--adapter-id", ADAPTER_ID, *extra],
        env={SECRET_ENV: SECRET, "QED_ADAPTER_SECRET": SECRET},
    )


class TestDecidingOnAnInstance:
    def test_a_signed_request_from_the_cli_is_accepted(
        self, instance: ServedInstance, tmp_path: Path
    ) -> None:
        """The whole reason this test starts a subprocess: the CLI's canonical
        string and the API's have to agree byte for byte, and they are built by
        different code."""
        proposal = write_proposal(tmp_path / "p.json", {"action": {"name": "list_buckets"}})
        result = remote(instance, proposal)
        assert result.exit_code == ALLOW_EXIT, result.output + instance.output
        assert "ALLOW" in result.output
        assert instance.base in result.output

    def test_a_block_from_the_server_fails_the_build(
        self, instance: ServedInstance, tmp_path: Path
    ) -> None:
        proposal = write_proposal(tmp_path / "p.json", OPEN_TO_THE_WORLD)
        result = remote(instance, proposal)
        assert result.exit_code == BLOCK_EXIT, result.output + instance.output
        assert "BLOCK" in result.output

    def test_the_evidence_reference_is_printed(
        self, instance: ServedInstance, tmp_path: Path
    ) -> None:
        """What makes the remote decision auditable from the build log: the
        reference resolves through `GET /v1/evidence/by-ref/`."""
        proposal = write_proposal(tmp_path / "p.json", {"action": {"name": "list_buckets"}})
        result = remote(instance, proposal)
        assert "evidence ref" in result.output

    def test_json_output_is_the_servers_own_document(
        self, instance: ServedInstance, tmp_path: Path
    ) -> None:
        proposal = write_proposal(tmp_path / "p.json", {"action": {"name": "list_buckets"}})
        result = remote(instance, proposal, "--json")
        payload = json.loads(result.output)
        assert payload["verdict"]["decision"] == "ALLOW"
        assert payload["evidence_ref"]

    def test_no_local_key_is_needed(self, instance: ServedInstance, tmp_path: Path) -> None:
        """The reason to use `--server` at all. A CI runner with a signing key
        is a CI runner that can mint evidence, which is the one thing the
        chain's value depends on nobody being able to do casually."""
        proposal = write_proposal(tmp_path / "p.json", {"action": {"name": "list_buckets"}})
        result = runner.invoke(
            app,
            [
                "check",
                str(proposal),
                "--server",
                instance.base,
                "--adapter-id",
                ADAPTER_ID,
                "--dir",
                str(tmp_path / "definitely-not-initialised"),
            ],
            env={"QED_ADAPTER_SECRET": SECRET},
        )
        assert result.exit_code == ALLOW_EXIT, result.output
        assert not (tmp_path / "definitely-not-initialised").exists()

    def test_a_wrong_secret_is_an_error_and_not_an_allow(
        self, instance: ServedInstance, tmp_path: Path
    ) -> None:
        proposal = write_proposal(tmp_path / "p.json", {"action": {"name": "list_buckets"}})
        result = runner.invoke(
            app,
            ["check", str(proposal), "--server", instance.base, "--adapter-id", ADAPTER_ID],
            env={"QED_ADAPTER_SECRET": "w" * 48},
        )
        assert result.exit_code == ERROR_EXIT, result.output


class TestWhenTheServerCannotBeReached:
    def test_it_is_an_error_and_never_an_allow(self, tmp_path: Path) -> None:
        """An instance that could not be reached has refused nothing. Reading
        this as ALLOW is the failure the whole project exists to prevent; and
        reading it as BLOCK would report a violation no policy produced."""
        proposal = write_proposal(tmp_path / "p.json")
        result = runner.invoke(
            app,
            [
                "check",
                str(proposal),
                "--server",
                f"http://127.0.0.1:{free_port()}",
                "--adapter-id",
                ADAPTER_ID,
            ],
            env={"QED_ADAPTER_SECRET": SECRET},
        )
        assert result.exit_code == ERROR_EXIT, result.output
        assert "could not reach" in result.output

    def test_a_missing_adapter_identity_says_what_to_register(self, tmp_path: Path) -> None:
        proposal = write_proposal(tmp_path / "p.json")
        result = runner.invoke(
            app,
            ["check", str(proposal), "--server", "http://127.0.0.1:1"],
            env={"QED_ADAPTER_ID": "", "QED_ADAPTER_SECRET": ""},
        )
        assert result.exit_code == ERROR_EXIT
        assert "--adapter-id" in result.output
        assert "AG-IDN-005" in result.output
