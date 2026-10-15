"""`qed adapters add|list|rotate` (SPEC §12.6).

Three properties carry the weight here, and each one is a way the command
could pass its happy path and still be wrong.

**The secret must not be anywhere but the terminal.** Not in `qed.yaml`, which
is a file somebody commits, and not in the chain, which is the artefact the
product exists to hand an auditor. A command that registered an adapter
correctly and wrote its secret into evidence would be worse than no command.

**The operator's config file must survive.** It is hand-written, with comments
explaining settings nobody remembers the reason for. `tests/infra/
test_config_edit.py` owns that in detail; here it is checked once end to end,
because the editor being right and the command calling it correctly are
different claims.

**A rotation must not be a cutover.** A shared secret cannot change on two
machines at once, so there is an overlap, and the overlap is the feature.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from qed.cli import app
from qed.config import load_config

runner = CliRunner()

HAND_WRITTEN = """\
# Do not reformat. The platform team reads this file.
instance_id: prod-eu-1

# Enforcing since 2026-09-01.
mode: enforce

api:
  port: 8710
"""


@pytest.fixture
def instance(tmp_path: Path) -> Path:
    state = tmp_path / "state"
    state.mkdir()
    (state / "qed.yaml").write_text(HAND_WRITTEN, encoding="utf-8")
    result = runner.invoke(app, ["keys", "init", "--dir", str(state)])
    assert result.exit_code == 0, result.output
    return state


def run(*args: str) -> object:
    return runner.invoke(app, list(args))


def exported(state: Path) -> str:
    # `--config` and not just `--dir`: the chain's genesis is bound to the
    # `instance_id` the config carries, and `export` without it opens a
    # session as the default `qed-local` and refuses the mismatch.
    result = runner.invoke(
        app, ["export", "--dir", str(state), "--config", str(state / "qed.yaml")]
    )
    assert result.exit_code == 0, result.output
    return result.stdout


def secret_from(output: str) -> str:
    line = next(line for line in output.splitlines() if line.strip().startswith("export "))
    return line.split("=", 1)[1].strip()


class TestAdd:
    def test_it_registers_the_adapter(self, instance: Path) -> None:
        result = runner.invoke(app, ["adapters", "add", "mcp-proxy-ci", "--dir", str(instance)])
        assert result.exit_code == 0, result.output
        config = load_config(instance / "qed.yaml").config
        assert [item.adapter_id for item in config.registered_adapters] == ["mcp-proxy-ci"]

    def test_the_secret_is_printed_once_and_stored_nowhere(self, instance: Path) -> None:
        """The whole design rests on this. `qed.yaml` is committed and the
        chain is handed to auditors; a shared secret in either is a disclosure
        with a long tail."""
        result = runner.invoke(app, ["adapters", "add", "mcp-proxy-ci", "--dir", str(instance)])
        secret = secret_from(result.output)
        assert len(secret) >= 32

        assert secret not in (instance / "qed.yaml").read_text(encoding="utf-8")
        assert secret not in exported(instance)
        for path in instance.rglob("*"):
            if path.is_file():
                assert secret not in path.read_text(encoding="utf-8", errors="ignore"), path

    def test_only_the_variable_name_reaches_the_config(self, instance: Path) -> None:
        runner.invoke(app, ["adapters", "add", "mcp-proxy-ci", "--dir", str(instance)])
        text = (instance / "qed.yaml").read_text(encoding="utf-8")
        assert "secret_env: QED_ADAPTER_SECRET_MCP_PROXY_CI" in text

    def test_the_operators_comments_survive(self, instance: Path) -> None:
        runner.invoke(app, ["adapters", "add", "mcp-proxy-ci", "--dir", str(instance)])
        text = (instance / "qed.yaml").read_text(encoding="utf-8")
        assert "# Do not reformat. The platform team reads this file." in text
        assert "# Enforcing since 2026-09-01." in text

    def test_it_leaves_an_admin_action_in_the_chain(self, instance: Path) -> None:
        """Registering an adapter grants an identity the right to submit
        proposals. An auditor asking "who may talk to this kernel, and since
        when" has to be able to answer it from the chain."""
        runner.invoke(app, ["adapters", "add", "mcp-proxy-ci", "--dir", str(instance)])
        records = [json.loads(line) for line in exported(instance).splitlines() if line.strip()]
        actions = [
            item["payload"]
            for item in records
            if item.get("type") == "admin_action"
            and item["payload"].get("action") == "adapters_add"
        ]
        assert len(actions) == 1
        assert actions[0]["adapter_id"] == "mcp-proxy-ci"
        assert actions[0]["secret_env"] == "QED_ADAPTER_SECRET_MCP_PROXY_CI"

    def test_a_duplicate_is_refused(self, instance: Path) -> None:
        runner.invoke(app, ["adapters", "add", "mcp-proxy-ci", "--dir", str(instance)])
        result = runner.invoke(app, ["adapters", "add", "mcp-proxy-ci", "--dir", str(instance)])
        assert result.exit_code == 1
        assert "already registered" in result.output

    # `-leading` is not in this list: Typer reads a leading hyphen as an
    # option before the command ever sees it, so it exercises the parser and
    # not the rule.
    @pytest.mark.parametrize("bad", ["Bad ID", "has space", "UPPER", "x", "a" * 64, "_leading"])
    def test_an_unusable_adapter_id_is_refused(self, instance: Path, bad: str) -> None:
        """The id travels in an HTTP header and into evidence, so the charset
        is narrow: a header value with a newline is a request-splitting bug,
        and an id that renders two ways is an identity nobody can follow."""
        result = runner.invoke(app, ["adapters", "add", bad, "--dir", str(instance)])
        assert result.exit_code == 1
        assert "not a usable adapter id" in result.output

    def test_a_missing_config_file_is_refused_rather_than_created(self, tmp_path: Path) -> None:
        """An invented `qed.yaml` is a config the running instance never
        reads: the adapter looks registered and is refused as AG-IDN-005."""
        state = tmp_path / "bare"
        state.mkdir()
        runner.invoke(app, ["keys", "init", "--dir", str(state)])
        result = runner.invoke(app, ["adapters", "add", "x-ci", "--dir", str(state)])
        assert result.exit_code == 1
        assert "no config file at" in result.output
        assert not (state / "qed.yaml").exists()

    def test_the_secret_env_name_can_be_chosen(self, instance: Path) -> None:
        result = runner.invoke(
            app,
            ["adapters", "add", "ci", "--dir", str(instance), "--secret-env", "MY_SECRET_NAME"],
        )
        assert result.exit_code == 0, result.output
        assert load_config(instance / "qed.yaml").config.registered_adapters[0].secret_env == (
            "MY_SECRET_NAME"
        )


class TestList:
    def test_it_says_when_nothing_is_registered(self, instance: Path) -> None:
        result = runner.invoke(app, ["adapters", "list", "--dir", str(instance)])
        assert result.exit_code == 0
        assert "no adapters are registered" in result.output

    def test_it_reports_a_registered_adapter_with_no_secret_set(self, instance: Path) -> None:
        """The diagnostic this command exists for. Previously the only way to
        learn that `secret_env` was unset was to start the server and read
        `/v1/status` -- or to watch an adapter be refused as unknown."""
        runner.invoke(app, ["adapters", "add", "mcp-proxy-ci", "--dir", str(instance)])
        result = runner.invoke(app, ["adapters", "list", "--dir", str(instance)])
        assert "no secret" in result.output
        assert "mcp-proxy-ci" in result.output

    def test_it_reports_ready_when_the_secret_is_set(
        self, instance: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        runner.invoke(app, ["adapters", "add", "mcp-proxy-ci", "--dir", str(instance)])
        monkeypatch.setenv("QED_ADAPTER_SECRET_MCP_PROXY_CI", "x" * 43)
        result = runner.invoke(app, ["adapters", "list", "--dir", str(instance)])
        assert "ready" in result.output

    def test_a_secret_that_is_too_short_is_not_ready(
        self, instance: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A short shared secret is a password somebody typed, and the API
        refuses it at startup. Saying `ready` here would send an operator
        looking in the wrong place."""
        runner.invoke(app, ["adapters", "add", "mcp-proxy-ci", "--dir", str(instance)])
        monkeypatch.setenv("QED_ADAPTER_SECRET_MCP_PROXY_CI", "short")
        result = runner.invoke(app, ["adapters", "list", "--dir", str(instance)])
        assert "too short" in result.output

    def test_it_never_prints_a_secret(
        self, instance: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        secret = "s3cret-" + "x" * 40
        runner.invoke(app, ["adapters", "add", "mcp-proxy-ci", "--dir", str(instance)])
        monkeypatch.setenv("QED_ADAPTER_SECRET_MCP_PROXY_CI", secret)
        result = runner.invoke(app, ["adapters", "list", "--dir", str(instance)])
        assert secret not in result.output

    def test_json_output(self, instance: Path) -> None:
        runner.invoke(app, ["adapters", "add", "mcp-proxy-ci", "--dir", str(instance)])
        result = runner.invoke(app, ["adapters", "list", "--dir", str(instance), "--json"])
        payload = json.loads(result.stdout)
        assert payload["adapters"][0]["adapter_id"] == "mcp-proxy-ci"
        assert payload["adapters"][0]["state"] == "no secret"


class TestRotate:
    def test_the_previous_secret_is_still_accepted(self, instance: Path) -> None:
        """The feature. A shared secret cannot change on two machines at the
        same instant, and under `fail: closed` a refused request is a blocked
        action -- so a cutover rotation is an outage."""
        runner.invoke(app, ["adapters", "add", "mcp-proxy-ci", "--dir", str(instance)])
        result = runner.invoke(app, ["adapters", "rotate", "mcp-proxy-ci", "--dir", str(instance)])
        assert result.exit_code == 0, result.output
        entry = load_config(instance / "qed.yaml").config.registered_adapters[0]
        assert entry.secret_env == "QED_ADAPTER_SECRET_MCP_PROXY_CI_V2"
        assert entry.previous_secret_env == "QED_ADAPTER_SECRET_MCP_PROXY_CI"

    def test_finish_drops_the_previous_one(self, instance: Path) -> None:
        runner.invoke(app, ["adapters", "add", "mcp-proxy-ci", "--dir", str(instance)])
        runner.invoke(app, ["adapters", "rotate", "mcp-proxy-ci", "--dir", str(instance)])
        result = runner.invoke(
            app, ["adapters", "rotate", "mcp-proxy-ci", "--finish", "--dir", str(instance)]
        )
        assert result.exit_code == 0, result.output
        entry = load_config(instance / "qed.yaml").config.registered_adapters[0]
        assert entry.previous_secret_env == ""
        assert "previous_secret_env" not in (instance / "qed.yaml").read_text(encoding="utf-8")

    def test_finishing_a_rotation_that_never_started_is_refused(self, instance: Path) -> None:
        runner.invoke(app, ["adapters", "add", "mcp-proxy-ci", "--dir", str(instance)])
        result = runner.invoke(
            app, ["adapters", "rotate", "mcp-proxy-ci", "--finish", "--dir", str(instance)]
        )
        assert result.exit_code == 1
        assert "not mid-rotation" in result.output

    def test_rotating_twice_keeps_counting(self, instance: Path) -> None:
        runner.invoke(app, ["adapters", "add", "mcp-proxy-ci", "--dir", str(instance)])
        runner.invoke(app, ["adapters", "rotate", "mcp-proxy-ci", "--dir", str(instance)])
        runner.invoke(
            app, ["adapters", "rotate", "mcp-proxy-ci", "--finish", "--dir", str(instance)]
        )
        runner.invoke(app, ["adapters", "rotate", "mcp-proxy-ci", "--dir", str(instance)])
        entry = load_config(instance / "qed.yaml").config.registered_adapters[0]
        assert entry.secret_env == "QED_ADAPTER_SECRET_MCP_PROXY_CI_V3"

    def test_the_overlap_is_reported_as_unset_until_the_secret_is_set(
        self, instance: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Mid-rotation, `/readyz` stays green on purpose -- an instance that
        can still authenticate restarted adapters must keep serving. So this
        listing is where an operator learns the grace period is not yet in
        effect."""
        runner.invoke(app, ["adapters", "add", "mcp-proxy-ci", "--dir", str(instance)])
        runner.invoke(app, ["adapters", "rotate", "mcp-proxy-ci", "--dir", str(instance)])
        monkeypatch.delenv("QED_ADAPTER_SECRET_MCP_PROXY_CI", raising=False)
        result = runner.invoke(app, ["adapters", "list", "--dir", str(instance)])
        assert "no overlap is in effect" in result.output

    def test_an_overlap_that_is_too_short_says_so(
        self, instance: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Set and unusable is not the same as absent, and both are different
        from working. An adapter still signing with the old secret is being
        refused right now in exactly one of these three states."""
        runner.invoke(app, ["adapters", "add", "mcp-proxy-ci", "--dir", str(instance)])
        runner.invoke(app, ["adapters", "rotate", "mcp-proxy-ci", "--dir", str(instance)])
        monkeypatch.setenv("QED_ADAPTER_SECRET_MCP_PROXY_CI", "short")
        result = runner.invoke(app, ["adapters", "list", "--dir", str(instance)])
        assert "too short" in result.output

    def test_a_working_overlap_says_the_old_secret_is_accepted(
        self, instance: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        runner.invoke(app, ["adapters", "add", "mcp-proxy-ci", "--dir", str(instance)])
        runner.invoke(app, ["adapters", "rotate", "mcp-proxy-ci", "--dir", str(instance)])
        monkeypatch.setenv("QED_ADAPTER_SECRET_MCP_PROXY_CI", "o" * 44)
        result = runner.invoke(app, ["adapters", "list", "--dir", str(instance)])
        assert "still accepted" in result.output

    def test_an_unknown_adapter_is_refused(self, instance: Path) -> None:
        result = runner.invoke(app, ["adapters", "rotate", "nope", "--dir", str(instance)])
        assert result.exit_code == 1
        assert "not registered" in result.output

    def test_the_new_secret_reaches_neither_the_config_nor_the_chain(self, instance: Path) -> None:
        runner.invoke(app, ["adapters", "add", "mcp-proxy-ci", "--dir", str(instance)])
        result = runner.invoke(app, ["adapters", "rotate", "mcp-proxy-ci", "--dir", str(instance)])
        secret = secret_from(result.output)
        assert secret not in (instance / "qed.yaml").read_text(encoding="utf-8")
        assert secret not in exported(instance)

    def test_it_leaves_an_admin_action_in_the_chain(self, instance: Path) -> None:
        runner.invoke(app, ["adapters", "add", "mcp-proxy-ci", "--dir", str(instance)])
        runner.invoke(app, ["adapters", "rotate", "mcp-proxy-ci", "--dir", str(instance)])
        records = [json.loads(line) for line in exported(instance).splitlines() if line.strip()]
        actions = [
            item["payload"]
            for item in records
            if item.get("type") == "admin_action"
            and item["payload"].get("action") == "adapters_rotate"
        ]
        assert len(actions) == 1
        assert actions[0]["previous_secret_env"] == "QED_ADAPTER_SECRET_MCP_PROXY_CI"
        assert actions[0]["finished"] is False


class TestTheSecretItPrintsIsTheSecretTheServerWants:
    """The join, which neither half's tests can make.

    `tests/cli/test_adapters.py` above proves the entry is written and the
    secret is not stored; `tests/api/test_auth.py` proves the API verifies a
    signature against whatever `secret_env` holds. Both can pass while the
    command produces a credential the server rejects -- a wrong variable
    name, a secret mangled on the way to the terminal, a `kind` the API reads
    differently. That gap is this project's most-repeated finding: a
    signature whose unit tests passed for eight weeks while nothing verified
    it end to end.

    So this registers an adapter with the real command, sets exactly the
    variable it printed to exactly the value it printed, and makes a signed
    request to an app built from the file it wrote.
    """

    def test_an_adapter_registered_by_the_command_can_authenticate(
        self, instance: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from fastapi.testclient import TestClient

        from qed.api.app import create_app
        from tests.api.conftest import Signer
        from tests.conftest import BASE_PROPOSAL

        result = runner.invoke(app, ["adapters", "add", "mcp-proxy-ci", "--dir", str(instance)])
        assert result.exit_code == 0, result.output
        secret = secret_from(result.output)

        # The variable name is read back out of the printed `export` line
        # rather than hard-coded, so a change to how the name is derived
        # fails here instead of quietly testing the wrong variable.
        export = next(
            line for line in result.output.splitlines() if line.strip().startswith("export ")
        )
        name = export.split("export ", 1)[1].split("=", 1)[0]
        monkeypatch.setenv(name, secret)

        app_under_test = create_app(
            directory=instance, config_path=instance / "qed.yaml"
        )
        with TestClient(app_under_test) as client:
            assert client.get("/readyz").status_code == 200
            signer = Signer(client, adapter_id="mcp-proxy-ci", secret=secret)
            assert signer.post("/v1/proposals", BASE_PROPOSAL).status_code == 200

    def test_the_same_adapter_with_a_different_secret_is_refused(
        self, instance: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The other half of the claim. A test that only shows a valid
        signature accepted would pass against a server that accepted
        anything."""
        from fastapi.testclient import TestClient

        from qed.api.app import create_app
        from tests.api.conftest import Signer
        from tests.conftest import BASE_PROPOSAL

        result = runner.invoke(app, ["adapters", "add", "mcp-proxy-ci", "--dir", str(instance)])
        secret = secret_from(result.output)
        monkeypatch.setenv("QED_ADAPTER_SECRET_MCP_PROXY_CI", secret)

        app_under_test = create_app(
            directory=instance, config_path=instance / "qed.yaml"
        )
        with TestClient(app_under_test) as client:
            signer = Signer(client, adapter_id="mcp-proxy-ci", secret="w" * 44)
            assert signer.post("/v1/proposals", BASE_PROPOSAL).status_code == 401

    def test_a_rotated_secret_authenticates_and_so_does_the_old_one(
        self, instance: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The overlap, end to end through the real commands rather than a
        hand-written config: this is what makes a rotation safe to run
        against a live fleet."""
        from fastapi.testclient import TestClient

        from qed.api.app import create_app
        from tests.api.conftest import Signer
        from tests.conftest import BASE_PROPOSAL

        first = runner.invoke(app, ["adapters", "add", "mcp-proxy-ci", "--dir", str(instance)])
        old_secret = secret_from(first.output)
        monkeypatch.setenv("QED_ADAPTER_SECRET_MCP_PROXY_CI", old_secret)

        second = runner.invoke(
            app, ["adapters", "rotate", "mcp-proxy-ci", "--dir", str(instance)]
        )
        new_secret = secret_from(second.output)
        monkeypatch.setenv("QED_ADAPTER_SECRET_MCP_PROXY_CI_V2", new_secret)

        app_under_test = create_app(
            directory=instance, config_path=instance / "qed.yaml"
        )
        with TestClient(app_under_test) as client:
            for index, secret in enumerate((new_secret, old_secret)):
                signer = Signer(client, adapter_id="mcp-proxy-ci", secret=secret)
                # A fresh id each time: proposal ids are single-use, and a 409
                # would be a pass for the wrong reason -- it is the duplicate
                # check answering, which is already past authentication.
                proposal = {**BASE_PROPOSAL, "id": f"01JB00000000000000000000{index:02d}"}
                response = signer.post("/v1/proposals", proposal)
                assert response.status_code == 200, (secret[:4], response.text)
