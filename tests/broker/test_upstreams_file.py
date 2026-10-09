"""Loading `upstreams.yaml`, and what `qed doctor` says about it (SPEC §7)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from qed.cli import app
from qed.config import QedConfig, load_config
from qed.infra.upstreams import UpstreamsError, load_upstreams

runner = CliRunner()

UPSTREAMS = {
    "upstreams": [
        {
            "id": "github",
            "kind": "mcp",
            "match": {"mcp_server": "github"},
            "credential": {
                "source": "env",
                "ref": "TEST_GH_TOKEN",
                "inject": {"type": "header", "name": "Authorization"},
            },
        },
        {"id": "wiki", "kind": "http", "match": {"host_globs": ["wiki.internal"]}},
    ]
}


def write(tmp_path: Path, upstreams: dict[str, object] | str) -> Path:
    path = tmp_path / "upstreams.yaml"
    if isinstance(upstreams, str):
        path.write_text(upstreams, encoding="utf-8")
    else:
        path.write_text(yaml.safe_dump(upstreams), encoding="utf-8")
    config = tmp_path / "qed.yaml"
    config.write_text(
        yaml.safe_dump({"mode": "enforce", "broker": {"upstreams_file": "upstreams.yaml"}}),
        encoding="utf-8",
    )
    return config


class TestLoading:
    def test_nothing_configured_is_an_empty_set(self) -> None:
        assert load_upstreams(QedConfig()).upstreams == []

    def test_a_valid_file_loads(self, tmp_path: Path) -> None:
        config = write(tmp_path, UPSTREAMS)
        loaded = load_upstreams(load_config(config).config, base=config)
        assert [u.id for u in loaded.upstreams] == ["github", "wiki"]

    def test_a_relative_path_resolves_next_to_the_config(self, tmp_path: Path) -> None:
        """Not against the working directory: a qed started by systemd runs
        from somewhere nobody chose."""
        config = write(tmp_path, UPSTREAMS)
        loaded = load_upstreams(load_config(config).config, base=config)
        assert loaded.upstreams

    def test_a_missing_file_is_an_error_not_an_empty_set(self, tmp_path: Path) -> None:
        """Carrying on with no upstreams would quietly turn every enforcing
        adapter advisory, and the symptom is one nobody notices until it
        matters."""
        config = tmp_path / "qed.yaml"
        config.write_text(
            yaml.safe_dump({"broker": {"upstreams_file": "nope.yaml"}}), encoding="utf-8"
        )
        with pytest.raises(UpstreamsError, match="Refusing to continue"):
            load_upstreams(load_config(config).config, base=config)

    def test_malformed_yaml_is_an_error(self, tmp_path: Path) -> None:
        config = write(tmp_path, "upstreams: [ unclosed")
        with pytest.raises(UpstreamsError, match="not valid YAML"):
            load_upstreams(load_config(config).config, base=config)

    def test_a_file_without_the_key_is_an_error(self, tmp_path: Path) -> None:
        config = write(tmp_path, {"something_else": []})
        with pytest.raises(UpstreamsError, match="top-level"):
            load_upstreams(load_config(config).config, base=config)

    def test_duplicate_ids_are_refused(self, tmp_path: Path) -> None:
        """Which one injects a credential would otherwise depend on file
        order, which is not a thing an operator should have to know."""
        doubled = {"upstreams": [UPSTREAMS["upstreams"][0], UPSTREAMS["upstreams"][0]]}
        config = write(tmp_path, doubled)
        with pytest.raises(UpstreamsError, match="share the id"):
            load_upstreams(load_config(config).config, base=config)


class TestDoctor:
    def qed_dir(self, tmp_path: Path) -> Path:
        from qed.infra.keys.file import init_keys

        directory = tmp_path / "qed"
        init_keys(directory)
        return directory

    def test_with_nothing_configured_it_says_everything_is_advisory(self, tmp_path: Path) -> None:
        directory = self.qed_dir(tmp_path)
        result = runner.invoke(app, ["doctor", "--dir", str(directory)])
        assert result.exit_code == 0, result.output
        assert "ADVISORY" in result.output.upper()

    def test_a_resolvable_credential_reads_as_enforcing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("TEST_GH_TOKEN", "ghp_" + "x" * 26)
        directory = self.qed_dir(tmp_path)
        config = write(tmp_path, UPSTREAMS)
        result = runner.invoke(
            app, ["doctor", "--dir", str(directory), "--config", str(config), "--json"]
        )
        assert result.exit_code == 0, result.output
        report = json.loads(result.output)
        github = next(u for u in report["upstreams"] if u["id"] == "github")
        assert github["enforcement"] == "enforcing"
        assert report["enforcing"] == 1

    def test_an_unresolvable_credential_is_downgraded_with_a_reason(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Config that claims more than it can deliver is worse than config
        that admits the gap, because the claim ends up in the evidence."""
        monkeypatch.delenv("TEST_GH_TOKEN", raising=False)
        directory = self.qed_dir(tmp_path)
        config = write(tmp_path, UPSTREAMS)
        report = json.loads(
            runner.invoke(
                app, ["doctor", "--dir", str(directory), "--config", str(config), "--json"]
            ).output
        )
        github = next(u for u in report["upstreams"] if u["id"] == "github")
        assert github["enforcement"] == "advisory"
        assert "TEST_GH_TOKEN" in github["credential"]

    def test_the_report_never_carries_a_credential(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        secret = "ghp_thisMustNotAppearAnywhere"
        monkeypatch.setenv("TEST_GH_TOKEN", secret)
        directory = self.qed_dir(tmp_path)
        config = write(tmp_path, UPSTREAMS)
        output = runner.invoke(
            app, ["doctor", "--dir", str(directory), "--config", str(config), "--json"]
        ).output
        assert secret not in output
        # The length is useful and safe: it distinguishes "set" from "set but
        # empty" without printing anything.
        assert f"{len(secret)} chars" in output

    def test_offline_does_not_reach_for_vault(self, tmp_path: Path) -> None:
        """An air-gapped posture check has to work, and a Vault read is the
        one thing in here that needs a network."""
        vaulted = {
            "upstreams": [
                {
                    "id": "pg",
                    "kind": "mcp",
                    "match": {"mcp_server": "postgres"},
                    "credential": {
                        "source": "vault",
                        "ref": "secret/data/qed/pg#DATABASE_URL",
                        "inject": {"type": "env", "name": "DATABASE_URL"},
                    },
                }
            ]
        }
        directory = self.qed_dir(tmp_path)
        config = write(tmp_path, vaulted)
        report = json.loads(
            runner.invoke(
                app,
                [
                    "doctor",
                    "--dir",
                    str(directory),
                    "--config",
                    str(config),
                    "--offline",
                    "--json",
                ],
            ).output
        )
        assert report["upstreams"][0]["credential"] == "not checked (offline)"
