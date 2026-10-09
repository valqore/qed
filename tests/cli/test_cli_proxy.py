"""`qed proxy`'s command surface (SPEC §12.3, §14).

The adapter itself is tested against real sockets in
``tests/adapters/http_proxy/``. What is left here is everything the command
does *before* it starts listening, which is where the refusals live: an
unidentified session, a reachable bind address, an upstream whose credential
cannot be injected into an HTTP request at all.

All three are refusals on purpose. The proxy is the one adapter where getting
it wrong is quiet -- it starts, it serves, and the damage shows up in the
chain or in somebody else's logs rather than on the terminal.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from qed.adapters.http_proxy.proxy import HttpProxyStats
from qed.cli import _print_http_stats, app

runner = CliRunner()


@pytest.fixture
def qed_dir(tmp_path: Path) -> Path:
    directory = tmp_path / "g"
    runner.invoke(app, ["keys", "init", "--dir", str(directory)])
    return directory


def config(tmp_path: Path, **values: object) -> Path:
    path = tmp_path / "qed.yaml"
    path.write_text(yaml.safe_dump(values), encoding="utf-8")
    return path


class TestItRefusesBeforeItListens:
    def test_without_a_principal_or_a_mandate(self, qed_dir: Path) -> None:
        """Every verdict would be a synthetic AG-IDN-007 identity BLOCK,
        reached before any rule runs, and in shadow mode nothing would look
        wrong."""
        result = runner.invoke(app, ["proxy", "--dir", str(qed_dir)])
        assert result.exit_code == 1
        assert "AG-IDN-007" in result.output

    def test_a_reachable_bind_address_without_the_flag(self, qed_dir: Path) -> None:
        """A forward proxy on a reachable interface is an open relay, and the
        chain would attribute every request through it to this --human."""
        result = runner.invoke(
            app,
            ["proxy", "--dir", str(qed_dir), "--human", "me@acme.com", "--host", "0.0.0.0"],
        )
        assert result.exit_code == 1
        assert "open relay" in result.output
        assert "--allow-non-loopback" in result.output

    @pytest.mark.parametrize("value", ["staging-ish", "production"])
    def test_an_environment_that_is_not_one_of_the_three(self, qed_dir: Path, value: str) -> None:
        result = runner.invoke(
            app, ["proxy", "--dir", str(qed_dir), "--human", "me@acme.com", "--env", value]
        )
        assert result.exit_code == 1

    def test_an_upstream_that_injects_into_the_environment(
        self, qed_dir: Path, tmp_path: Path
    ) -> None:
        """An environment variable is how a credential reaches a stdio child
        process. An HTTP request does not have one, so the upstream would
        match, resolve, and have its credential silently dropped."""
        (tmp_path / "upstreams.yaml").write_text(
            yaml.safe_dump(
                {
                    "upstreams": [
                        {
                            "id": "wrong",
                            "kind": "http",
                            "credential": {
                                "source": "env",
                                "ref": "X",
                                "inject": {"type": "env", "name": "DATABASE_URL"},
                            },
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        path = config(tmp_path, broker={"upstreams_file": "upstreams.yaml"})
        result = runner.invoke(
            app,
            ["proxy", "--dir", str(qed_dir), "--config", str(path), "--human", "me@acme.com"],
        )
        assert result.exit_code == 1
        assert "does not have" in result.output
        assert "not held" in result.output

    def test_without_a_signing_key(self, tmp_path: Path) -> None:
        result = runner.invoke(
            app, ["proxy", "--dir", str(tmp_path / "nokeys"), "--human", "me@acme.com"]
        )
        assert result.exit_code == 1
        assert "keys init" in result.output


class TestTheClosingSummary:
    """A session that was entirely advisory looks identical to an enforcing
    one in every count except the ones below, so those two lines are the
    whole point of the summary."""

    def test_it_separates_tunnels_from_plain_requests(self) -> None:
        stats = HttpProxyStats(requests=3, tunnels=2, allowed=5)
        _print_http_stats(stats)

    def test_advisory_calls_are_called_out(self, capsys: pytest.CaptureFixture[str]) -> None:
        _print_http_stats(HttpProxyStats(requests=1, tunnels=1, allowed=2, advisory=1))
        out = capsys.readouterr().out
        assert "2 request(s); 1 plain, 1 tunnel(s)" in out
        assert "1 of those request(s) were ADVISORY" in out
        assert "not holding the credential" in out

    def test_a_fully_enforcing_session_says_nothing_about_advisory(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _print_http_stats(HttpProxyStats(requests=2, allowed=2))
        assert "ADVISORY" not in capsys.readouterr().out

    def test_stripped_credentials_are_reported_once_each(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Worth noticing in both directions: usually somebody wired a token
        into the agent and is wondering why it is ignored, and sometimes the
        agent is trying to reach past QED."""
        stats = HttpProxyStats(
            requests=2, allowed=2, stripped=["Authorization", "X-Api-Key", "Authorization"]
        )
        _print_http_stats(stats)
        out = capsys.readouterr().out
        assert "removed 3 agent-supplied credential header(s)" in out
        assert "Authorization, X-Api-Key" in out

    def test_the_byte_counts_are_printed(self, capsys: pytest.CaptureFixture[str]) -> None:
        """For a tunnel they are the only facts QED has."""
        _print_http_stats(HttpProxyStats(tunnels=1, bytes_to_upstream=656, bytes_to_client=4415))
        assert "656 bytes out, 4415 bytes in" in capsys.readouterr().out
