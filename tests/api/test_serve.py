"""``qed serve`` and the container (SPEC §14, §20.4).

``qed serve`` is started for real here, as a subprocess bound to a loopback
port, and probed over HTTP. The in-process ``TestClient`` tests cover the
handlers; this covers the thing that is easy to get wrong and invisible to a
TestClient -- that the CLI wires the config, the bind address and the lifespan
together, and that uvicorn actually comes up.

The Dockerfile checks are static. Building an image needs a daemon that CI for
this repo does not have, so what is asserted is the set of properties SPEC §20.4
fixes: distroless, non-root, no shell in the runtime stage.
"""

from __future__ import annotations

import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Iterator
from pathlib import Path

import pytest
import yaml

from qed.infra.keys.file import init_keys

REPO = Path(__file__).resolve().parents[2]
DOCKERFILE = REPO / "deploy" / "Dockerfile"
STARTUP_TIMEOUT = 45.0


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def wait_for(url: str, *, deadline: float) -> tuple[int, bytes]:
    """Poll until the server answers, or fail with whatever went wrong."""
    last: Exception | None = None
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as response:
                return int(response.status), response.read()
        except urllib.error.HTTPError as exc:  # a real answer, just not 2xx
            return int(exc.code), exc.read()
        except OSError as exc:
            last = exc
            time.sleep(0.2)
    raise AssertionError(f"{url} never answered: {last}")


class Served:
    """A running ``qed serve``, plus whatever it printed."""

    def __init__(self, base: str, process: subprocess.Popen[bytes], log: Path) -> None:
        self.base = base
        self.process = process
        self.log = log

    @property
    def output(self) -> str:
        return self.log.read_text(encoding="utf-8", errors="replace")


@pytest.fixture
def served(tmp_path: Path) -> Iterator[Served]:
    """Start the real CLI on a loopback port.

    Output goes to a file rather than a pipe for two reasons: an unread pipe
    deadlocks once uvicorn has written a buffer's worth of logs, and this
    suite runs with ``filterwarnings = ["error"]``, where an unclosed pipe at
    teardown is a test error rather than a warning.
    """
    directory = tmp_path / "qed"
    init_keys(directory)
    config = tmp_path / "qed.yaml"
    config.write_text(yaml.safe_dump({"mode": "shadow"}), encoding="utf-8")

    port = free_port()
    log = tmp_path / "serve.log"
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
                "--dev",
            ],
            cwd=str(REPO),
            stdout=sink,
            stderr=subprocess.STDOUT,
        )
        try:
            yield Served(f"http://127.0.0.1:{port}", process, log)
        finally:
            process.terminate()
            try:
                process.wait(timeout=20)
            except subprocess.TimeoutExpired:  # pragma: no cover
                process.kill()
                process.wait(timeout=10)


class TestQedServe:
    def test_it_comes_up_and_reports_ready(self, served: Served) -> None:
        import json

        deadline = time.monotonic() + STARTUP_TIMEOUT
        status, _ = wait_for(f"{served.base}/healthz", deadline=deadline)
        assert status == 200, "the process is listening but not alive"

        status, body = wait_for(f"{served.base}/readyz", deadline=deadline)
        assert status == 200, served.output
        payload = json.loads(body)
        assert payload["ready"] is True
        assert payload["key_id"].startswith("ed25519:")
        assert payload["dev"] is True
        assert served.process.poll() is None, "the server exited while being probed"

    def test_dev_mode_warns_on_stderr(self, served: Served) -> None:
        """An operator must not be able to miss that auth is off."""
        wait_for(f"{served.base}/healthz", deadline=time.monotonic() + STARTUP_TIMEOUT)
        assert "--dev is on" in served.output
        assert "NOT checked" in served.output

    def test_it_binds_only_where_it_was_told(self, served: Served) -> None:
        """A policy kernel that quietly binds 0.0.0.0 is an open one."""
        wait_for(f"{served.base}/healthz", deadline=time.monotonic() + STARTUP_TIMEOUT)
        port = int(served.base.rsplit(":", 1)[1])

        with socket.socket() as probe:
            probe.settimeout(2)
            assert probe.connect_ex(("127.0.0.1", port)) == 0

        # The host's non-loopback address must not be listening.
        external = socket.gethostbyname(socket.gethostname())
        if external.startswith("127."):  # pragma: no cover - CI without a LAN address
            pytest.skip("this host has no non-loopback address to probe")
        with socket.socket() as probe:
            probe.settimeout(2)
            assert probe.connect_ex((external, port)) != 0

    def test_it_refuses_an_unknown_mode_rather_than_guessing(self, tmp_path: Path) -> None:
        directory = tmp_path / "qed"
        init_keys(directory)
        config = tmp_path / "bad.yaml"
        config.write_text(yaml.safe_dump({"mode": "advisory-ish"}), encoding="utf-8")
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                "from qed.cli import main; main()",
                "serve",
                "--dir",
                str(directory),
                "--config",
                str(config),
                "--port",
                str(free_port()),
            ],
            cwd=str(REPO),
            capture_output=True,
            timeout=STARTUP_TIMEOUT,
        )
        assert result.returncode != 0
        assert b"mode" in result.stderr


class TestTheContainerIsWhatTheSpecAsksFor:
    """SPEC §20.4: distroless, non-root."""

    def test_there_is_a_dockerfile(self) -> None:
        assert DOCKERFILE.is_file()

    def test_the_runtime_stage_is_distroless(self) -> None:
        text = DOCKERFILE.read_text(encoding="utf-8")
        runtime = text.split("AS runtime", 1)[0].rsplit("FROM ", 1)[1]
        assert "distroless" in runtime

    def test_it_runs_as_a_non_root_user(self) -> None:
        text = DOCKERFILE.read_text(encoding="utf-8")
        assert "USER 65532:65532" in text
        assert "USER root" not in text

    def test_the_build_stage_is_separate_from_the_runtime_stage(self) -> None:
        """pip and a compiler must not be in the shipped image."""
        text = DOCKERFILE.read_text(encoding="utf-8")
        assert text.count("FROM ") == 2
        assert "COPY --from=builder" in text
        assert "pip install" not in text.split("AS runtime", 1)[1]

    def test_the_entrypoint_is_exec_form(self) -> None:
        """Shell form needs a shell, and distroless has none."""
        text = DOCKERFILE.read_text(encoding="utf-8")
        entrypoint = next(line for line in text.splitlines() if line.startswith("ENTRYPOINT"))
        assert entrypoint.startswith("ENTRYPOINT [")

    def test_it_declares_no_anonymous_volume_for_the_chain(self) -> None:
        """A VOLUME line is how an evidence chain disappears on `docker run`."""
        text = DOCKERFILE.read_text(encoding="utf-8")
        assert not any(line.startswith("VOLUME") for line in text.splitlines())
