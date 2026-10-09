"""The container (SPEC §20.4, §24).

Two halves, and the split matters.

The **static** half reads the Dockerfile and asserts the properties SPEC §20.4
fixes: distroless, non-root, no shell in the runtime stage, no anonymous
volume. It runs everywhere and costs nothing.

The **real** half builds the image and starts it. It exists because the static
half once passed on an image that could not run at all: the runtime base was
`distroless/python3-debian12`, which ships Python 3.11, while the builder
installed wheels for 3.12. The 3.12 extension modules landed beside a 3.11
interpreter that could not load them, and the first symptom was `ImportError:
cannot import name 'ArgsKwargs' from 'pydantic_core._pydantic_core' (unknown
location)` -- in a container, from a build that had been green for weeks.

A second bug surfaced the same way: `qed/compliance/frameworks.yaml` was not in
`package-data`, so the wheel did not contain it, so the image started, bound
its port, and died on the first request. `tests/test_packaging.py` guards that
one directly now; this guards the class.

Skipped without a Docker daemon.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
DOCKERFILE = REPO / "deploy" / "Dockerfile"
STAGE_SCRIPT = REPO / "deploy" / "stage-libs.sh"
TAG = "qed-test:pytest"


def dockerfile() -> str:
    return DOCKERFILE.read_text(encoding="utf-8")


def runtime_stage() -> str:
    return dockerfile().split("AS runtime", 1)[1]


# --------------------------------------------------------------------------
# Static
# --------------------------------------------------------------------------


class TestWhatTheDockerfileSays:
    """SPEC §20.4: distroless, non-root."""

    def test_there_is_a_dockerfile(self) -> None:
        assert DOCKERFILE.is_file()

    def test_the_runtime_stage_is_distroless(self) -> None:
        text = dockerfile()
        runtime = text.split("AS runtime", 1)[0].rsplit("FROM ", 1)[1]
        assert "distroless" in runtime

    def test_the_runtime_base_is_not_the_distroless_python_image(self) -> None:
        """It ships Python 3.11 and `qed` requires 3.12. A 3.12 wheel's
        compiled extension beside a 3.11 interpreter is an ABI mismatch that
        presents as a nonsense ImportError, in a container, from a build that
        looked fine."""
        runtime = dockerfile().split("AS runtime", 1)[0].rsplit("FROM ", 1)[1]
        assert "python3-debian" not in runtime

    def test_it_runs_as_a_non_root_user(self) -> None:
        text = dockerfile()
        assert "USER 65532:65532" in text
        assert "USER root" not in text

    def test_the_build_tools_are_not_in_the_shipped_image(self) -> None:
        """pip and a compiler must not be in the runtime stage."""
        text = dockerfile()
        assert "COPY --from=" in text
        assert "pip install" not in runtime_stage()
        # Three stages: build, staging, runtime. Stated as a number so that a
        # fourth has to be a decision somebody makes here too.
        assert text.count("FROM ") == 3

    def test_the_entrypoint_is_exec_form(self) -> None:
        """Shell form needs a shell, and distroless has none."""
        entrypoint = next(
            line for line in dockerfile().splitlines() if line.startswith("ENTRYPOINT")
        )
        assert entrypoint.startswith("ENTRYPOINT [")

    def test_it_declares_no_anonymous_volume_for_the_chain(self) -> None:
        """A VOLUME line is how an evidence chain disappears on `docker run`."""
        assert not any(line.startswith("VOLUME") for line in dockerfile().splitlines())

    def test_the_postgres_extra_is_installed(self) -> None:
        """The HA path is a property of the deployment, not of the image. An
        operator who sets `evidence.store_env` should not discover that the
        container they were handed cannot talk to a database."""
        assert "[postgres]" in dockerfile()

    def test_the_library_closure_is_computed_and_not_listed(self) -> None:
        """A hand-written list of Debian libraries goes stale on the next base
        bump and fails at import time in production."""
        assert STAGE_SCRIPT.is_file()
        script = STAGE_SCRIPT.read_text(encoding="utf-8")
        assert "ldd" in script
        # It must fail rather than ship an image that cannot start.
        assert "test -s /tmp/extra" in script

    def test_the_stage_script_has_unix_line_endings(self) -> None:
        """`sh` reads the carriage return as part of the argument: `set -eu\\r`
        is `set: Illegal option -`, from a script that looks correct in every
        editor."""
        assert b"\r" not in STAGE_SCRIPT.read_bytes()


# --------------------------------------------------------------------------
# Real
# --------------------------------------------------------------------------


def docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    probe = subprocess.run(
        ["docker", "info", "--format", "{{.ServerVersion}}"],
        capture_output=True,
        text=True,
        check=False,
    )
    return probe.returncode == 0


@pytest.fixture(scope="module")
def image(tmp_path_factory: pytest.TempPathFactory) -> str:
    """Build once for the whole module. A minute, and then four cheap tests.

    The build log goes to a file rather than a pipe. A container build writes
    megabytes, and this suite runs with ``filterwarnings = ["error"]``, where
    a decode failure on `subprocess`'s reader thread is a test error rather
    than a warning -- reported against whichever test happened to be running.
    """
    log = tmp_path_factory.mktemp("docker") / "build.log"
    with log.open("wb") as sink:
        build = subprocess.run(
            ["docker", "build", "-f", str(DOCKERFILE), "-t", TAG, str(REPO)],
            stdout=sink,
            stderr=subprocess.STDOUT,
            check=False,
        )
    assert build.returncode == 0, log.read_text(encoding="utf-8", errors="replace")[-4000:]
    return TAG


@pytest.mark.slow
@pytest.mark.skipif(not docker_available(), reason="no Docker daemon")
class TestTheImageActuallyRuns:
    def run(self, image: str, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["docker", "run", "--rm", image, *args],
            capture_output=True,
            text=True,
            check=False,
        )

    def test_the_cli_starts(self, image: str) -> None:
        """The one the static checks cannot make. An interpreter that cannot
        load its own extension modules fails here and nowhere earlier."""
        result = self.run(image, "--help")
        assert result.returncode == 0, result.stdout + result.stderr
        assert "Policy and evidence kernel" in result.stdout

    def test_every_runtime_import_resolves(self, image: str) -> None:
        """Including psycopg, whose compiled extension is the one most likely
        to be built for the wrong ABI."""
        result = subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "--entrypoint",
                "python3.12",
                image,
                "-c",
                "import qed, psycopg, pydantic, fastapi, uvicorn, cryptography, yaml, "
                "sqlite3, httpx, qed_verify; print('ok')",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        assert "ok" in result.stdout

    def test_the_packaged_data_files_are_there(self, image: str) -> None:
        """The second bug this class exists for: the wheel was missing
        `compliance/frameworks.yaml`, so the image started and died on the
        first request."""
        result = subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "--entrypoint",
                "python3.12",
                image,
                "-c",
                "from qed.compliance.loader import frameworks; "
                "from qed.core.policy.loader import baseline_pack_dir; "
                "import pathlib; "
                "assert frameworks(); "
                "assert list(pathlib.Path(baseline_pack_dir()).glob('*.yaml')); "
                "print('data ok')",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        assert "data ok" in result.stdout

    def test_it_decides_a_proposal_and_the_chain_verifies(self, image: str, tmp_path: Path) -> None:
        """End to end in the shipped artifact: keys, a decision, an export,
        and the independent verifier -- run on the host, against the chain the
        container wrote."""
        import json

        from qed_verify.verify import load_jsonl, verify_records

        from qed.infra.keys.file import PUBLIC_DIR_NAME, load_public_keys
        from tests.conftest import BASE_PROPOSAL

        state = tmp_path / "state"
        state.mkdir()
        (state / "proposal.json").write_text(json.dumps(BASE_PROPOSAL), encoding="utf-8")
        mount = f"{state}:/var/lib/qed"

        def inside(*args: str) -> subprocess.CompletedProcess[str]:
            return subprocess.run(
                ["docker", "run", "--rm", "-v", mount, image, *args],
                capture_output=True,
                text=True,
                check=False,
            )

        keys = inside("keys", "init", "--dir", "/var/lib/qed")
        assert keys.returncode == 0, keys.stdout + keys.stderr

        check = inside("check", "/var/lib/qed/proposal.json", "--dir", "/var/lib/qed")
        # 0 ALLOW, 2 BLOCK, 3 REQUIRE_APPROVAL -- any of them is the kernel
        # working. 1 would be a malfunction.
        assert check.returncode in {0, 2, 3}, check.stdout + check.stderr

        export = inside("export", "--dir", "/var/lib/qed")
        assert export.returncode == 0, export.stderr
        report = verify_records(
            load_jsonl(export.stdout), load_public_keys(state / PUBLIC_DIR_NAME)
        )
        assert report.ok, report.summary()
