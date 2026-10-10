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

import os
import platform
import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
DOCKERFILE = REPO / "deploy" / "Dockerfile"
STAGE_SCRIPT = REPO / "deploy" / "stage-libs.sh"
TAG = "qed-test:pytest"

#: The architecture this machine is not. Release builds both.
FOREIGN_PLATFORM = "linux/arm64" if platform.machine() in {"x86_64", "AMD64"} else "linux/amd64"


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

    def test_the_builder_image_is_pinned_to_a_version(self) -> None:
        """The `BUILDER_IMAGE` arg exists to point at a *mirror*, not to choose
        a different Python: the runtime copies this interpreter and `qed`
        requires 3.12, so a default that did not name the version would make
        the ABI mismatch this file exists for possible again."""
        text = dockerfile()
        assert "ARG BUILDER_IMAGE=python:3.12-" in text

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

    def test_no_architecture_triplet_is_hardcoded(self) -> None:
        """`x86_64-linux-gnu` was, and the arm64 image therefore put every
        shared library in a directory that architecture's loader does not look
        in -- `python3.12: error while loading shared libraries:
        libpython3.12.so.1.0`. Nothing caught it because this file only ever
        built for the host.
        """
        for path in (DOCKERFILE, STAGE_SCRIPT):
            text = path.read_text(encoding="utf-8")
            code = "\n".join(line for line in text.splitlines() if not line.strip().startswith("#"))
            assert "x86_64-linux-gnu" not in code, (
                f"{path.name} hardcodes an architecture; derive it from "
                "`sysconfig.get_config_var('MULTIARCH')`"
            )

    def test_the_stage_script_asserts_libpython_is_there(self) -> None:
        """The one library whose absence stops the interpreter before it can
        say anything useful, so it is checked by name rather than trusted to
        the count."""
        assert "libpython3.12.so.1.0" in STAGE_SCRIPT.read_text(encoding="utf-8")

    def test_the_stage_script_has_unix_line_endings(self) -> None:
        """`sh` reads the carriage return as part of the argument: `set -eu\\r`
        is `set: Illegal option -`, from a script that looks correct in every
        editor."""
        assert b"\r" not in STAGE_SCRIPT.read_bytes()


# --------------------------------------------------------------------------
# Real
# --------------------------------------------------------------------------


#: Every probe below runs at **import** time, which is collection time for the
#: whole suite. An unbounded `subprocess.run` there is a suite that hangs
#: instead of failing, with no test name to blame and nothing on stdout -- and
#: it is `docker` being asked, so a busy daemon or a stalled pull is the
#: ordinary case, not the exotic one. A probe that cannot answer in time is a
#: probe that answers False.
PROBE_TIMEOUT_S = 20
PULL_TIMEOUT_S = 180


def _probe(argv: list[str], timeout: int) -> subprocess.CompletedProcess[str] | None:
    """Run `argv`, or None if it could not answer within `timeout`."""
    try:
        return subprocess.run(argv, capture_output=True, text=True, check=False, timeout=timeout)
    except subprocess.TimeoutExpired:
        print(f"probe timed out after {timeout}s: {' '.join(argv)}")
        return None


def docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    probe = _probe(["docker", "info", "--format", "{{.ServerVersion}}"], PROBE_TIMEOUT_S)
    return probe is not None and probe.returncode == 0


@pytest.fixture(scope="module")
def image(tmp_path_factory: pytest.TempPathFactory) -> str:
    """Build once for the whole module. A minute, and then four cheap tests.

    The build log goes to a file rather than a pipe. A container build writes
    megabytes, and this suite runs with ``filterwarnings = ["error"]``, where
    a decode failure on `subprocess`'s reader thread is a test error rather
    than a warning -- reported against whichever test happened to be running.
    """
    log = tmp_path_factory.mktemp("docker") / "build.log"
    # CI points this at AWS's mirror of the same official image, because Docker
    # Hub's unauthenticated pull limit is per runner IP and shared -- a failure
    # that looks like ours and is not.
    mirror = os.environ.get("QED_BUILDER_IMAGE")
    build_args = ["--build-arg", f"BUILDER_IMAGE={mirror}"] if mirror else []
    command = [
        "docker",
        "build",
        *build_args,
        "-f",
        str(DOCKERFILE),
        "-t",
        TAG,
        str(REPO),
    ]
    with log.open("wb") as sink:
        build = subprocess.run(
            command,
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

        # A bind mount keeps the host's ownership, and the image's own user is
        # 65532, so on Linux the container cannot write the directory it was
        # handed. Running as the host user is what an operator does with a bind
        # mount -- and it is worth asserting, because an image that only works
        # as uid 65532 cannot be run under an arbitrary one, which is what a
        # restrictive `runAsUser` admission policy will do to it.
        #
        # None of this applies to the two arrangements the docs recommend: a
        # named Docker volume takes its ownership from the image, and the Helm
        # chart sets `fsGroup: 65532`.
        user: list[str] = []
        if hasattr(os, "getuid"):
            user = ["--user", f"{os.getuid()}:{os.getgid()}"]

        def inside(*args: str) -> subprocess.CompletedProcess[str]:
            return subprocess.run(
                ["docker", "run", "--rm", *user, "-v", mount, image, *args],
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


#: A tiny image the probe starts under emulation. Pulled in its own step so a
#: registry failure is not mistaken for a missing emulator.
PROBE_IMAGE = "public.ecr.aws/docker/library/busybox:latest"


def emulation_available() -> bool:
    """Whether this machine can run a foreign architecture.

    Docker Desktop ships QEMU; a bare Linux runner needs `binfmt` installed.
    Without it the build still succeeds and the image cannot be started, which
    is the half that matters here -- so the test skips rather than passing on
    the easy half.

    The pull is a separate step from the run. One probe that did both returned
    the same False for "this machine has no emulator" and "the registry did not
    answer just then", and the second of those made the arm64 tests vanish from
    a CI run on a workflow that had installed the emulator a step earlier. A
    skip that is really a transient failure is the worst outcome available: it
    is a green run with the test that caught the last arm64 bug not having run.
    """
    if not docker_available():
        return False
    pull = _probe(["docker", "pull", "--platform", FOREIGN_PLATFORM, PROBE_IMAGE], PULL_TIMEOUT_S)
    if pull is None or pull.returncode != 0:
        # Not an answer about emulation. Say so, and let `QED_REQUIRE_EMULATION`
        # decide whether a run that cannot tell is allowed to pass.
        detail = "timed out" if pull is None else pull.stderr.strip()[-500:]
        print(f"emulation probe could not pull {PROBE_IMAGE}: {detail}")
        return False
    probe = _probe(
        ["docker", "run", "--rm", "--platform", FOREIGN_PLATFORM, PROBE_IMAGE, "true"],
        PROBE_TIMEOUT_S,
    )
    return probe is not None and probe.returncode == 0


@pytest.fixture(scope="module")
def foreign_image(tmp_path_factory: pytest.TempPathFactory) -> str:
    tag = "qed-test:foreign"
    log = tmp_path_factory.mktemp("docker-foreign") / "build.log"
    with log.open("wb") as sink:
        build = subprocess.run(
            [
                "docker",
                "buildx",
                "build",
                "--platform",
                FOREIGN_PLATFORM,
                "-f",
                str(DOCKERFILE),
                "-t",
                tag,
                "--load",
                str(REPO),
            ],
            stdout=sink,
            stderr=subprocess.STDOUT,
            check=False,
        )
    assert build.returncode == 0, log.read_text(encoding="utf-8", errors="replace")[-4000:]
    return tag


#: Set by CI, which installs the emulator itself: there, a skip is a failure.
#: The workflow used to catch this with "something skipped" over the whole
#: file, which named the symptom and not the test.
REQUIRE_EMULATION = os.environ.get("QED_REQUIRE_EMULATION") == "1"


#: Asked once. Where emulation is *required* the tests run anyway and fail with
#: Docker's own output, which says more than any message composed here -- and a
#: `pytest.fail` during collection would be a collection error rather than a
#: named failing test.
NO_EMULATION = not emulation_available()


@pytest.mark.slow
@pytest.mark.skipif(
    NO_EMULATION and not REQUIRE_EMULATION,
    reason="no emulation for another architecture",
)
class TestTheImageWorksOnTheOtherArchitecture:
    """The gap that shipped: `/usr/lib/x86_64-linux-gnu` was hardcoded, so the
    arm64 image put every shared library where that loader does not look and
    could not start. The release workflow builds both architectures; this file
    only ever built for the host, so nothing said so until a tag did.

    One build and one start, under emulation. Slow -- minutes, not seconds --
    which is why it is `slow` and why the assertion is "it runs" rather than
    anything about performance.
    """

    def test_the_emulator_is_actually_here(self) -> None:
        """First in the class, so a missing emulator is named rather than
        showing up as a confusing build failure three minutes later."""
        assert not NO_EMULATION, (
            f"QED_REQUIRE_EMULATION=1 and this machine cannot start a "
            f"{FOREIGN_PLATFORM} image. The job installed the emulator, so this is "
            "a broken binfmt setup or a registry that did not answer -- the probe "
            "printed which. These tests are not skipped here, because a skip would "
            "be a green run with the test that caught the last arm64 bug not having "
            "run."
        )

    def test_it_starts(self, foreign_image: str) -> None:
        result = subprocess.run(
            ["docker", "run", "--rm", "--platform", FOREIGN_PLATFORM, foreign_image, "--help"],
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        assert "Policy and evidence kernel" in result.stdout

    def test_the_libraries_are_where_that_loader_looks(self, foreign_image: str) -> None:
        """The specific failure, asserted specifically."""
        result = subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "--platform",
                FOREIGN_PLATFORM,
                "--entrypoint",
                "python3.12",
                foreign_image,
                "-c",
                "import pathlib, sysconfig; "
                "triplet = sysconfig.get_config_var('MULTIARCH'); "
                "path = pathlib.Path('/usr/lib') / triplet / 'libpython3.12.so.1.0'; "
                "assert path.exists(), f'{path} missing'; print(triplet)",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        assert "linux-gnu" in result.stdout
