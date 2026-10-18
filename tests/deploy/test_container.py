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
import time
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


class TestWhereTheBaseImageComesFrom:
    """The build depends on a third party that is allowed to say no.

    It said no on 2026-10-15: ECR Public answered `429 Too Many Requests --
    Data limit exceeded` to an anonymous pull, four tests errored, and the
    `deploy` required check went red on a commit about something else. These
    tests are static, so they run everywhere and cost nothing -- the mirror
    list is the kind of thing that rots quietly between the rare occasions it
    is exercised.
    """

    def test_there_is_more_than_one_registry(self) -> None:
        """One mirror is a single point of failure with extra steps. The
        quotas are per source address and CI runners share addresses, so the
        second and third entries have to be different *hosts*, not different
        paths on the same one."""
        hosts = {
            mirror.split("/")[0] if "." in mirror.split("/")[0] else "docker.io"
            for mirror in BUILDER_MIRRORS
        }
        assert len(hosts) == len(BUILDER_MIRRORS), f"not independent registries: {hosts}"

    def test_ci_pulls_postgres_from_more_than_one_registry_too(self) -> None:
        """The same argument, applied to the place it was not applied.

        The builder image got a mirror list on 2026-10-15 and the Postgres
        service container did not, because a `services:` block takes exactly
        one `image:` and cannot have a list. On 2026-10-17 `public.ecr.aws`
        refused again and the `postgres` job died before its first step --
        the identical outage, in the half that had not been fixed, which is
        finding #58's shape and the second time it has recurred.

        So that job now pulls in a step and starts the container itself. This
        test is what stops it going back: it reads the workflow rather than
        trusting the comment there, because a comment explaining why
        something is safe is exactly where this project has twice found
        something unsafe.

        Two earlier versions of this test were wrong, and both in ways worth
        leaving on the record. The first sliced the job out of the file by
        looking for the next two-space-indented line -- which is every key
        inside `steps:` as well -- so it read a fragment. The second parsed
        the YAML properly and then hunted the shell script with a regex,
        where it matched the words `no registry served postgres:17` inside an
        error message and concluded Docker Hub was a fallback. It passed with
        one registry configured. That is finding #48 again: prose answering a
        question that was asked of configuration.

        So the list is a variable now, and this reads the variable.
        """
        import yaml as pyyaml

        workflow = pyyaml.safe_load(
            (REPO / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        )
        job = workflow["jobs"]["postgres"]

        assert "services" not in job, (
            "the postgres job is back on a service container, which can name "
            "only one registry and therefore has no fallback"
        )

        images = job["env"]["POSTGRES_MIRRORS"].split()
        hosts = {
            image.split("/")[0] if "." in image.split("/")[0] else "docker.io" for image in images
        }
        assert len(hosts) == len(images), f"not independent registries: {hosts}"
        assert len(images) >= 2, f"postgres is pulled from one registry only: {images}"

        # A list nothing reads is a list that is not doing anything -- the
        # shape of #60, where a plumbed parameter with a plausible default was
        # invisible for twelve weeks.
        runs = "\n".join(step["run"] for step in job["steps"] if "run" in step)
        assert "$POSTGRES_MIRRORS" in runs, (
            "POSTGRES_MIRRORS is set and never used, so the job pulls from "
            "wherever the script happens to name"
        )

    def test_every_mirror_names_the_same_interpreter(self) -> None:
        """The whole point of the list is that it does not matter which one
        answers. The runtime stage copies the builder's Python, so a mirror
        naming a different version would make the build's correctness depend
        on which registry was throttling that hour -- the ABI mismatch in this
        module's docstring, arriving at random."""
        for mirror in BUILDER_MIRRORS:
            assert mirror.endswith(f":{BUILDER_TAG}"), mirror

    def test_the_mirrors_agree_with_the_dockerfile_default(self) -> None:
        """A `BUILDER_IMAGE` arg whose default drifts from the list means a
        local `docker build` and CI are building different images."""
        assert f"ARG BUILDER_IMAGE=python:{BUILDER_TAG}" in dockerfile()

    def test_a_pinned_image_is_tried_first_but_is_not_the_only_one(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """CI pins one to express a preference. Reading that as the only
        permitted source is the bug: it turned a registry's hourly quota into
        a red `main`."""
        monkeypatch.setenv("QED_BUILDER_IMAGE", "registry.example/python:" + BUILDER_TAG)
        candidates = _builder_candidates()
        assert candidates[0] == "registry.example/python:" + BUILDER_TAG
        assert len(candidates) == len(BUILDER_MIRRORS) + 1
        assert set(BUILDER_MIRRORS) <= set(candidates)

    def test_pinning_a_mirror_does_not_duplicate_it(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """CI pins the ECR mirror, which is already in the list. Trying it
        twice in a row is exactly the retry-the-same-host behaviour the list
        replaced."""
        monkeypatch.setenv("QED_BUILDER_IMAGE", BUILDER_MIRRORS[0])
        candidates = _builder_candidates()
        assert candidates == BUILDER_MIRRORS
        assert len(candidates) == len(set(candidates))

    def test_a_platform_is_asked_for_when_one_is_given(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The arm64 build must pull the arm64 manifest, not the host's.

        Resolving against the host and then building for another architecture
        looks like it works -- the pull succeeds -- and leaves `docker buildx`
        to fetch the foreign manifest itself, from the one registry, with no
        fallback. That shipped, and ECR Public's byte quota failed the arm64
        build an hour later while the amd64 build beside it passed.
        """
        seen: list[list[str]] = []

        def record(argv: list[str], timeout: int) -> subprocess.CompletedProcess[str]:
            seen.append(argv)
            return subprocess.CompletedProcess(argv, 0, "", "")

        monkeypatch.setattr("tests.deploy.test_container._probe", record)
        image, _ = _pull_first_available(("example/thing:1",), 10, platform="linux/arm64")
        assert image == "example/thing:1"
        assert seen == [["docker", "pull", "--platform", "linux/arm64", "example/thing:1"]]

    def test_no_platform_is_asked_for_when_none_is_given(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """`--platform` on the host build would pin it to whatever this
        machine is, which is the opposite of what a default should do."""
        seen: list[list[str]] = []

        def record(argv: list[str], timeout: int) -> subprocess.CompletedProcess[str]:
            seen.append(argv)
            return subprocess.CompletedProcess(argv, 0, "", "")

        monkeypatch.setattr("tests.deploy.test_container._probe", record)
        _pull_first_available(("example/thing:1",), 10)
        assert seen == [["docker", "pull", "example/thing:1"]]

    def test_the_next_registry_is_tried_when_the_first_refuses(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A 429 from one host must reach the next host, not a retry of the
        same one -- the quotas are per source address and a runner cannot
        change its address."""
        refused = subprocess.CompletedProcess(
            [], 1, "", "429 Too Many Requests: toomanyrequests: Data limit exceeded"
        )
        attempts: list[str] = []

        def record(argv: list[str], timeout: int) -> subprocess.CompletedProcess[str]:
            attempts.append(argv[-1])
            if argv[-1] == "first/one:1":
                return refused
            return subprocess.CompletedProcess(argv, 0, "", "")

        monkeypatch.setattr("tests.deploy.test_container._probe", record)
        image, why_not = _pull_first_available(("first/one:1", "second/two:1"), 10)
        assert image == "second/two:1"
        assert why_not == ""
        assert attempts == ["first/one:1", "second/two:1"]

    def test_every_refusal_is_reported_when_none_answer(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The failure message has to name what each registry said. A test
        that fails with "could not pull" sends whoever reads CI to reproduce
        an environment they do not have."""
        monkeypatch.setattr(
            "tests.deploy.test_container._probe",
            lambda argv, timeout: subprocess.CompletedProcess(argv, 1, "", "429 from " + argv[-1]),
        )
        monkeypatch.setattr("tests.deploy.test_container.PULL_BACKOFF_S", 0.0)
        image, why_not = _pull_first_available(("first/one:1", "second/two:1"), 10)
        assert image is None
        assert "first/one:1" in why_not
        assert "second/two:1" in why_not

    def test_no_pin_means_the_mirror_list(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("QED_BUILDER_IMAGE", raising=False)
        assert _builder_candidates() == BUILDER_MIRRORS

    def test_an_empty_pin_is_not_a_registry(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """`env: QED_BUILDER_IMAGE: ${{ vars.THING }}` with the variable unset
        is the empty string, not an absent variable. Passed through, it
        becomes `--build-arg BUILDER_IMAGE=` and the build fails on an empty
        `FROM`."""
        monkeypatch.setenv("QED_BUILDER_IMAGE", "   ")
        assert _builder_candidates() == BUILDER_MIRRORS


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


#: One more round after the first, because a throttle is often over in seconds.
PULL_ROUNDS = 2
PULL_BACKOFF_S = 5.0


def _pull_first_available(
    candidates: tuple[str, ...], timeout: int, platform: str | None = None
) -> tuple[str | None, str]:
    """The first of `candidates` that pulls, or why none of them did.

    Every image this file needs comes from a registry that can refuse, and the
    refusal that matters is not an outage: it is a quota. `public.ecr.aws`
    answers `429 Too Many Requests -- Data limit exceeded` and Docker Hub
    answers `toomanyrequests`, both counted **per source address**, and CI
    runners share addresses with everyone else on the pool. So the answer is
    not a longer retry against the same host -- it is another host, and only
    then another round.
    """
    attempts: list[str] = []
    for round_number in range(PULL_ROUNDS):
        if round_number:
            time.sleep(PULL_BACKOFF_S)
        for image in candidates:
            argv = ["docker", "pull", *(["--platform", platform] if platform else []), image]
            pull = _probe(argv, timeout)
            if pull is None:
                attempts.append(f"{image}: timed out after {timeout}s")
                continue
            if pull.returncode == 0:
                return image, ""
            attempts.append(f"{image}: {pull.stderr.strip()[-200:]}")
    return None, "; ".join(attempts)


#: Mirrors of the **same** official Python image, tried in order.
#:
#: They must all name the same interpreter. The runtime stage copies the
#: builder's Python, so a fallback that quietly built on 3.13 would reproduce
#: the ABI mismatch described at the top of this file -- from a green build,
#: on a day when one registry happened to be throttling.
#: `test_every_mirror_names_the_same_interpreter` holds the list to that.
#:
#: Why a list at all: on 2026-10-15 `public.ecr.aws` answered 429 to the
#: anonymous pull and took `deploy` -- a required check -- down with it, on a
#: commit that touched none of this. The probe image below has had a mirror
#: list since the last time a registry did this to us; the builder, the bigger
#: pull in the job that gates releases, did not. The fix had been applied to
#: the cheap half only.
BUILDER_TAG = "3.12-slim-bookworm"
BUILDER_MIRRORS = (
    f"public.ecr.aws/docker/library/python:{BUILDER_TAG}",
    f"mirror.gcr.io/library/python:{BUILDER_TAG}",
    f"python:{BUILDER_TAG}",
)


def _builder_candidates() -> tuple[str, ...]:
    """`QED_BUILDER_IMAGE` first when set, then every mirror.

    CI sets that variable to express a *preference* -- try AWS's mirror before
    Docker Hub -- and the fixture used to read it as the only permitted
    source, which is how one registry's hourly data cap became a red `main`.
    A preference it remains; the fallbacks are what make it safe to have one.
    """
    pinned = os.environ.get("QED_BUILDER_IMAGE", "").strip()
    if not pinned:
        return BUILDER_MIRRORS
    return (pinned, *(mirror for mirror in BUILDER_MIRRORS if mirror != pinned))


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
    # The base image is pulled in its own step, before the build, for the same
    # reason the emulation probe pulls separately: a registry that refuses and
    # a Dockerfile that is wrong are different problems, and `docker build`
    # reports them identically -- as a failed build, against this commit.
    #
    # Pulling first is also what makes a mirror list usable at all. Inside a
    # build there is one `FROM` and no second chance.
    base, why_not = _pull_first_available(_builder_candidates(), PULL_TIMEOUT_S)
    assert base is not None, (
        "no registry would serve the builder base image, so the container could "
        "not be built. This is the environment and not the commit -- but it is "
        "deliberately a failure and not a skip, because a skip here is a green "
        f"`deploy` with the image never built. Tried: {why_not}"
    )
    command = [
        "docker",
        "build",
        "--build-arg",
        f"BUILDER_IMAGE={base}",
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


#: Tiny images the probe starts under emulation, tried in order. Pulled in
#: their own step so a registry failure is not mistaken for a missing emulator.
#:
#: Three registries rather than one, because the failure this list exists for
#: has happened: ECR Public answered `toomanyrequests: Rate exceeded` to an
#: anonymous pull and failed the `deploy` job, which is a required status check.
#: The rate limit is per source address and CI runners share addresses, so
#: retrying the same host is the weakest possible answer -- `mirror.gcr.io` is a
#: pull-through cache of Docker Hub with its own budget, and Docker Hub is a
#: third party again. All three being throttled in the same minute is not a
#: thing to design around.
#:
#: Deliberately still not a skip. See `test_the_emulator_is_actually_here`: a
#: skip here would be a green run with the test that caught the last arm64 bug
#: not having run.
PROBE_IMAGES = (
    "public.ecr.aws/docker/library/busybox:latest",
    "mirror.gcr.io/library/busybox:latest",
    "busybox:latest",
)

#: Shorter than `PULL_TIMEOUT_S`, which sizes the builder base -- a far larger
#: image than busybox. Six attempts at
#: that timeout is an eighteen-minute stall at collection time if the network
#: blackholes rather than refuses, and collection is where nothing is reported
#: yet. A busybox manifest and one layer is seconds; a minute is already
#: generous, and the budget for the whole probe is now bounded by it.
PROBE_PULL_TIMEOUT_S = 60


def _pull_probe_image() -> tuple[str | None, str]:
    """The first probe image that pulls, or why none of them did."""
    image, why_not = _pull_first_available(
        PROBE_IMAGES, PROBE_PULL_TIMEOUT_S, platform=FOREIGN_PLATFORM
    )
    if image is None:
        return None, "no probe image could be pulled -- " + why_not
    return image, ""


def emulation_available() -> tuple[bool, str]:
    """Whether this machine can run a foreign architecture, and why not.

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

    **It returns the reason rather than printing it.** The first version
    printed, and a failing CI run then said "the probe printed which" with no
    probe output anywhere in the log: this runs at import, which is collection
    time, and pytest discards module-level stdout under `-q`. A guard that
    reports its symptom and not its cause is half a guard, and the half it
    keeps is the one that cannot be acted on.
    """
    if not docker_available():
        return False, "no Docker daemon answered `docker info`"

    image, why_not = _pull_probe_image()
    if image is None:
        # Not an answer about emulation at all: no registry cooperated.
        return False, why_not

    probe = _probe(
        ["docker", "run", "--rm", "--platform", FOREIGN_PLATFORM, image, "true"],
        PROBE_TIMEOUT_S,
    )
    if probe is None:
        return False, f"starting a {FOREIGN_PLATFORM} image timed out after {PROBE_TIMEOUT_S}s"
    if probe.returncode != 0:
        return False, (
            f"a {FOREIGN_PLATFORM} image would not start, which is what a missing or "
            f"broken binfmt looks like: {probe.stderr.strip()[-400:]}"
        )
    return True, ""


@pytest.fixture(scope="module")
def foreign_image(tmp_path_factory: pytest.TempPathFactory) -> str:
    tag = "qed-test:foreign"
    log = tmp_path_factory.mktemp("docker-foreign") / "build.log"
    # The same mirror list, resolved **for the architecture this actually
    # builds**. The first version resolved against the host, on the reasoning
    # that a quota belongs to the registry and the source address rather than
    # to the manifest being asked for -- so a registry that had just served
    # amd64 would serve arm64 too. That was wrong, and CI said so within the
    # hour: ECR Public's limit is on bytes transferred, the amd64 pull spent
    # what was left of it, and the arm64 manifest came back 429 while the
    # host build beside it had succeeded. Pulling the foreign manifest here is
    # what lets this fall through to the next registry, which is the whole
    # point of having a list.
    base, why_not = _pull_first_available(
        _builder_candidates(), PULL_TIMEOUT_S, platform=FOREIGN_PLATFORM
    )
    assert base is not None, (
        f"no registry would serve the {FOREIGN_PLATFORM} builder base image: {why_not}"
    )
    with log.open("wb") as sink:
        build = subprocess.run(
            [
                "docker",
                "buildx",
                "build",
                "--platform",
                FOREIGN_PLATFORM,
                "--build-arg",
                f"BUILDER_IMAGE={base}",
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


#: Asked once, with the reason kept for the failure message. A `pytest.fail`
#: during collection would be a collection error rather than a named failing
#: test, so the verdict is carried instead of raised.
_HAS_EMULATION, EMULATION_REASON = emulation_available()
NO_EMULATION = not _HAS_EMULATION


class TestTheProbeSaysWhy:
    """Runs everywhere, including where emulation is absent.

    The class below is skipped on a laptop with no binfmt, so the thing that
    would catch a probe reporting no reason is skipped exactly when it matters.
    This is not -- and it does not skip in the other direction either: the
    `deploy` job fails on *any* skip in this directory, so a test that skipped
    when emulation works would turn a healthy runner red.
    """

    def test_the_verdict_and_its_reason_agree(self) -> None:
        """A no must say why, and name which half failed.

        Otherwise the failure message reads "The probe says: " and whoever is
        reading CI has to reproduce the environment to find out why -- which
        was the actual outcome of the first version, which printed the reason
        at collection time where `-q` discards it.

        "The registry did not answer" and "there is no emulator" are different
        problems with different fixes, so the reason has to separate them.
        """
        if not NO_EMULATION:
            assert EMULATION_REASON == "", "a yes should carry no reason"
            return

        assert EMULATION_REASON.strip(), (
            "the probe said no and gave no reason, which is the bug this pair of "
            "values exists to prevent"
        )
        lowered = EMULATION_REASON.lower()
        assert any(word in lowered for word in ("pull", "binfmt", "docker daemon", "timed out")), (
            EMULATION_REASON
        )


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
        showing up as a confusing build failure three minutes later.

        The reason is in the message because it has to be: it is gathered at
        collection time, and nothing printed then survives `-q`.
        """
        assert not NO_EMULATION, (
            f"QED_REQUIRE_EMULATION=1 and this machine cannot run {FOREIGN_PLATFORM}. "
            f"The probe says: {EMULATION_REASON}\n"
            "The job installs the emulator a step earlier, so this is either a broken "
            "binfmt setup or a registry that did not answer -- and the sentence above "
            "says which. These tests are not skipped here, because a skip would be a "
            "green run with the test that caught the last arm64 bug not having run."
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
