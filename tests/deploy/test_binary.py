"""The single-file binary (SPEC §22 week 10, §24.1).

Two kinds of test here, and the split is the point.

The **static** ones read `deploy/qed.spec` and cost nothing. They exist because
the spec file carries a second copy of facts that live elsewhere -- the data
files, the lazy imports, the `pathex` roots -- and two copies of the same list
are two chances to be wrong. `tests/test_packaging.py` already makes that
argument about the wheel; this makes it about the binary.

The **real** one builds the binary and drives it, and is `slow`. It is the only
test that can tell you the thing worth knowing, which is not "PyInstaller
succeeded" but "the commands a brew user runs actually work". Building proves
very little: the first build of this succeeded and then `qed verify` told a user
with no Python to run `pip install`, because `qed_verify` is an editable install
and the bundler needed its directory on `pathex`.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import ClassVar, cast

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
SPEC = ROOT / "deploy" / "qed.spec"
WORKFLOWS = ROOT / ".github" / "workflows"


def spec_text() -> str:
    return SPEC.read_text(encoding="utf-8")


# --------------------------------------------------------------------------
# Static: the spec file agrees with the rest of the repository
# --------------------------------------------------------------------------


class TestTheSpecFile:
    def test_it_exists_where_the_docs_say(self) -> None:
        assert SPEC.exists()

    def test_it_builds_the_cli_and_not_a_module_path(self) -> None:
        """`qed/cli.py`, not `-m qed.cli`: a frozen `-m` entry point resolves
        `__main__` differently and typer's command group goes missing."""
        assert '"qed" / "cli.py"' in spec_text()

    def test_it_collects_every_extension_the_wheel_ships(self) -> None:
        """The data files are the thing most likely to drift, and the failure
        is remote from the cause: the binary starts and dies on the first
        request, exactly as the wheel once did (`tests/test_packaging.py`)."""
        with (ROOT / "pyproject.toml").open("rb") as handle:
            patterns = tomllib.load(handle)["tool"]["setuptools"]["package-data"]["qed"]
        extensions = {Path(pattern).suffix for pattern in patterns}
        text = spec_text()
        for extension in extensions:
            assert f"**/*{extension}" in text, (
                f"the wheel ships {extension} files and the binary spec does not collect them"
            )

    def test_it_puts_the_verifier_package_on_the_path(self) -> None:
        """`qed_verify` is an editable install in `packages/qed-verify/`.
        `collect_submodules` finds its *names* through the editable finder
        while the bundler needs the directory. Without this the binary builds
        and `qed verify` tells a user with no Python to run `pip install`."""
        assert '"packages" / "qed-verify"' in spec_text()

    def test_it_names_the_lazily_imported_packages(self) -> None:
        """`qed/cli.py` imports its heavy dependencies inside functions, by
        design (SPEC 20.3: `qed check` must not pay for the MCP SDK). That is
        precisely what static analysis cannot follow, so each one is listed."""
        text = spec_text()
        for package in ("qed", "qed_verify", "uvicorn", "keyring"):
            assert f'collect_submodules("{package}")' in text, package

    def test_upx_is_off(self) -> None:
        """It breaks code signing on macOS, and a binary that cannot be
        notarised is one a Homebrew user cannot run without a warning."""
        assert "upx=False" in spec_text()

    def test_it_is_a_console_binary(self) -> None:
        assert "console=True" in spec_text()


class TestTheHomebrewFormula:
    """It is a template in this repository and a file in `valqore/tap`.

    Kept here so the binary and the formula that installs it change together.
    These tests are about the two of them agreeing, not about Ruby.
    """

    FORMULA = ROOT / "deploy" / "homebrew" / "qed.rb.template"

    def formula(self) -> str:
        return self.FORMULA.read_text(encoding="utf-8")

    def test_it_exists(self) -> None:
        assert self.FORMULA.exists()

    def test_it_is_a_template_and_says_so(self) -> None:
        """The tap repository was reserved on 2026-10-17 and is private, so
        the reason this file keeps its placeholders has changed: it is no
        longer that there is nowhere to put a rendered formula, it is that
        there must be exactly one source of truth for it. The tap's copy is
        `render.sh`'s output; a filled-in formula here would be a second."""
        text = self.formula()
        assert self.FORMULA.suffix == ".template"
        assert "not published" in text
        assert "VERSION" in text and "SHA256_" in text

    def test_it_names_every_asset_the_release_builds(self) -> None:
        """The formula downloads by name. A label added to the release matrix
        and not here is a platform nobody can `brew install`."""
        labels = binary_labels()
        text = self.formula()
        for label in labels:
            assert label in text, f"the release builds {label} and the formula ignores it"

    def test_its_test_block_checks_more_than_the_version(self) -> None:
        """A `--version` passes on a binary whose data files are missing. The
        wheel shipped that bug once and the container shipped it again, so the
        formula's own test runs `policy lint` and verifies a chain."""
        text = self.formula()
        assert "policy lint" in text
        assert "qed verify" in text


class TestTheTapDriftCheck:
    """`.github/workflows/tap-drift.yml` must notice a tap left behind.

    `release.yml` publishes to PyPI, GHCR, the Helm registry and a GitHub
    release and does not touch the Homebrew tap. `valqore/homebrew-tap`'s
    formula is rendered by hand, and a step done by hand is a step that gets
    skipped: the tap served 1.0.0 while this repository shipped 1.1.0 and then
    1.1.1, so `brew install valqore/tap/qed` was two releases behind and
    nothing said so.

    Finding #72 is why this cannot be a unit test. A guard inside a repository
    cannot see a surface the repository never reaches; the tap is a different
    repository and `brew` is a different channel. So the workflow reads them
    live, and these tests only guard the workflow -- the two label lists
    agreeing, the failure being a failure, and the gotchas staying written
    down.
    """

    CHECK: ClassVar[Path] = WORKFLOWS / "tap-drift.yml"

    def workflow(self) -> dict:
        return cast(dict, yaml.safe_load(self.CHECK.read_text(encoding="utf-8")))

    def run_blocks(self) -> str:
        """The executable lines of every `run:` body, and nothing else.

        Deliberately not the file's text. An assertion against the text of a
        workflow is answered by that workflow's own comments -- which is how a
        guard written an hour ago passed against the exact bug it was for
        (finding #48, in `runner-labels.yml`).

        `yaml.safe_load` is not enough on its own, which is the part that is
        easy to miss: it drops *YAML* comments, but a `#` line inside a `run:`
        block is a *shell* comment and lives on inside the parsed string. Two
        kinds of comment, one of them invisible to the parser. The first draft
        of this helper stopped at `safe_load`, and
        `test_it_reads_the_tap_through_the_api_not_the_raw_cdn` failed on the
        comment that explains why the check avoids the raw CDN.
        """
        steps = self.workflow()["jobs"]["tap"]["steps"]
        lines = [
            line
            for step in steps
            if "run" in step
            for line in step["run"].splitlines()
            if not line.strip().startswith("#")
        ]
        return "\n".join(lines)

    def steps(self) -> dict[str, str]:
        """Each step's executable lines, keyed by the step's name.

        `run_blocks()` concatenates everything, which is fine for "is this
        idea present anywhere" and useless for "does *this* step fail". Four
        steps here can each exit 1, so a search of the concatenation passed
        when the version comparison was softened to a warning and the other
        three still exited. Mutation 4, caught by running it.
        """
        out: dict[str, str] = {}
        for step in self.workflow()["jobs"]["tap"]["steps"]:
            if "run" not in step:
                continue
            body = "\n".join(
                line for line in step["run"].splitlines() if not line.strip().startswith("#")
            )
            out[str(step.get("name", ""))] = body
        return out

    def the_step_that(self, *needles: str) -> str:
        """The one step whose body mentions all of `needles`.

        Found by content rather than by name, so renaming a step does not
        silently stop testing it.
        """
        matches = [body for body in self.steps().values() if all(n in body for n in needles)]
        assert len(matches) == 1, (
            f"expected exactly one step mentioning {needles}, found {len(matches)}"
        )
        return matches[0]

    def test_the_check_exists(self) -> None:
        assert self.CHECK.exists()

    def test_it_requires_exactly_the_platforms_the_release_builds(self) -> None:
        """Both directions, same as the runner-label canary.

        A platform added to `release.yml` and not here is a `brew install` that
        404s for somebody with nothing to warn them -- and a platform required
        here that the release stopped building makes this check fail every
        Monday for a question nobody is asking.
        """
        required = set(re.findall(r"platforms=\"([^\"]+)\"", self.run_blocks()))
        assert len(required) == 1, "tap-drift.yml should set `platforms=` exactly once"
        probed = set(required.pop().split())
        built = binary_labels()

        missing = built - probed
        assert not missing, (
            f"release.yml builds {sorted(missing)} and tap-drift.yml does not require it. "
            "A platform the formula skips is one nobody can brew install."
        )
        stale = probed - built
        assert not stale, (
            f"tap-drift.yml requires {sorted(stale)}, which release.yml no longer builds. "
            "This check would fail every Monday for a platform that does not exist."
        )

    def test_it_runs_on_a_schedule(self) -> None:
        """The drift that matters is the tap trailing days later, so a Monday
        is what finds it. It cannot live in `release.yml`: the formula's
        checksums come from the release's own `.sha256` files, so the render
        can only happen after the release exists and a release-time check
        would fail every time, correctly and uselessly."""
        canary = self.workflow()
        # PyYAML parses the unquoted key `on` as the boolean True.
        triggers = canary.get("on") or canary.get(True)
        assert "schedule" in triggers, "tap-drift.yml has no schedule"
        assert triggers["schedule"][0]["cron"]

    def test_the_version_comparison_fails_rather_than_warns(self) -> None:
        """A notice nobody reads is not a guard.

        Asserted on the comparing step alone. `exit 1` appears in four steps
        here, so searching the whole workflow passed with this one softened to
        `::warning::` -- which is the exact bug, since a warning on a green run
        is how the tap got two releases behind in the first place.
        """
        comparing = self.the_step_that("$RELEASE", "$TAP")
        assert "exit 1" in comparing, (
            "the step comparing the tap against the release does not exit 1"
        )

    def test_it_says_how_to_fix_it(self) -> None:
        """The fix is a hand render in another repository, which nobody will
        remember. The error message carries the command."""
        blocks = self.run_blocks()
        assert "render.sh" in blocks
        assert "homebrew-tap" in blocks

    def test_it_checks_the_checksums_and_not_only_the_version(self) -> None:
        """A matching version with a stale hash is worse than a stale version:
        `brew install` fails on a checksum mismatch while the formula looks
        current. A version comparison alone cannot see that.

        Its own step, and that step has to fail too.
        """
        checksums = self.the_step_that(".sha256", "formula.rb")
        assert "gh release download " in checksums
        assert "exit 1" in checksums, "the checksum step reports and does not fail"

    def test_it_does_not_ask_for_the_latest_release(self) -> None:
        """`/releases/latest` excludes prereleases, and every QED release so
        far is marked prerelease -- it returns the wrong answer or none. The
        check lists releases and filters, and this keeps somebody from
        "simplifying" it back into the trap."""
        blocks = self.run_blocks()
        assert "releases/latest" not in blocks
        assert "gh release list" in blocks

    def test_it_reads_the_tap_through_the_api_not_the_raw_cdn(self) -> None:
        """`raw.githubusercontent.com` caches for minutes and served a stale
        version within seconds of the tap being pushed to 1.1.1, which would
        make this check fail on a tap that is in fact current."""
        blocks = self.run_blocks()
        assert "raw.githubusercontent" not in blocks
        assert "gh api repos/valqore/homebrew-tap" in blocks


def working_bash() -> str | None:
    """A `bash` that is actually bash, or `None`.

    `shutil.which("bash")` is not the question, and answering it broke `main`.
    On a GitHub `windows-latest` runner it returns
    `C:\\Windows\\System32\\bash.exe` -- the WSL launcher, with no distribution
    installed. It prints a UTF-16 message about `wsl --install -d <Distro>` and
    exits 1, so the skip never fired and four tests failed on a `bash` that
    exists and is not one.

    Git for Windows is on those runners as well and its bash works, so this
    prefers finding a working one over skipping: Windows runs these tests
    rather than pretending it cannot. Running `echo` is the only way to tell
    the difference, and it is cheap.
    """
    candidates = [
        "bash",
        r"C:\Program Files\Git\bin\bash.exe",
        r"C:\Program Files\Git\usr\bin\bash.exe",
    ]
    for candidate in candidates:
        resolved = shutil.which(candidate)
        if resolved is None:
            continue
        try:
            done = subprocess.run(
                [resolved, "-c", "echo qed"], capture_output=True, text=True, timeout=60
            )
        except (OSError, subprocess.SubprocessError):  # pragma: no cover - platform
            continue
        if done.returncode == 0 and done.stdout.strip() == "qed":
            return resolved
    return None


BASH = working_bash()


@pytest.mark.skipif(BASH is None, reason="no working bash (a WSL stub does not count)")
class TestRenderingTheFormula:
    """`render.sh` turns the template into the file that goes in the tap.

    It exists because the obvious alternative -- `sed 's/VERSION/1.0.0/g'` --
    was used once, by hand, to produce the tap's first formula, and it rewrote
    the template's own documentation into nonsense ("`1.0.0`, and the three
    SHA256 values, come from the release") while leaving the formula below it
    correct. The formula was right and the file was wrong, which is the shape
    of mistake nobody checks for.

    These tests feed it checksums from a directory instead of a release, which
    is why they need no network and no `gh`.
    """

    RENDER = ROOT / "deploy" / "homebrew" / "render.sh"

    PLATFORMS: ClassVar[dict[str, str]] = {
        "macos-arm64": "a" * 64,
        "macos-x86_64": "b" * 64,
        "linux-x86_64": "c" * 64,
    }

    def sums(self, directory: Path, platforms: dict[str, str] | None = None) -> str:
        """Write `.sha256` files shaped like the ones the release carries."""
        for platform, digest in (platforms or self.PLATFORMS).items():
            name = f"qed-9.9.9-{platform}"
            (directory / f"{name}.sha256").write_text(f"{digest}  {name}\n", encoding="utf-8")
        return str(directory).replace("\\", "/")

    def render(self, directory: Path, **kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [cast("str", BASH), str(self.RENDER), "9.9.9", self.sums(directory, **kwargs)],  # type: ignore[arg-type]
            capture_output=True,
            text=True,
        )

    def test_it_exists(self) -> None:
        assert self.RENDER.exists()

    def test_it_renders_a_formula_with_nothing_left_to_fill_in(self, tmp_path: Path) -> None:
        """A rendered formula still carrying `SHA256_LINUX_X86_64` is a
        `brew install` that dies on a checksum mismatch, and the only place to
        notice is the user's terminal."""
        done = self.render(tmp_path)
        assert done.returncode == 0, done.stderr

        body = [line for line in done.stdout.splitlines() if not line.lstrip().startswith("#")]
        assert body, "no formula came out"
        for line in body:
            assert "SHA256_" not in line
            assert "VERSION" not in line

        assert 'version "9.9.9"' in done.stdout
        for digest in self.PLATFORMS.values():
            assert f'sha256 "{digest}"' in done.stdout

    def test_each_platform_gets_its_own_checksum(self, tmp_path: Path) -> None:
        """Three URLs and three hashes, paired by platform. Pasting one hash
        into all three slots passes every check Homebrew makes at *build* time
        and fails for two thirds of users."""
        out = self.render(tmp_path).stdout
        for platform, digest in self.PLATFORMS.items():
            url = next(line for line in out.splitlines() if f"qed-9.9.9-{platform}" in line)
            following = out.splitlines()[out.splitlines().index(url) + 1]
            assert digest in following, f"{platform} is paired with the wrong checksum"

    def test_it_refuses_when_a_platform_has_no_checksum(self, tmp_path: Path) -> None:
        """The release matrix gaining a platform must fail here rather than
        ship a formula that quietly ignores it -- which is the same argument
        `test_it_names_every_asset_the_release_builds` makes in reverse."""
        done = self.render(tmp_path, platforms={"linux-x86_64": "c" * 64})
        assert done.returncode != 0
        assert "SHA256_MACOS_ARM64" in done.stderr

    def test_it_succeeds_quietly(self, tmp_path: Path) -> None:
        """A script that prints the right answer and exits 1 is a red CI run
        with nothing wrong in it. This one did: its `EXIT` trap ended in
        `[ -n "$tmp" ] && rm -rf "$tmp"`, which is false whenever no temporary
        directory was made, and a trap's last status becomes the exit status."""
        done = self.render(tmp_path)
        assert done.returncode == 0
        assert done.stderr == ""

    def test_it_names_the_command_that_produced_it(self, tmp_path: Path) -> None:
        """A generated file that says so without saying how is not checkable.
        Naming `render.sh` means a reader can run it and diff."""
        comments = [
            line
            for line in self.render(tmp_path).stdout.splitlines()
            if line.lstrip().startswith("#")
        ]
        assert comments, "the rendered formula has no header"
        assert any("render.sh" in line for line in comments)

    def test_the_prose_survives_substitution(self, tmp_path: Path) -> None:
        """The bug this script was written for, and the reason this test goes
        to the trouble of rendering a *modified* template.

        No comment in the real template happens to contain `VERSION` below the
        header, so a test that renders the real one passes whether comments are
        substituted or not -- it asserts something true on both sides of the
        change, which is a test this project has written before and does not
        want again. So: plant a comment that a blanket `sed` would mangle, and
        check it comes out intact.
        """
        work = tmp_path / "render"
        work.mkdir()
        shutil.copy(self.RENDER, work / "render.sh")

        planted = "  # VERSION and the SHA256_LINUX_X86_64 slot are filled by render.sh."
        template = (ROOT / "deploy" / "homebrew" / "qed.rb.template").read_text(encoding="utf-8")
        template = template.replace("class Qed < Formula", f"class Qed < Formula\n{planted}")
        (work / "qed.rb.template").write_text(template, encoding="utf-8")

        sums = tmp_path / "sums"
        sums.mkdir()
        done = subprocess.run(
            [cast("str", BASH), str(work / "render.sh"), "9.9.9", self.sums(sums)],
            capture_output=True,
            text=True,
        )
        assert done.returncode == 0, done.stderr
        assert planted in done.stdout.splitlines(), (
            "a comment mentioning a placeholder was rewritten; substitution must skip comment lines"
        )


# --------------------------------------------------------------------------
# Real: build it and drive it
# --------------------------------------------------------------------------


def pyinstaller_available() -> bool:
    try:
        import PyInstaller  # noqa: F401
    except ImportError:
        return False
    return True


@pytest.mark.slow
@pytest.mark.skipif(not pyinstaller_available(), reason="pyinstaller is not installed")
class TestTheBinaryActuallyRuns:
    """Builds once for the whole class, then a handful of cheap commands.

    Module scope on the fixture, not class scope: a class-scoped fixture that
    builds trips pytest's own `assert not self._finalizers`, which this project
    has now hit in three different files.
    """

    def run(self, binary: Path, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(binary), *args], capture_output=True, text=True, check=False, timeout=180
        )

    def test_it_starts_and_prints_help(self, binary: Path) -> None:
        result = self.run(binary, "--help")
        assert result.returncode == 0, result.stderr
        assert "Policy and evidence kernel" in result.stdout

    def test_it_reports_the_version_it_was_built_from(self, binary: Path) -> None:
        from qed.version import VERSION

        result = self.run(binary, "status", "--help")
        assert result.returncode == 0, result.stderr
        assert VERSION

    def test_the_policy_pack_is_bundled_and_lints_clean(self, binary: Path) -> None:
        """`policy lint` resolves every rule's control references against the
        compliance catalogues, so a clean lint proves **both** sets of YAML
        made it in -- which is more than a `--help` that only proves the
        bootloader works."""
        result = self.run(binary, "policy", "lint")
        assert result.returncode == 0, result.stdout + result.stderr
        assert "46 rules" in result.stdout

    def test_the_compliance_catalogues_are_bundled(self, binary: Path) -> None:
        result = self.run(binary, "packs", "list", "--json")
        assert result.returncode == 0, result.stderr
        report = json.loads(result.stdout)
        assert len(report["catalogues"]) == 10

    def test_it_decides_and_the_chain_verifies(self, binary: Path, tmp_path: Path) -> None:
        """The whole point of the binary: `qed check` and `qed verify` with no
        Python on the machine."""
        state = tmp_path / "state"
        assert self.run(binary, "keys", "init", "--dir", str(state)).returncode == 0

        proposal = ROOT / "examples" / "proposals" / "prod-db-drop.json"
        decided = self.run(binary, "check", str(proposal), "--dir", str(state))
        # 0 ALLOW, 2 BLOCK, 3 REQUIRE_APPROVAL -- any of them is the kernel
        # working; 1 would be a malfunction.
        assert decided.returncode in {0, 2, 3}, decided.stdout + decided.stderr

        verified = self.run(binary, "verify", "--dir", str(state))
        assert verified.returncode == 0, verified.stdout + verified.stderr
        assert "OK" in verified.stdout

    def test_demo_runs_in_the_frozen_binary(self, binary: Path, tmp_path: Path) -> None:
        """`qed demo` is the first command a Homebrew user runs, and it touches
        more of the wheel than any other single command: the signing key, the
        policy pack, the store, the chain writer and the bundled verifier.

        The `not verified` assertion is the one that earns its place. The demo
        degrades politely when `qed-verify` is missing, which is right for a
        `pip install valqore-qed` and wrong for the binary -- it ships the
        verifier, so a demo that printed the polite line here would mean the
        bundling had silently broken.
        """
        result = self.run(binary, "demo", "--dir", str(tmp_path / "demo"))
        assert result.returncode == 0, result.stdout + result.stderr
        assert "verified: contiguous, unmodified, signed" in result.stdout
        assert "not verified" not in result.stdout

    def test_verify_does_not_tell_a_binary_user_to_run_pip(
        self, binary: Path, tmp_path: Path
    ) -> None:
        """The bug the first build had. A brew user has no pip and no Python,
        so "pip install ./packages/qed-verify" is advice they cannot take."""
        state = tmp_path / "state2"
        self.run(binary, "keys", "init", "--dir", str(state))
        result = self.run(binary, "verify", "--dir", str(state))
        assert "pip install" not in result.stdout + result.stderr

    def test_doctor_runs_offline(self, binary: Path, tmp_path: Path) -> None:
        state = tmp_path / "state3"
        self.run(binary, "keys", "init", "--dir", str(state))
        result = self.run(binary, "doctor", "--dir", str(state), "--offline")
        assert result.returncode == 0, result.stdout + result.stderr
        assert "self-gov" in result.stdout, "the week 10 posture line should be there too"


@pytest.fixture(scope="module")
def binary(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Build the single-file binary once.

    Module scope deliberately: see the class docstring. The build takes about a
    minute, so a function-scoped fixture would make this class take ten.
    """
    if not pyinstaller_available():
        pytest.skip("pyinstaller is not installed")
    work = tmp_path_factory.mktemp("pyinstaller")
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "PyInstaller",
            str(SPEC),
            "--noconfirm",
            "--clean",
            "--log-level",
            "WARN",
            "--distpath",
            str(work / "dist"),
            "--workpath",
            str(work / "build"),
        ],
        capture_output=True,
        text=True,
        check=False,
        cwd=ROOT,
        timeout=900,
    )
    assert result.returncode == 0, result.stdout[-4000:] + result.stderr[-4000:]
    built = work / "dist" / ("qed.exe" if sys.platform == "win32" else "qed")
    assert built.exists(), f"the build reported success and produced no {built.name}"
    # Not a hard assertion on the number: it moves with every dependency. But a
    # binary under ten megabytes has lost something, and one over two hundred
    # has gained something nobody meant to ship.
    megabytes = built.stat().st_size / 1_000_000
    assert 10 < megabytes < 200, f"the binary is {megabytes:.0f} MB, which is suspicious"
    yield built
    shutil.rmtree(work, ignore_errors=True)


# --------------------------------------------------------------------------
# The runners the release depends on
# --------------------------------------------------------------------------


def binary_labels() -> set[str]:
    """The platform labels `release.yml`'s binary matrix builds.

    Every asset in a release is named `qed-<version>-<label>`, so this set is
    what the formula must cover and what `tap-drift.yml` must require. Two
    hand-written copies of it would be two chances to be wrong, which is the
    argument this whole module's docstring makes about `qed.spec`.
    """
    workflow = yaml.safe_load((WORKFLOWS / "release.yml").read_text(encoding="utf-8"))
    return {entry["label"] for entry in workflow["jobs"]["binary"]["strategy"]["matrix"]["include"]}


def runner_labels(path: Path) -> set[str]:
    """Every hosted-runner label a workflow names.

    Read from the text rather than the parsed YAML because the labels appear in
    three shapes: `runs-on: ubuntu-latest` on a job, `- runner: macos-15` in a
    matrix the job then uses as `runs-on: ${{ matrix.runner }}`, and a bare
    `- ubuntu-latest` under a `runner:` block list. A `runs-on` that is an
    expression is not a label; the matrix entry it resolves to is.
    """
    labels: set[str] = set()
    in_block_list = False
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        inline = re.match(r"-?\s*(?:runs-on|runner):\s*(.*)$", stripped)
        if inline:
            value = inline.group(1).strip().strip("\"'")
            # `runner:` with nothing after it opens a block list of labels.
            in_block_list = not value
            if value and "${{" not in value:
                labels.add(value)
            continue

        if in_block_list:
            item = re.match(r"-\s*(\S+)$", stripped)
            if item:
                labels.add(item.group(1).strip("\"'"))
                continue
            in_block_list = False

    return labels


class TestTheRunnerLabelCanary:
    """`.github/workflows/runner-labels.yml` must cover what `release.yml` uses.

    A runner label that will not run a job has now cost two releases.
    `macos-13` cost v1.0.0 two tags -- the job queued against a label with no
    machines and held the release until GitHub cancelled it at the 24-hour
    limit. `macos-14` cost v1.1.0 its `macos-arm64` binary: that job was
    cancelled in the same second it started, so the *run* read `cancelled`
    while `pypi`, `image`, `sign`, `chart` and `release` all reported success.
    A release went to four channels missing one asset.

    `macos-14` was deprecated and due to retire on 2026-11-02, but it had not
    retired when that happened: a probe on 2026-11-02 at 11:47 UTC got a real
    runner in four seconds. The cause was the capacity reduction GitHub warned
    would precede the date. So neither the canary nor this class tests for
    retirement; they test whether a label release.yml depends on will run a
    job, which is the only part a release can feel.

    `release.yml` carried an accurate comment about the first occurrence
    throughout the second. A recorded lesson is not a guard. The canary is the
    guard, and this is the guard on the canary: the two label lists have to be
    the same set, or the canary becomes a weekly green tick for a question
    nobody is asking any more. Same shape as finding #58 -- the fix applied to
    one of the two places that needed it.
    """

    def test_the_canary_exists(self) -> None:
        assert (WORKFLOWS / "runner-labels.yml").exists()

    def test_it_probes_exactly_the_labels_the_release_depends_on(self) -> None:
        release = runner_labels(WORKFLOWS / "release.yml")
        canary = yaml.safe_load((WORKFLOWS / "runner-labels.yml").read_text(encoding="utf-8"))
        probed = set(canary["jobs"]["probe"]["strategy"]["matrix"]["runner"])
        # `verdict` runs on a label of its own and is not a thing to probe.
        probed_plus_own = probed | {canary["jobs"]["verdict"]["runs-on"]}
        missing = release - probed_plus_own
        assert not missing, (
            f"release.yml depends on {sorted(missing)} and runner-labels.yml does not "
            "probe them. A label is a dependency; add it to the canary's matrix."
        )
        stale = probed - release
        assert not stale, (
            f"runner-labels.yml probes {sorted(stale)}, which release.yml no longer uses. "
            "A canary watching a label nothing depends on is a weekly green tick for "
            "a question nobody is asking."
        )

    def test_it_turns_a_cancelled_probe_into_a_failure(self) -> None:
        """The whole point. A job cancelled for want of a runner is not a
        failure, and a cancelled scheduled run reads like somebody pressed a
        button. The `verdict` job is what makes that arrive as a failure, which
        is the only state that reaches a maintainer.

        This asserts the wiring is present, which is text matching and not
        behaviour: these three strings were all present while the job had only
        ever run green, and a guard that has never failed is a guess about what
        it does when it fails. The behaviour was proved separately, on a
        throwaway branch on 2026-11-02 (run 41440411755), by forcing one probe
        to exit 1 -- `verdict` ran on `if: always()`, read `probe result:
        failure` and exited 1. The comparison is `!= "success"`, so a cancelled
        probe takes the branch a failed one just took.
        """
        text = (WORKFLOWS / "runner-labels.yml").read_text(encoding="utf-8")
        assert "needs.probe.result" in text
        assert "if: always()" in text
        assert "exit 1" in text

        # The comparison itself, read from the parsed step rather than from
        # the file. `!= "success"` is what makes cancelled and failed the same
        # case; `= "failure"` would miss the one that actually happens.
        #
        # Read from the file, this assertion passes against that exact bug,
        # because the comment above the job quotes `!= "success"` in prose and
        # `in text` cannot tell a comment from a command. It was written that
        # way first and it did exactly that -- finding #48, a guard answered by
        # a comment. yaml.safe_load drops comments, so the parsed `run` block
        # is the only place the question can be asked honestly.
        canary = yaml.safe_load(text)
        verdict = canary["jobs"]["verdict"]["steps"][0]["run"]
        assert '!= "success"' in verdict, (
            'the verdict job does not test `!= "success"`. A probe against a '
            "label that will not run is cancelled, not failed; a test for "
            "failure alone misses the case this workflow exists for."
        )

    def test_it_runs_on_a_schedule_and_not_only_on_demand(self) -> None:
        """A canary nobody triggers is a file. `on.schedule` is what makes a
        retirement show up on an ordinary Monday instead of in a release."""
        canary = yaml.safe_load((WORKFLOWS / "runner-labels.yml").read_text(encoding="utf-8"))
        # PyYAML parses the unquoted key `on` as the boolean True.
        triggers = canary.get("on") or canary.get(True)
        assert "schedule" in triggers, "runner-labels.yml has no schedule"
        assert triggers["schedule"][0]["cron"]

    def test_no_workflow_names_a_label_we_have_already_moved_off(self) -> None:
        """The ones that have already cost a release, plus their generation.

        Not a general check against GitHub's catalogue -- there is no API for
        that, which is why the canary is a live probe rather than a list. This
        is only a floor: a label we have moved off should not come back by
        somebody copying an old job.

        Deliberately not called `retired`. `macos-14` is in this set and still
        served a runner on its own retirement date, so a set called `retired`
        would be asserting something false about its own contents -- which is
        the mistake this test's own class docstring used to make.
        """
        moved_off = {"macos-12", "macos-13", "macos-14", "ubuntu-20.04"}
        for path in sorted(WORKFLOWS.glob("*.yml")):
            found = runner_labels(path) & moved_off
            assert not found, (
                f"{path.name} names {sorted(found)}, which this project has moved off. "
                "Use a current label; the canary probes only what release.yml uses."
            )
