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
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import ClassVar, cast

import pytest

ROOT = Path(__file__).resolve().parents[2]
SPEC = ROOT / "deploy" / "qed.spec"


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
        import yaml as pyyaml

        workflow = pyyaml.safe_load(
            (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
        )
        labels = {
            entry["label"] for entry in workflow["jobs"]["binary"]["strategy"]["matrix"]["include"]
        }
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
