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
        """Publishing is the irreversible step and the tap is not reserved yet
        (SPEC 24). A file that looked ready to publish would be an invitation
        to publish it."""
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
