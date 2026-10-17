"""`qed --version`, and `doctor` reporting the same number (SPEC §25.6).

For twelve weeks and twenty-two commands there was no way to ask this binary
what it was: `--version` was not an option, `version` was not a command, and
`doctor` -- the command whose whole job is posture -- did not print it either.

It matters more here than in most tools. `VERSION` *is* `ENGINE_VERSION`, the
value stamped into every verdict record, and the record is immutable. The
project already has a scar from that: `ENGINE_VERSION` sat at `0.1.0` for seven
weeks of releases, so an auditor asking "which engine decided this?" got an
answer wrong by six versions with nothing able to correct it. "Which engine am
I holding?" is the same question asked one step earlier, and it needs an answer
that does not require reading the source.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from typer.testing import CliRunner

from qed.cli import app
from qed.version import VERSION

runner = CliRunner()


class TestTheVersionFlag:
    def test_it_prints_the_version(self) -> None:
        result = runner.invoke(app, ["--version"])
        assert result.exit_code == 0
        assert VERSION in result.output

    def test_it_is_the_one_literal_and_not_a_copy(self) -> None:
        """Imported from `qed.version`, so this cannot pass against a second
        hardcoded string -- which is the failure mode `qed/version.py` exists
        to prevent, and which it documents happening in eight places at once."""
        assert f"qed {VERSION}" in runner.invoke(app, ["--version"]).output

    def test_it_says_whether_this_is_a_binary_or_a_wheel(self) -> None:
        """The single-file binary freezes the interpreter it was built on, and
        the difference has already produced a defect: a frozen build telling a
        user with no Python to run `pip install`. A bug report that does not
        say which one it came from cannot be reproduced."""
        output = runner.invoke(app, ["--version"]).output
        assert ("single-file binary" in output) == bool(getattr(sys, "frozen", False))
        assert "python" in output

    def test_it_answers_without_a_state_directory(self, tmp_path: Path) -> None:
        """The person most likely to type `qed --version` has just downloaded
        a binary and has no `qed.yaml`, no keys and no chain. A `--version`
        that resolved a session first would fail for exactly them, which is
        why the option is eager."""
        result = runner.invoke(app, ["--version"], env={"QED_DIR": str(tmp_path / "nothing")})
        assert result.exit_code == 0
        assert VERSION in result.output

    def test_the_top_level_help_still_describes_the_product(self) -> None:
        """Guard on how the flag was added. A `@app.callback()` carrying a
        docstring can take over the group's help text, and the Homebrew
        formula's test block greps `qed --help` for this phrase -- so the
        failure would have surfaced as a broken `brew test` on a machine
        nobody here has."""
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "Policy and evidence kernel" in result.output
        assert "--version" in result.output


class TestDoctorReportsIt:
    """Both renderings, because `doctor` builds a dict and then prints it by
    hand.

    Its own source says so about the clock warning -- "this has to be added in
    both places, which is how the first version of this silently printed
    nothing" -- and adding `version` reproduced it immediately: the JSON had it
    and the human output did not. One assertion per rendering is the only shape
    that catches that.
    """

    def state(self, tmp_path: Path) -> Path:
        directory = tmp_path / "state"
        assert runner.invoke(app, ["keys", "init", "--dir", str(directory)]).exit_code == 0
        return directory

    def test_the_json_carries_it(self, tmp_path: Path) -> None:
        result = runner.invoke(
            app, ["doctor", "--dir", str(self.state(tmp_path)), "--offline", "--json"]
        )
        assert result.exit_code == 0
        assert json.loads(result.output)["version"] == VERSION

    def test_the_human_output_carries_it_too(self, tmp_path: Path) -> None:
        result = runner.invoke(app, ["doctor", "--dir", str(self.state(tmp_path)), "--offline"])
        assert result.exit_code == 0
        assert VERSION in result.output, (
            "doctor's human rendering dropped the version; it is built line by "
            "line and does not follow the report dict"
        )
