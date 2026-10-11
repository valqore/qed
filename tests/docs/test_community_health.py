"""The files GitHub reads rather than a human (SPEC §20, §25.1).

These are easy to believe in without checking. A `CODE_OF_CONDUCT.md` section
written inside `CONTRIBUTING.md` satisfies a reader and not GitHub's community
profile, which looks for the file; an issue-template directory with a syntax
error is ignored silently; a `CODEOWNERS` line naming a team that does not exist
is dropped without a warning, so the protection reads as present and is absent.

Each one is the same shape as the compliance failure this product exists to
remove: a control that appears in a report while nothing enforces it. Checking
them here costs a second.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
GITHUB = ROOT / ".github"


class TestTheFilesGitHubLooksFor:
    @pytest.mark.parametrize(
        "name",
        [
            "LICENSE",
            "NOTICE",
            "README.md",
            "CHANGELOG.md",
            "SECURITY.md",
            "CONTRIBUTING.md",
            "GOVERNANCE.md",
            "CODE_OF_CONDUCT.md",
            "THREAT_MODEL.md",
        ],
    )
    def test_it_is_at_the_repository_root(self, name: str) -> None:
        """At the root, not under `docs/`: that is where GitHub and a fresh
        clone look. The site reaches them by inclusion (`mkdocs.yml`)."""
        assert (ROOT / name).is_file(), f"{name} is missing from the repository root"

    def test_the_code_of_conduct_says_where_to_report(self) -> None:
        """A code of conduct with no channel and no decider is decoration."""
        text = (ROOT / "CODE_OF_CONDUCT.md").read_text(encoding="utf-8")
        assert "@valqore.io" in text, "no reporting address"
        assert "recused" in text, "nothing says what happens when a report concerns a maintainer"

    def test_contributing_points_at_the_full_code_of_conduct(self) -> None:
        text = (ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")
        assert "CODE_OF_CONDUCT.md" in text


def issue_templates() -> list[Path]:
    found = sorted((GITHUB / "ISSUE_TEMPLATE").glob("*.yml"))
    assert found, "no issue templates"
    return found


def codeowner_rules() -> list[str]:
    path = GITHUB / "CODEOWNERS"
    assert path.is_file(), "CODEOWNERS is missing"
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def dependabot() -> dict[str, object]:
    path = GITHUB / "dependabot.yml"
    assert path.is_file(), "dependabot.yml is missing"
    loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(loaded, dict)
    return loaded


class TestIssueTemplates:
    def test_every_template_parses(self) -> None:
        """A template with a YAML error is ignored, and GitHub says nothing."""
        for path in issue_templates():
            yaml.safe_load(path.read_text(encoding="utf-8"))

    def test_blank_issues_are_disabled(self) -> None:
        """Otherwise a reporter can bypass every template -- including the one
        that tells them a vulnerability does not belong in a public issue."""
        config = yaml.safe_load((GITHUB / "ISSUE_TEMPLATE" / "config.yml").read_text("utf-8"))
        assert config["blank_issues_enabled"] is False

    def test_the_security_channel_is_offered_before_an_issue(self) -> None:
        config = yaml.safe_load((GITHUB / "ISSUE_TEMPLATE" / "config.yml").read_text("utf-8"))
        links = config["contact_links"]
        assert any("security" in link["name"].lower() for link in links)
        assert any("disclosure" in link["about"].lower() for link in links)

    def test_the_bug_report_warns_about_shadow_mode(self) -> None:
        """Shadow is the shipped default and exits 0 even on BLOCK, so "it did
        not block anything" is the first report this project will receive."""
        bug = (GITHUB / "ISSUE_TEMPLATE" / "bug_report.yml").read_text(encoding="utf-8")
        assert "shadow" in bug.lower()

    def test_there_is_a_template_for_an_overclaim(self) -> None:
        """The most valuable report this project can receive, and every instance
        found so far was found by a person rather than by the suite."""
        assert (GITHUB / "ISSUE_TEMPLATE" / "overclaim.yml").is_file()


class TestCodeowners:
    def test_every_rule_names_an_owner(self) -> None:
        for line in codeowner_rules():
            assert "@" in line, f"no owner on: {line}"

    def test_the_frozen_format_has_an_owner(self) -> None:
        """A change under these paths can invalidate records already written,
        which is the one thing ADR-0015 says cannot be walked back."""
        owned = {line.split()[0] for line in codeowner_rules()}
        for path in (
            "/qed/core/evidence/",
            "/packages/qed-verify/",
            "/tests/evidence/fixtures/",
            "/docs/evidence-format.md",
        ):
            assert path in owned, f"{path} has no explicit owner"

    def test_every_owned_path_exists(self) -> None:
        """A pattern matching nothing is a protection that does not apply."""
        for line in codeowner_rules():
            pattern = line.split()[0]
            if pattern == "*":
                continue
            assert (ROOT / pattern.strip("/")).exists(), f"CODEOWNERS names a missing {pattern}"


class TestDependabot:
    def test_every_watched_directory_exists(self) -> None:
        updates = dependabot()["updates"]
        assert isinstance(updates, list)
        for update in updates:
            directory = str(update["directory"]).strip("/")
            assert (ROOT / directory).is_dir(), f"dependabot watches a missing {directory!r}"

    def test_the_verifier_is_watched_separately(self) -> None:
        """It ships to auditors as its own distribution with its own pin."""
        updates = dependabot()["updates"]
        assert isinstance(updates, list)
        assert any("qed-verify" in str(u["directory"]) for u in updates)

    def test_a_cryptography_major_is_not_proposed_automatically(self) -> None:
        """The one dependency whose major version can change what a signature
        means. Read by hand against the changelog, never merged on green CI."""
        updates = dependabot()["updates"]
        assert isinstance(updates, list)
        pip = [u for u in updates if u["package-ecosystem"] == "pip"]
        assert pip
        for update in pip:
            ignored = {str(entry["dependency-name"]) for entry in update.get("ignore", [])}
            assert "cryptography" in ignored, f"{update['directory']} would bump it unattended"


def test_the_pull_request_template_asks_about_the_frozen_format() -> None:
    path = GITHUB / "PULL_REQUEST_TEMPLATE.md"
    assert path.is_file(), "PULL_REQUEST_TEMPLATE.md is missing"
    text = path.read_text(encoding="utf-8")
    assert "ADR-0015" in text, "nothing warns a contributor that the format is frozen"
    assert "signed off" in text, "nothing mentions the DCO, which CI enforces"
