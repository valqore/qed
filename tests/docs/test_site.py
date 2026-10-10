"""The documentation site agrees with the documentation (SPEC §26, §22 week 11).

`mkdocs build` will happily produce a site with a page missing from the nav. The
page is published, reachable by URL, and invisible -- the build is green and the
artifact is wrong. That is the same failure as the wheel that shipped without
`compliance/packs/*.yaml`, and `docs/validation.md` has the list of times this
project has made it.

So the nav and `docs/` are asserted to be the same set, in **both** directions:
a page not listed is a page nobody finds, and a nav entry with no file is a
build failure under `strict: true`. The static checks here cost nothing and run
everywhere; `test_it_builds` does the real thing and is `slow`.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
CONFIG = ROOT / "mkdocs.yml"
DOCS = ROOT / "docs"

#: Root documents that must each have a page on the site. They live at the
#: repository root because that is where GitHub and a fresh clone look for them,
#: so the site reaches them through `pymdownx.snippets` rather than a copy.
INCLUDED_FROM_ROOT = (
    "THREAT_MODEL.md",
    "GOVERNANCE.md",
    "CONTRIBUTING.md",
    "SECURITY.md",
    "CHANGELOG.md",
    "QED_SPEC.md",
)


def load_config() -> dict[str, Any]:
    """Parse `mkdocs.yml` ignoring the `!!python/name:` tags material uses.

    `yaml.safe_load` refuses those tags outright, and the alternative -- running
    mkdocs to get the parsed config -- would make every assertion here depend on
    mkdocs being installed. The nav is plain YAML, which is all this needs.
    """
    text = CONFIG.read_text(encoding="utf-8")
    text = re.sub(r"!!python/\S+", "''", text)
    loaded = yaml.safe_load(text)
    assert isinstance(loaded, dict)
    return loaded


def nav_targets(node: object) -> list[str]:
    """Every file path in the nav, however deeply the sections are nested."""
    if isinstance(node, str):
        return [node]
    if isinstance(node, list):
        return [target for item in node for target in nav_targets(item)]
    if isinstance(node, dict):
        return [target for value in node.values() for target in nav_targets(value)]
    return []


@pytest.fixture(scope="module")
def config() -> dict[str, Any]:
    return load_config()


@pytest.fixture(scope="module")
def listed(config: dict[str, Any]) -> set[str]:
    return set(nav_targets(config["nav"]))


@pytest.fixture(scope="module")
def on_disk() -> set[str]:
    return {path.relative_to(DOCS).as_posix() for path in DOCS.rglob("*.md")}


class TestTheNavCoversTheDocs:
    def test_every_page_on_disk_is_in_the_nav(self, listed: set[str], on_disk: set[str]) -> None:
        """A page not in the nav is published and unreachable by browsing."""
        missing = sorted(on_disk - listed)
        assert not missing, f"these pages exist and no nav entry points at them: {missing}"

    def test_every_nav_entry_exists(self, listed: set[str], on_disk: set[str]) -> None:
        """`strict: true` makes this fatal at build time; failing here names it."""
        dangling = sorted(listed - on_disk)
        assert not dangling, f"the nav points at pages that do not exist: {dangling}"

    def test_the_nav_has_no_duplicates(self, config: dict[str, Any]) -> None:
        """One page in two sections is a reader who cannot tell where they are."""
        targets = nav_targets(config["nav"])
        duplicated = sorted({t for t in targets if targets.count(t) > 1})
        assert not duplicated, f"listed more than once: {duplicated}"

    def test_every_adr_is_listed(self, listed: set[str]) -> None:
        """The ADRs are the record of why the code disagrees with the spec.

        An unlisted one is the single most likely page to go missing, because
        adding an ADR is a different motion from editing the nav.
        """
        adrs = {p.relative_to(DOCS).as_posix() for p in (DOCS / "adr").glob("[0-9]*.md")}
        assert adrs, "no ADRs found; this test is looking in the wrong place"
        assert not sorted(adrs - listed), f"unlisted ADRs: {sorted(adrs - listed)}"


class TestTheRootDocumentsAreReachable:
    def test_each_one_has_a_page(self, on_disk: set[str]) -> None:
        """One copy of each, included at build time, never duplicated into docs/."""
        includes = {
            path.name: path.read_text(encoding="utf-8")
            for path in DOCS.glob("*.md")
            if "--8<--" in path.read_text(encoding="utf-8")
        }
        blob = "\n".join(includes.values())
        for name in INCLUDED_FROM_ROOT:
            assert f'--8<-- "{name}"' in blob, f"{name} is not included by any page"

    def test_the_include_targets_exist(self) -> None:
        """`check_paths: true` makes mkdocs fail on a missing one; this says which."""
        pattern = re.compile(r'--8<--\s+"([^"]+)"')
        for page in DOCS.rglob("*.md"):
            for target in pattern.findall(page.read_text(encoding="utf-8")):
                assert (ROOT / target).exists(), f"{page.name} includes a missing {target}"

    def test_no_root_document_links_relatively(self) -> None:
        """A root document may not carry a relative link to another document.

        This is the one real cost of including rather than copying, and
        `strict: true` found it the moment week 11 added cross-references:
        `[THREAT_MODEL.md](THREAT_MODEL.md)` resolves on GitHub, where the
        reader is at the repository root, and not on the site, where the page
        is at `/security/` and the target is `../threat-model/`. There is no
        spelling that satisfies both, so a backticked filename is used instead
        -- it is correct in both contexts and broken in neither.

        `mkdocs build --strict` would catch this anyway, which is why it is
        configured. This names it without a build.
        """
        pattern = re.compile(r"\]\((?!https?://|#)([^)]+\.md[^)]*)\)")
        offenders: list[str] = []
        for name in INCLUDED_FROM_ROOT:
            for target in pattern.findall((ROOT / name).read_text(encoding="utf-8")):
                offenders.append(f"{name} links relatively to {target}")
        assert not offenders, (
            "a relative link in a root document cannot resolve both on GitHub "
            "and on the site; use a backticked filename instead -- " + "; ".join(offenders)
        )

    def test_no_root_document_was_copied_into_docs(self) -> None:
        """Two copies of a normative document is the bug the includes avoid.

        Compared against the real directory listing rather than with
        `Path.exists()`: Windows is case-insensitive, so `docs/governance.md`
        -- the stub that includes the root file, and exactly what is supposed
        to be there -- answers `True` to `(docs / "GOVERNANCE.md").exists()`.
        Written that way this test failed on Windows and passed in CI on Linux,
        which is the worse of the two directions.
        """
        present = {path.name for path in DOCS.iterdir() if path.is_file()}
        for name in INCLUDED_FROM_ROOT:
            assert name not in present, (
                f"{name} exists in docs/ as well as at the root; the site includes "
                "the root copy, so this one would silently become the published one"
            )


class TestTheConfiguration:
    def test_broken_links_fail_the_build(self, config: dict[str, Any]) -> None:
        """A dead link on the site is a reader who cannot check a claim."""
        assert config.get("strict") is True

    def test_snippets_are_configured_to_check_paths(self, config: dict[str, Any]) -> None:
        """Without it, a missing include renders the literal `--8<--` line."""
        extensions = config["markdown_extensions"]
        snippets = [e for e in extensions if isinstance(e, dict) and "pymdownx.snippets" in e]
        assert snippets, "pymdownx.snippets is not configured"
        assert snippets[0]["pymdownx.snippets"]["check_paths"] is True

    def test_the_site_directory_is_not_committed(self) -> None:
        gitignore = (ROOT / ".gitignore").read_text(encoding="utf-8")
        assert "site/" in gitignore, "`mkdocs build` output would be committed"


# --------------------------------------------------------------------------
# The real thing
# --------------------------------------------------------------------------


def mkdocs_available() -> bool:
    return shutil.which("mkdocs") is not None or _importable("mkdocs")


def _importable(name: str) -> bool:
    try:
        __import__(name)
    except ImportError:
        return False
    return True


@pytest.mark.slow
@pytest.mark.skipif(not mkdocs_available(), reason="mkdocs is not installed")
def test_it_builds(tmp_path: Path) -> None:
    """`mkdocs build --strict`, which is the only check that proves the rest.

    Static assertions about a config file are assertions about a config file.
    This is the one that catches a broken cross-reference, a snippet that does
    not resolve, or a theme feature that no longer exists.
    """
    result = subprocess.run(
        [sys.executable, "-m", "mkdocs", "build", "--strict", "--site-dir", str(tmp_path / "site")],
        capture_output=True,
        text=True,
        check=False,
        cwd=ROOT,
        timeout=300,
    )
    assert result.returncode == 0, result.stdout[-4000:] + result.stderr[-4000:]
    index = tmp_path / "site" / "index.html"
    assert index.exists(), "the build reported success and produced no index.html"
    # The spec is the largest page and the one most likely to be truncated by a
    # snippet misconfiguration, so it gets the assertion.
    spec = tmp_path / "site" / "spec" / "index.html"
    assert spec.exists()
    assert "Policy language" in spec.read_text(encoding="utf-8", errors="replace")
