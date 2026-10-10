"""The landing page says only things the repository can back (SPEC §22 week 12).

A landing page is the one document nobody tests, and the one most likely to
round a number up. It is also the first thing a reader of this project sees, so
a wrong figure there costs more than a wrong figure anywhere else.

Three kinds of check:

* **Every command shown exists.** The page prints a terminal transcript; if
  `qed check` were renamed the page would go on showing it forever.
* **Every number matches its source.** 46 rules, 16 shadow, p95 4.5 ms -- each
  re-derived here from the thing that produced it rather than compared against
  a second copy of the claim.
* **Nothing from a deny-list appears.** Star counts, customer names,
  certifications and compliance percentages are the four things this category
  lies about, and `ADR-0011` and `GOVERNANCE.md` both commit to not printing a
  percentage. The deny-list makes that commitment apply to the marketing too.

`tests/docs/test_claims.py` does the same job for the Markdown documents. This
is HTML and a different shape, hence a separate file.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
PAGE = ROOT / "landing" / "index.html"


@pytest.fixture(scope="module")
def page() -> str:
    return PAGE.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def visible(page: str) -> str:
    """The page with HTML comments stripped.

    The file's header comment explains where each number came from, so a check
    for "does this claim appear" would find it in the comment and pass whether
    or not the reader can see it.
    """
    return re.sub(r"<!--.*?-->", "", page, flags=re.DOTALL)


class TestItExists:
    def test_the_page_is_there(self) -> None:
        assert PAGE.exists(), "SPEC §22 week 12 asks for a landing page"

    def test_it_is_self_contained(self, visible: str) -> None:
        """No external script, stylesheet, font or image.

        The product claims zero bytes leave by default. A page that loads a
        font from a CDN has already contradicted it when the reader reaches the
        first sentence.
        """
        for pattern, what in (
            (r"<script", "a script tag"),
            (r"<link[^>]+stylesheet", "an external stylesheet"),
            (r"<img", "an image"),
            (r"@import", "a CSS import"),
            (r"url\(\s*['\"]?https?://", "a remote CSS asset"),
        ):
            assert not re.search(pattern, visible, re.IGNORECASE), f"the page loads {what}"

    def test_every_outbound_link_is_to_a_place_we_own(self, visible: str) -> None:
        """Only the repository and valqore.io. A third-party link on a page
        about not trusting third parties needs a better reason than decoration."""
        allowed = ("https://github.com/valqore/qed", "https://valqore.io")
        links = re.findall(r'href="(https?://[^"]+)"', visible)
        assert links, "no outbound links at all; has the markup changed?"
        stray = sorted({link for link in links if not link.startswith(allowed)})
        assert not stray, f"links outside valqore: {stray}"

    def test_it_renders_in_both_themes(self, visible: str) -> None:
        """A page with one palette shows dark text on a dark ground for half
        its readers. Tokens are defined on `:root` and redefined for dark."""
        assert "prefers-color-scheme: dark" in visible
        assert '[data-theme="dark"]' in visible
        assert "--bg:" in visible


class TestEveryCommandShownIsReal:
    #: Each command the page shows, as the page spells it and as the CLI
    #: registers it. The two differ: the install block ends in
    #: `docker run ghcr.io/valqore/qed:1.0.0 serve`, where the command has no
    #: `qed ` in front of it, and a test that assumed one reported `qed serve`
    #: missing from a page that shows it.
    SHOWN = (
        ("qed keys init", "keys init"),
        ("qed doctor", "doctor"),
        ("qed check", "check"),
        ("qed export", "export"),
        ("qed policy test", "policy test"),
        (":1.0.0 serve", "serve"),
    )

    def test_the_page_shows_commands(self, visible: str) -> None:
        assert "qed check" in visible, "the transcript should show a real run"

    @pytest.mark.parametrize(("shown", "command"), SHOWN, ids=[c for _, c in SHOWN])
    def test_the_cli_has_it(self, shown: str, command: str, visible: str) -> None:
        """Named on the page and registered in `qed/cli.py`.

        Compared against the decorator rather than against `--help`: `--help`
        is what the onboarding guide was written from, and three of its passages
        were wrong for exactly that reason (`docs/validation.md`).
        """
        assert shown in visible, f"the page no longer shows `{shown}`"
        source = (ROOT / "qed" / "cli.py").read_text(encoding="utf-8")
        head, _, tail = command.partition(" ")
        if tail:
            registered = f'_app.command("{tail}")' in source
        else:
            registered = f'@app.command("{head}")' in source or f"\ndef {head}(" in source
        assert registered, f"`qed {command}` is on the page and not in the CLI"

    def test_the_verifier_entry_point_is_spelled_right(self, visible: str) -> None:
        """`qed-verify`, hyphenated, is what an auditor types."""
        assert "qed-verify chain.jsonl" in visible
        config = (ROOT / "packages" / "qed-verify" / "pyproject.toml").read_text(encoding="utf-8")
        assert "qed-verify" in config

    def test_the_exit_codes_are_the_real_ones(self, visible: str) -> None:
        """The page tells a reader a CI job is one line. SPEC §12.5: 0 ALLOW,
        2 BLOCK, 3 REQUIRE_APPROVAL."""
        from qed.runtime import EXIT_APPROVAL, EXIT_BLOCK

        assert f"{EXIT_BLOCK}&nbsp;BLOCK" in visible
        assert f"{EXIT_APPROVAL}&nbsp;REQUIRE_APPROVAL" in visible


class TestEveryNumberIsDerivable:
    def test_the_baseline_rule_count(self, visible: str) -> None:
        """Counted by loading the bundle, which is what `qed policy lint` does."""
        from qed.core.policy.loader import load_bundle

        bundle = load_bundle([ROOT / "qed" / "core" / "policy" / "packs" / "agent-baseline"])
        total = len(bundle.bundle.rules)
        assert f">{total}<" in visible or f"{total} baseline rules" in visible, (
            f"the page should say {total} baseline rules"
        )

    def test_the_shadow_rule_count(self, visible: str) -> None:
        """The number that decides whether a first install blocks anything."""
        from qed.core.policy.loader import load_bundle

        bundle = load_bundle([ROOT / "qed" / "core" / "policy" / "packs" / "agent-baseline"])
        shadow = sum(1 for rule in bundle.bundle.rules if rule.mode == "shadow")
        assert f"{shadow} ship in shadow mode" in visible, (
            f"{shadow} baseline rules ship in shadow mode; the page says otherwise"
        )

    def test_the_latency_numbers_match_the_performance_page(self, visible: str) -> None:
        """Two documents, one measurement. `docs/performance.md` is the source."""
        performance = (ROOT / "docs" / "performance.md").read_text(encoding="utf-8")
        for number in ("4.5 ms", "10.6 ms"):
            assert number in visible, f"the page should quote {number}"
            assert number.replace(" ", " ") in performance or number in performance, (
                f"{number} is on the landing page and not in docs/performance.md"
            )

    def test_the_budget_is_stated_with_the_measurement(self, visible: str) -> None:
        """A latency with no budget beside it is a number, not a claim."""
        assert "50 ms budget" in visible

    def test_the_control_mapping_is_a_fraction_and_not_a_percentage(self, visible: str) -> None:
        """ADR-0011: coverage refuses a percentage unless the catalogue is
        complete. "35 / 76" with the unmapped ones named is the honest form;
        "46% compliant" is the thing the whole category does instead."""
        assert re.search(r"\d+\s*/\s*\d+", visible), "the mapping should be a fraction"
        assert "unmapped" in visible


class TestTheDenyList:
    #: Phrases that would each be a claim the repository cannot support. Not a
    #: style rule: every one of these is something a competitor's page says and
    #: `GOVERNANCE.md` or `ADR-0011` commits against.
    FORBIDDEN = (
        "trusted by",
        "customers",
        "enterprise-grade",
        "soc 2 compliant",
        "soc2 compliant",
        "iso certified",
        "certified",
        "% compliant",
        "github stars",
        "industry-leading",
        "military-grade",
        "unhackable",
        "tamper-proof",
    )

    @pytest.mark.parametrize("phrase", FORBIDDEN)
    def test_it_does_not_appear(self, phrase: str, visible: str) -> None:
        assert phrase not in visible.lower(), (
            f"{phrase!r} is on the landing page and nothing in the repository supports it"
        )

    def test_tamper_evident_not_tamper_proof(self, visible: str) -> None:
        """The chain detects modification; it does not prevent it. An operator
        with the database can rewrite it -- which is what checkpoint anchoring
        is for, and what `qed doctor` says is weak until one is configured."""
        lowered = visible.lower()
        assert "tamper-proof" not in lowered and "tamperproof" not in lowered

    def test_the_advisory_caveat_is_on_the_page(self, visible: str) -> None:
        """The single most load-bearing honest sentence in the product, quoted
        from `qed doctor` rather than paraphrased."""
        assert "every adapter is ADVISORY" in visible
        source = (ROOT / "qed" / "cli.py").read_text(encoding="utf-8")
        assert "every adapter is ADVISORY" in source, "the page quotes doctor; doctor changed"


class TestThePrelaunchNotice:
    def test_it_is_present(self, visible: str) -> None:
        """While the names are unreserved, `pip install valqore-qed` fails.

        The page shows the command because that is what it will be; it carries
        the notice because today it is not. `landing/README.md` says to remove
        the notice in the same commit that sets `PUBLISH_PYPI=true`.
        """
        assert "Not published yet" in visible
        assert "do not work yet" in visible

    def test_publishing_is_still_gated(self) -> None:
        """The other half of that pair, so the two cannot drift apart silently.

        A test cannot read a repository variable, so this checks the gate is
        still *written* in the workflow. If publishing is ever unconditional
        while the notice is up, this is where it surfaces.
        """
        workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
        assert "vars.PUBLISH_PYPI == 'true'" in workflow, (
            "publishing is no longer gated; remove the pre-launch notice from "
            "landing/index.html in the same change"
        )

    def test_the_launch_checklist_exists(self) -> None:
        readme = (ROOT / "landing" / "README.md").read_text(encoding="utf-8")
        assert "Launch checklist" in readme
        assert "security@valqore.io" in readme, "the unowned alias is a launch blocker"
