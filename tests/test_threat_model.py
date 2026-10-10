"""`THREAT_MODEL.md` says things that must stay true (SPEC §17, §22 week 10).

A threat model is the one document an auditor reads expecting precision, and the
one most likely to drift: it names rules, constants, config keys and files, and
every one of those can be renamed by somebody who never opens it.

So the claims that are checkable are checked. This is not a lint pass on prose
-- it is the same discipline as `tests/test_packaging.py`, which exists because
a list nobody verified was wrong.

It also found a real error on its first run: the document cited ADR-0001 for the
advisory-adapter concession, and ADR-0001 is the blast-radius table.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
DOCUMENT = ROOT / "THREAT_MODEL.md"


@pytest.fixture(scope="module")
def text() -> str:
    return DOCUMENT.read_text(encoding="utf-8")


class TestItExistsWhereTheSpecSaysItDoes:
    def test_the_spec_names_this_file(self) -> None:
        """SPEC §17: "Full STRIDE in `THREAT_MODEL.md`." At the repository
        root, not under `docs/`, because that is where the spec points."""
        assert DOCUMENT.exists()
        spec = (ROOT / "QED_SPEC.md").read_text(encoding="utf-8")
        assert "THREAT_MODEL.md" in spec

    def test_every_stride_category_is_covered(self, text: str) -> None:
        for heading in (
            "### Spoofing",
            "### Tampering",
            "### Repudiation",
            "### Information disclosure",
            "### Denial of service",
            "### Elevation of privilege",
        ):
            assert heading in text, heading


class TestTheRulesItNamesExist:
    """A renamed rule leaves a threat model citing a control that is gone."""

    def test_every_cited_rule_id_is_a_real_rule(self, text: str) -> None:
        from qed.core.policy.loader import baseline_pack_dir, load_bundle

        shipped = {rule.rule_id for rule in load_bundle([baseline_pack_dir()]).bundle.rules}
        cited = set(re.findall(r"\bAG-[A-Z]{3}-\d{3}\b", text))
        assert cited, "the document cites no rules, which cannot be right"
        from qed.core.policy.engine import SYNTHETIC_RULES

        # The codes that are not rules in a pack: the approval module's SoD
        # refusals, and the engine's synthetic ones (`AG-DEF-001` is the bundle
        # default). Exempt by *provenance* rather than by name, so a new
        # synthetic rule needs no change here and a typo'd pack rule is still
        # caught.
        synthetic = set(SYNTHETIC_RULES)
        unknown = cited - shipped - synthetic - {"AG-SOD-001", "AG-SOD-002"}
        assert not unknown, f"{sorted(unknown)} are cited and do not exist"

    def test_the_sod_codes_are_the_ones_the_approval_module_raises(self, text: str) -> None:
        """`AG-SOD-001` and `AG-SOD-002` are not rules in the pack -- they are
        raised by `check_separation_of_duties`, which is why they are excluded
        above rather than silently tolerated."""
        source = (ROOT / "qed" / "core" / "approval" / "model.py").read_text(encoding="utf-8")
        for code in ("AG-SOD-001", "AG-SOD-002"):
            assert code in source
            assert code in text


class TestTheNumbersItQuotes:
    def test_the_proposal_and_params_limits(self, text: str) -> None:
        from qed.adapters.common import MAX_PARAMS_BYTES, MAX_PROPOSAL_BYTES

        assert f"{MAX_PROPOSAL_BYTES // 1024} KB proposal" in text
        assert f"{MAX_PARAMS_BYTES // 1024} KB `params_redacted`" in text

    def test_the_regex_timeout(self, text: str) -> None:
        from qed.core.policy.predicates import REGEX_TIMEOUT

        assert f"{int(REGEX_TIMEOUT * 1000)} ms timeout" in text

    def test_the_clock_skew_window(self, text: str) -> None:
        from qed.config import ApiConfig

        assert f"{ApiConfig().max_clock_skew_seconds}s)" in text

    def test_the_clock_tolerance(self, text: str) -> None:
        from qed.core.clock import TOLERANCE_SECONDS

        assert f"more than {int(TOLERANCE_SECONDS)} seconds in the future" in text

    def test_the_connect_timeout(self, text: str) -> None:
        from qed.infra.storage.postgres import CONNECT_TIMEOUT_S

        assert f"`connect_timeout` ({CONNECT_TIMEOUT_S}s)" in text

    def test_the_rate_limit_example_matches_the_default(self, text: str) -> None:
        from qed.core.ratelimit import DEFAULT_PER_ADAPTER_RPS

        rps = int(DEFAULT_PER_ADAPTER_RPS)
        assert f"`per_adapter_rps: {rps}`" in text
        assert f"admit {4 * rps}/s between them" in text, "four replicas, so four times"


class TestTheFilesItPointsAt:
    def test_every_repository_path_it_cites_exists(self, text: str) -> None:
        """The most common way a document like this rots: a module moves."""
        cited = set(re.findall(r"`(qed/[a-z0-9_/]+\.py|tests/[a-z0-9_/]+\.py)`", text))
        assert cited, "it cites no source files, which cannot be right"
        missing = [path for path in cited if not (ROOT / path).exists()]
        assert not missing, f"{sorted(missing)} are cited and do not exist"

    def test_the_directories_it_cites_exist(self, text: str) -> None:
        cited = set(re.findall(r"`(qed/[a-z0-9_/]+/)`", text))
        missing = [path for path in cited if not (ROOT / path).is_dir()]
        assert not missing, f"{sorted(missing)} are cited and do not exist"

    def test_every_adr_it_cites_exists(self, text: str) -> None:
        """This caught a real one: the advisory-adapter concession was
        attributed to ADR-0001, which is the blast-radius table."""
        cited = set(re.findall(r"\bADR-(\d{4})\b", text))
        assert cited
        available = {path.name[:4] for path in (ROOT / "docs" / "adr").glob("*.md")}
        missing = cited - available
        assert not missing, f"ADR-{sorted(missing)} cited and does not exist"

    def test_the_companion_documents_exist(self, text: str) -> None:
        for name in ("SECURITY.md", "docs/assurance-classes.md"):
            assert name in text
            assert (ROOT / name).exists()


class TestTheConfigKeysItNames:
    def test_they_resolve_on_the_real_config(self, text: str) -> None:
        """A key named here and absent from the model is a control an operator
        cannot turn on."""
        from qed.config import QedConfig

        config = QedConfig()
        for dotted in (
            "api.max_clock_skew_seconds",
            "evidence.checkpoint.publishers",
        ):
            assert dotted in text, dotted
            target: object = config
            for part in dotted.split("."):
                assert hasattr(target, part), dotted
                target = getattr(target, part)


class TestItLeadsWithTheLimits:
    def test_the_limitations_section_exists_and_is_substantial(self, text: str) -> None:
        """The section an auditor wants. If it ever gets shorter than the
        STRIDE table, something has been quietly dropped."""
        assert "## What qed does not protect against" in text
        limits = text.split("## What qed does not protect against", 1)[1]
        stride = text.split("## STRIDE", 1)[1].split("## What qed does not", 1)[0]
        assert len(limits) > len(stride), (
            "the limitations are shorter than the controls, which for this "
            "product is the wrong way round"
        )

    def test_it_says_qed_is_advisory_on_most_paths(self, text: str) -> None:
        """The first and largest limitation, and the one a reader most needs
        before they weigh any of the evidence."""
        assert "does not stop anything" in text
        assert "advisory" in text.lower()

    def test_it_says_cli_identity_is_self_asserted(self, text: str) -> None:
        assert "self-asserted" in text

    def test_it_says_an_operator_with_the_key_can_rewrite_the_chain(self, text: str) -> None:
        """The thing anchoring exists for, and the reason `qed doctor` reports
        "anchors: none" in yellow rather than as a neutral fact."""
        assert "rewrite the chain" in text
        assert "only an anchor" in text.lower()

    def test_it_says_shadow_is_the_default(self, text: str) -> None:
        from qed.config import QedConfig

        assert QedConfig().mode.value == "shadow"
        assert "Shadow mode is the shipped default" in text


class TestTheMustTable:
    def test_all_nine_of_the_specs_musts_are_listed(self, text: str) -> None:
        """SPEC §17 has nine. A table with eight is a table that dropped one."""
        table = text.split("## SPEC §17's nine MUSTs", 1)[1]
        rows = [line for line in table.splitlines() if line.startswith("| ") and "|" in line]
        # One header row plus nine MUSTs. The separator row starts `|-`, not
        # `| `, so it is not counted -- which the first run of this test got
        # wrong in the other direction.
        assert len(rows) == 10, f"expected 9 MUSTs, found {len(rows) - 1}"

    def test_the_gated_signing_is_still_described_as_gated(self, text: str) -> None:
        """Publishing is the irreversible step and stays off until the name
        reservations are done. If the workflow ever ungates it, this must be
        updated in the same commit."""
        assert "gated off" in text
        workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
        assert "PUBLISH_GHCR" in workflow
