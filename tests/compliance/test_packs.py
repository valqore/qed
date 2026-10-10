"""Control catalogues and coverage (SPEC §11, week 8).

A rule says `compliance: [{framework: eu_ai_act, control: "Art. 14"}]`. Until
week 8 nothing said what `Art. 14` *is*, so an OSCAL export handed an auditor a
list of identifiers with no titles and no way to tell a thorough mapping from a
decorative one.

Most of this file is about not overclaiming, because that is where a compliance
feature does damage:

* **a label is not a quotation** -- every pack carries the standard's `source`,
  and nothing here pretends to be verbatim legal or standards text;
* **a percentage requires a complete catalogue** -- "5 of 5" over a list
  somebody curated reads as complete and is not;
* **an unmapped framework still gets a catalogue**, so the zero is visible.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from qed.cli import app
from qed.compliance.loader import canonical_framework, frameworks
from qed.compliance.packs import (
    Pack,
    control,
    coverage,
    pack,
    packs,
    unknown_controls,
)
from qed.core.policy.loader import baseline_pack_dir, load_bundle

runner = CliRunner()
PACK_DIR = Path(__file__).resolve().parents[2] / "qed" / "compliance" / "packs"


@pytest.fixture(scope="module")
def rules():  # type: ignore[no-untyped-def]
    return load_bundle([baseline_pack_dir()]).bundle.rules


# --------------------------------------------------------------------------
# The catalogues themselves
# --------------------------------------------------------------------------


class TestEveryPackIsWellFormed:
    def test_there_is_one_per_framework_in_the_registry(self) -> None:
        """A framework the normaliser knows and no catalogue defines is a
        framework a rule can cite with no control ever resolving."""
        registered = {fw.id for fw in frameworks()}
        catalogued = {item.framework for item in packs()}
        assert registered == catalogued, registered.symmetric_difference(catalogued)

    @pytest.mark.parametrize("path", sorted(PACK_DIR.glob("*.yaml")), ids=lambda p: p.stem)
    def test_the_file_is_named_after_its_framework(self, path: Path) -> None:
        """So `qed policy lint`'s "add it to packs/<framework>.yaml" is true."""
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        assert data["framework"] == path.stem

    @pytest.mark.parametrize("item", packs(), ids=lambda p: p.framework)
    def test_the_framework_id_is_canonical(self, item: Pack) -> None:
        assert canonical_framework(item.framework) == item.framework

    @pytest.mark.parametrize("item", packs(), ids=lambda p: p.framework)
    def test_every_control_has_a_label_and_the_pack_has_a_source(self, item: Pack) -> None:
        """The source is what makes a label safe to write. An auditor who wants
        the standard's own words follows it; nothing here claims to quote."""
        assert item.source.startswith("https://")
        assert item.controls or item.framework == "iso_42001"
        for entry in item.controls:
            assert entry.id.strip() == entry.id
            assert len(entry.label) > 3, (item.framework, entry.id)

    @pytest.mark.parametrize("item", packs(), ids=lambda p: p.framework)
    def test_control_ids_are_unique(self, item: Pack) -> None:
        ids = [entry.id for entry in item.controls]
        assert len(ids) == len(set(ids)), item.framework

    @pytest.mark.parametrize("item", packs(), ids=lambda p: p.framework)
    def test_every_catalogue_says_what_it_covers(self, item: Pack) -> None:
        """`scope` is the sentence an auditor needs, and **a complete catalogue
        needs it too**.

        For a partial one it says that absence means "not mapped" rather than
        "not applicable". For a complete one it says what the completeness is
        *of*: `eu_ai_act` prints a percentage, and 44.4% reads as a share of
        the Regulation when it is a share of nine articles out of 113.
        """
        assert item.scope, f"{item.framework} says nothing about its scope"

    def test_the_edition_is_recorded_where_identifiers_depend_on_it(self) -> None:
        """`PR.AC-4` is a CSF 1.1 identifier and does not exist in 2.0, where
        the family was renamed to PR.AA. A mapping to a retired identifier is
        one nobody can follow, so the version is written down."""
        csf = pack("nist_csf")
        assert csf is not None
        assert csf.version == "1.1"


class TestLookups:
    def test_a_control_resolves_by_canonical_id(self) -> None:
        found = control("eu_ai_act", "Art. 14")
        assert found is not None
        assert "oversight" in found.label.lower()

    def test_a_control_resolves_through_an_alias(self) -> None:
        """The normaliser's whole job: `EU AI Act` and `eu_ai_act` are one
        framework, so a lookup must not depend on which a rule wrote."""
        assert control("EU AI Act", "Art. 14") == control("eu_ai_act", "Art. 14")

    def test_an_unknown_framework_is_none_rather_than_an_error(self) -> None:
        assert pack("not_a_framework") is None
        assert control("not_a_framework", "X") is None

    def test_an_unknown_control_is_none(self) -> None:
        assert control("eu_ai_act", "Art. 999") is None


# --------------------------------------------------------------------------
# What the rules actually map
# --------------------------------------------------------------------------


class TestTheBaselinePackResolves:
    def test_every_mapping_has_a_catalogue_entry(self, rules) -> None:  # type: ignore[no-untyped-def]
        """The invariant `qed policy lint` enforces as an **error**. A control
        id that is almost right reaches the OSCAL export looking exactly like a
        real mapping, and the first person to notice is the auditor who goes
        looking for the control."""
        assert unknown_controls(rules) == []

    def test_lint_rejects_a_control_nothing_defines(self, tmp_path: Path) -> None:
        broken = tmp_path / "rules"
        broken.mkdir()
        (broken / "bad.yaml").write_text(
            yaml.safe_dump(
                [
                    {
                        "rule_id": "XX-BAD-001",
                        "name": "cites a control that does not exist",
                        "message": "m",
                        "verdict": "BLOCK",
                        "when": {"field": "action.name", "equals": "x"},
                        "compliance": [{"framework": "eu_ai_act", "control": "Art. 999"}],
                    }
                ]
            ),
            encoding="utf-8",
        )
        result = load_bundle([broken])
        codes = {finding.code for finding in result.findings}
        assert "unknown_control" in codes
        assert not result.ok, "an uncatalogued control must be an error, not a warning"

    def test_the_message_says_where_to_add_it(self, tmp_path: Path) -> None:
        broken = tmp_path / "rules"
        broken.mkdir()
        (broken / "bad.yaml").write_text(
            yaml.safe_dump(
                [
                    {
                        "rule_id": "XX-BAD-002",
                        "name": "x",
                        "message": "m",
                        "verdict": "ALLOW",
                        "when": {"field": "action.name", "equals": "x"},
                        "compliance": [{"framework": "soc2", "control": "CC9.9"}],
                    }
                ]
            ),
            encoding="utf-8",
        )
        findings = [f for f in load_bundle([broken]).findings if f.code == "unknown_control"]
        assert findings
        assert "packs/soc2.yaml" in findings[0].message


class TestCoverage:
    def test_a_complete_catalogue_gets_a_percentage(self, rules) -> None:  # type: ignore[no-untyped-def]
        rows = {row.framework: row for row in coverage(rules)}
        eu = rows["eu_ai_act"]
        assert eu.catalogue == "complete"
        assert eu.percentage is not None
        assert 0 < eu.percentage < 100, "4 of 9 articles, so neither extreme"

    def test_a_partial_catalogue_refuses_one(self, rules) -> None:  # type: ignore[no-untyped-def]
        """The honesty rule. "9 of 9" over a curated list reads as complete and
        means "every criterion we chose to list"."""
        rows = {row.framework: row for row in coverage(rules)}
        soc2 = rows["soc2"]
        assert soc2.catalogue == "partial"
        assert soc2.mapped == soc2.controls
        assert soc2.percentage is None, "a partial catalogue printed 100%"

    def test_an_unmapped_framework_is_listed_at_zero(self, rules) -> None:  # type: ignore[no-untyped-def]
        """Omitting the pack would make it look like a framework nobody had
        considered. A visible zero is a gap somebody can close."""
        rows = {row.framework: row for row in coverage(rules)}
        assert rows["iso_42001"].mapped == 0
        assert rows["iso_42001"].controls > 0
        assert rows["iso_42001"].rules == ()

    def test_a_deliberate_gap_says_why(self, rules) -> None:  # type: ignore[no-untyped-def]
        """A stated reason is something an auditor can disagree with; a bare
        absence is something they can only guess at."""
        rows = {row.framework: row for row in coverage(rules)}
        eu = rows["eu_ai_act"]
        assert set(eu.unmapped_notes) <= set(eu.unmapped), "a mapped control carries a gap note"
        assert "Art. 11" in eu.unmapped_notes
        assert "documentation" in eu.unmapped_notes["Art. 11"]

    def test_a_note_is_a_claim_about_the_kernel(self, rules) -> None:  # type: ignore[no-untyped-def]
        """Not a reading of the standard. "Nothing here records X" is
        checkable; "this does not apply to us" is a legal opinion and has no
        business in a YAML file."""
        rows = {row.framework: row for row in coverage(rules)}
        for note in rows["eu_ai_act"].unmapped_notes.values():
            assert "not applicable" not in note.lower()
            assert "does not apply" not in note.lower()

    def test_the_unmapped_controls_are_named(self, rules) -> None:  # type: ignore[no-untyped-def]
        """The question an auditor asks first is which controls you do *not*
        claim."""
        rows = {row.framework: row for row in coverage(rules)}
        assert "Art. 9" in rows["eu_ai_act"].unmapped
        assert "Art. 14" not in rows["eu_ai_act"].unmapped

    def test_the_scope_travels_with_the_row(self, rules) -> None:  # type: ignore[no-untyped-def]
        rows = {row.framework: row for row in coverage(rules)}
        assert "Chapter III Section 2" in rows["eu_ai_act"].scope
        assert all(row.scope for row in rows.values())

    def test_the_depth_flag_comes_from_the_registry(self, rules) -> None:  # type: ignore[no-untyped-def]
        """SPEC §11's honesty flag: how deep the mapping goes, not how good."""
        rows = {row.framework: row for row in coverage(rules)}
        assert rows["eu_ai_act"].depth == "article"
        assert rows["nist_ai_rmf"].depth == "category"
        assert rows["dora"].depth == "pack"

    def test_aliases_do_not_split_a_framework_in_two(self, tmp_path: Path) -> None:
        """Two spellings would be two rows in this report and two control sets
        in an OSCAL export, with nothing telling the reader they are one
        framework. That is what `policy normalize-frameworks` is for, and this
        asserts the report groups them regardless."""
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "aliased.yaml").write_text(
            yaml.safe_dump(
                [
                    {
                        "rule_id": "XX-ALIAS-001",
                        "name": "x",
                        "message": "m",
                        "verdict": "ALLOW",
                        "when": {"field": "action.name", "equals": "a"},
                        "compliance": [{"framework": "EU AI Act", "control": "Art. 14"}],
                    },
                    {
                        "rule_id": "XX-ALIAS-002",
                        "name": "y",
                        "message": "m",
                        "verdict": "ALLOW",
                        "when": {"field": "action.name", "equals": "b"},
                        "compliance": [{"framework": "eu_ai_act", "control": "Art. 10"}],
                    },
                ]
            ),
            encoding="utf-8",
        )
        rows = {row.framework: row for row in coverage(load_bundle([rules_dir]).bundle.rules)}
        assert rows["eu_ai_act"].mapped == 2
        assert len(rows["eu_ai_act"].rules) == 2


# --------------------------------------------------------------------------
# The command
# --------------------------------------------------------------------------


class TestPacksList:
    def test_it_reports_every_framework(self) -> None:
        result = runner.invoke(app, ["packs", "list", "--json"])
        assert result.exit_code == 0, result.output
        report = json.loads(result.output)
        assert len(report["catalogues"]) == len(packs())
        assert all(url.startswith("https://") for url in report["sources"].values())

    def test_a_partial_catalogue_has_a_null_percentage_in_json(self) -> None:
        report = json.loads(runner.invoke(app, ["packs", "list", "--json"]).output)
        by_id = {item["framework"]: item for item in report["catalogues"]}
        assert by_id["soc2"]["percentage"] is None
        assert by_id["eu_ai_act"]["percentage"] is not None

    def test_the_table_names_the_unmapped_controls(self) -> None:
        result = runner.invoke(app, ["packs", "list"])
        assert result.exit_code == 0, result.output
        assert "not mapped" in result.output
        assert "Art. 9" in result.output

    def test_a_stated_gap_prints_its_reason(self) -> None:
        output = runner.invoke(app, ["packs", "list"]).output
        assert "not mapped -- Art. 26:" in output
        assert "the gap is in the rules" in " ".join(output.split())

    def test_gaps_with_no_reason_are_still_listed(self) -> None:
        """ISO 42001 has eight unmapped clauses and no notes; they must not
        vanish because the notes path took over."""
        output = runner.invoke(app, ["packs", "list"]).output
        assert "iso_42001: not mapped -- 4.1," in output

    def test_a_percentage_never_appears_without_its_scope(self) -> None:
        """The scope is the half a reader drops, so it prints with the number
        instead of staying in a YAML file nobody opens."""
        output = runner.invoke(app, ["packs", "list"]).output
        assert "44.4%" in output
        assert "Chapter III Section 2" in output
        assert "complete for the scope" in output

    def test_every_framework_scope_is_printed(self) -> None:
        output = runner.invoke(app, ["packs", "list"]).output
        for item in packs():
            assert f"  {item.framework}:" in output, item.framework

    def test_the_gap_notes_are_in_the_json(self) -> None:
        report = json.loads(runner.invoke(app, ["packs", "list", "--json"]).output)
        by_id = {item["framework"]: item for item in report["catalogues"]}
        assert "Art. 26" in by_id["eu_ai_act"]["unmapped_notes"]
        assert by_id["iso_42001"]["unmapped_notes"] == {}

    def test_the_scope_is_in_the_json(self) -> None:
        report = json.loads(runner.invoke(app, ["packs", "list", "--json"]).output)
        assert all(item["scope"] for item in report["catalogues"])

    def test_the_table_explains_what_partial_means(self) -> None:
        """Otherwise a reader sees `partial` in a coverage column and assumes
        it is a bad score rather than a refusal to score."""
        output = runner.invoke(app, ["packs", "list"]).output
        assert "no honest percentage" in output

    def test_the_output_is_ascii(self) -> None:
        """A Windows console at the default code page cannot encode a section
        sign, which was a week-1 bug."""
        output = runner.invoke(app, ["packs", "list"]).output
        assert all(ord(char) < 127 for char in output), [
            char for char in output if ord(char) >= 127
        ]

    def test_import_exists_and_needs_a_key(self, tmp_path: Path) -> None:
        """Week 9 built it. The refusal moved from "not implemented" to "say
        which key vouches for these control titles" -- `tests/compliance/
        test_pack_bundles.py` is where the bundle format lives."""
        missing = tmp_path / "whatever.qedpack.json"
        result = runner.invoke(app, ["packs", "import", str(missing)])
        assert result.exit_code == 1
        assert "cannot read" in result.output


class TestNormalizeFrameworks:
    def write(self, tmp_path: Path, framework: str) -> Path:
        path = tmp_path / "rules.yaml"
        path.write_text(
            "- rule_id: XX-001\n"
            "  name: x\n"
            "  message: m\n"
            "  verdict: ALLOW\n"
            "  when: { field: action.name, equals: x }\n"
            "  compliance:\n"
            f'    - {{ framework: {framework}, control: "Art. 14" }}\n',
            encoding="utf-8",
        )
        return path

    def test_an_alias_is_rewritten(self, tmp_path: Path) -> None:
        path = self.write(tmp_path, '"EU AI Act"')
        result = runner.invoke(app, ["policy", "normalize-frameworks", str(path)])
        assert result.exit_code == 0, result.output
        assert "eu_ai_act" in path.read_text(encoding="utf-8")
        assert "EU AI Act" not in path.read_text(encoding="utf-8")

    def test_a_canonical_id_is_left_alone(self, tmp_path: Path) -> None:
        path = self.write(tmp_path, "eu_ai_act")
        before = path.read_text(encoding="utf-8")
        result = runner.invoke(app, ["policy", "normalize-frameworks", str(path)])
        assert result.exit_code == 0
        assert path.read_text(encoding="utf-8") == before
        assert "already canonical" in result.output

    def test_check_reports_without_writing(self, tmp_path: Path) -> None:
        path = self.write(tmp_path, '"EU AI Act"')
        before = path.read_text(encoding="utf-8")
        result = runner.invoke(app, ["policy", "normalize-frameworks", str(path), "--check"])
        assert result.exit_code == 1
        assert path.read_text(encoding="utf-8") == before
        assert "EU AI Act -> eu_ai_act" in result.output

    def test_it_only_touches_the_framework_value(self, tmp_path: Path) -> None:
        """Text substitution, not a YAML round-trip: a reformat would rewrite
        every comment and quote style in a file somebody wrote by hand, and the
        diff would be unreviewable."""
        path = tmp_path / "rules.yaml"
        path.write_text(
            "# a comment that must survive\n"
            "- rule_id: XX-001   # and this one\n"
            "  name: 'single quoted'\n"
            "  message: m\n"
            "  verdict: ALLOW\n"
            "  when: { field: action.name, equals: x }\n"
            "  compliance:\n"
            '    - { framework: "AI Act", control: "Art. 14" }\n',
            encoding="utf-8",
        )
        runner.invoke(app, ["policy", "normalize-frameworks", str(path)])
        after = path.read_text(encoding="utf-8")
        assert "# a comment that must survive" in after
        assert "# and this one" in after
        assert "'single quoted'" in after
        assert 'framework: "eu_ai_act"' in after

    def test_a_directory_is_walked(self, tmp_path: Path) -> None:
        nested = tmp_path / "policies" / "deep"
        nested.mkdir(parents=True)
        self.write(nested, '"AI Act"')
        result = runner.invoke(app, ["policy", "normalize-frameworks", str(tmp_path)])
        assert result.exit_code == 0, result.output
        assert "eu_ai_act" in (nested / "rules.yaml").read_text(encoding="utf-8")

    def test_an_unknown_framework_is_left_for_the_linter(self, tmp_path: Path) -> None:
        """It cannot be normalised and it is not this command's job to refuse
        it: `policy lint` already reports an unknown framework, and a rewriter
        that errored on one would stop somebody fixing the other twenty."""
        path = self.write(tmp_path, "not_a_framework")
        result = runner.invoke(app, ["policy", "normalize-frameworks", str(path)])
        assert result.exit_code == 0
        assert "not_a_framework" in path.read_text(encoding="utf-8")

    def test_a_missing_path_is_refused(self, tmp_path: Path) -> None:
        result = runner.invoke(app, ["policy", "normalize-frameworks", str(tmp_path / "nope.yaml")])
        assert result.exit_code == 1
        assert "does not exist" in result.output


# --------------------------------------------------------------------------
# OSCAL
# --------------------------------------------------------------------------


class TestTheExportCarriesTheCatalogue:
    def test_a_finding_names_the_control(self) -> None:
        from qed.core.evidence.export.oscal import TITLE_LABEL_CHARS, _target_title

        title = _target_title("eu_ai_act", "Art. 14")
        assert title == "eu_ai_act Art. 14 -- Human oversight"
        assert TITLE_LABEL_CHARS > 40

    def test_a_long_label_is_truncated_in_the_title_only(self) -> None:
        """A NIST AI RMF subcategory runs to 160 characters; a title that long
        makes a report table unreadable. The full text stays in the prop."""
        from qed.core.evidence.export.oscal import _label, _target_title

        title = _target_title("nist_ai_rmf", "GOVERN-1.5")
        label = _label("nist_ai_rmf", "GOVERN-1.5")
        assert label is not None
        assert title.endswith("...")
        assert len(title) < len(label)

    def test_an_uncatalogued_control_falls_back_to_the_identifier(self) -> None:
        """Should not happen -- lint makes it an error -- and an absent label
        is honest where "unknown" in a title would read as the control's name.
        """
        from qed.core.evidence.export.oscal import _target_title

        assert _target_title("eu_ai_act", "Art. 999") == "eu_ai_act Art. 999"

    def test_the_depth_and_source_travel_with_every_finding(self) -> None:
        from qed.core.evidence.export.oscal import _catalogue_source, _depth

        assert _depth("eu_ai_act") == "article"
        assert _catalogue_source("eu_ai_act").startswith("https://eur-lex")  # type: ignore[union-attr]
