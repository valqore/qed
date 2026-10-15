"""Editing a hand-written `qed.yaml` without destroying it.

The thing under test is not "does the adapter appear". It is "does everything
else survive" -- the comments explaining why a setting is what it is, the
blank lines, the key order, the sections this module has never heard of.
A config editor that passes its happy path and quietly deletes an operator's
reasoning has failed at the only job that made it worth writing instead of
telling people to use a text editor.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from qed.config import AdapterCredential, load_config
from qed.infra.config_edit import ConfigEditRefused, add_adapter, rewrite_adapter

HAND_WRITTEN = """\
# Managed by the platform team. Ask before changing `mode`.
instance_id: prod-eu-1

# Enforcing since 2026-09-01. Shadow first if you add rules.
mode: enforce

api:
  host: 0.0.0.0
  port: 8710
"""

WITH_ADAPTERS = """\
# Top matter.
instance_id: prod-eu-1

adapters:
  # The CI runner. Rotated quarterly.
  - adapter_id: mcp-proxy-ci
    secret_env: QED_SECRET_CI
    kind: mcp

api:
  port: 8710
"""

UNDER_API = """\
instance_id: prod-eu-1

api:
  port: 8710
  adapters:
    - adapter_id: first
      secret_env: QED_SECRET_FIRST
      kind: mcp
"""


def write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "qed.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def entry(adapter_id: str = "new-one", **kwargs: str) -> AdapterCredential:
    return AdapterCredential(
        adapter_id=adapter_id,
        secret_env=kwargs.get("secret_env", "QED_SECRET_NEW"),
        kind=kwargs.get("kind", "mcp"),
        previous_secret_env=kwargs.get("previous_secret_env", ""),
    )


class TestWhatMustSurvive:
    def test_every_comment_is_still_there(self, tmp_path: Path) -> None:
        """The reason this module exists. `yaml.safe_dump` of a parsed
        document returns no comments at all, because they were never in the
        parse tree -- a round-trip deletes the operator's reasoning and
        reports success."""
        path = write(tmp_path, HAND_WRITTEN)
        add_adapter(path, entry())
        after = path.read_text(encoding="utf-8")
        assert "# Managed by the platform team. Ask before changing `mode`." in after
        assert "# Enforcing since 2026-09-01. Shadow first if you add rules." in after

    def test_the_original_text_is_untouched(self, tmp_path: Path) -> None:
        """Not merely "the comments are present somewhere": the file before
        the insertion point is byte-for-byte what it was."""
        path = write(tmp_path, HAND_WRITTEN)
        add_adapter(path, entry())
        after = path.read_text(encoding="utf-8")
        assert after.startswith(HAND_WRITTEN.rstrip() + "\n")

    def test_a_comment_inside_the_list_survives(self, tmp_path: Path) -> None:
        path = write(tmp_path, WITH_ADAPTERS)
        add_adapter(path, entry())
        after = path.read_text(encoding="utf-8")
        assert "  # The CI runner. Rotated quarterly." in after

    def test_sections_after_the_list_keep_their_place(self, tmp_path: Path) -> None:
        """Appending after the sequence's trailing blank line would push the
        new item below `api:` -- where it parses as part of a different
        section, or not at all."""
        path = write(tmp_path, WITH_ADAPTERS)
        add_adapter(path, entry())
        after = path.read_text(encoding="utf-8")
        assert after.index("adapter_id: new-one") < after.index("api:")
        assert load_config(path).config.api.port == 8710


class TestWhereTheEntryLands:
    def test_a_file_with_no_adapters_gains_a_top_level_list(self, tmp_path: Path) -> None:
        path = write(tmp_path, HAND_WRITTEN)
        add_adapter(path, entry())
        config = load_config(path).config
        assert [item.adapter_id for item in config.registered_adapters] == ["new-one"]

    def test_an_existing_top_level_list_is_appended_to(self, tmp_path: Path) -> None:
        path = write(tmp_path, WITH_ADAPTERS)
        add_adapter(path, entry())
        config = load_config(path).config
        assert [item.adapter_id for item in config.registered_adapters] == [
            "mcp-proxy-ci",
            "new-one",
        ]

    def test_a_list_under_api_is_appended_to_rather_than_duplicated(self, tmp_path: Path) -> None:
        """Both spellings are honoured by `registered_adapters`, so writing a
        top-level list beside an existing `api.adapters` would leave a file
        with two adapter lists and no explanation."""
        path = write(tmp_path, UNDER_API)
        add_adapter(path, entry())
        after = path.read_text(encoding="utf-8")
        assert after.count("adapters:") == 1
        config = load_config(path).config
        assert [item.adapter_id for item in config.registered_adapters] == ["first", "new-one"]

    def test_the_indentation_matches_the_list_it_joins(self, tmp_path: Path) -> None:
        path = write(tmp_path, UNDER_API)
        add_adapter(path, entry())
        lines = path.read_text(encoding="utf-8").splitlines()
        items = [line for line in lines if line.strip().startswith("- adapter_id:")]
        assert len({len(line) - len(line.lstrip()) for line in items}) == 1

    def test_an_adapters_key_in_another_section_is_not_mistaken_for_this_one(
        self, tmp_path: Path
    ) -> None:
        """A key with the same name under a section the config reader does
        not read is a different key. Appending to it would register nothing
        while printing success."""
        path = write(
            tmp_path,
            "instance_id: x\n\nui:\n  adapters:\n    - name: not-a-credential\n",
        )
        add_adapter(path, entry())
        config = load_config(path).config
        assert [item.adapter_id for item in config.registered_adapters] == ["new-one"]
        assert "not-a-credential" in path.read_text(encoding="utf-8")


class TestWhatItRefuses:
    def test_a_duplicate_adapter_id(self, tmp_path: Path) -> None:
        path = write(tmp_path, WITH_ADAPTERS)
        before = path.read_text(encoding="utf-8")
        with pytest.raises(ConfigEditRefused, match="already registered"):
            add_adapter(path, entry("mcp-proxy-ci"))
        assert path.read_text(encoding="utf-8") == before

    def test_a_flow_sequence(self, tmp_path: Path) -> None:
        """`adapters: []` parses correctly and cannot be appended to by
        anything that works in lines. Refusing costs a paste; guessing costs
        a config file."""
        path = write(tmp_path, "instance_id: x\nadapters: []\n")
        before = path.read_text(encoding="utf-8")
        with pytest.raises(ConfigEditRefused, match="flow sequence"):
            add_adapter(path, entry())
        assert path.read_text(encoding="utf-8") == before

    def test_rotating_an_adapter_that_is_not_there(self, tmp_path: Path) -> None:
        path = write(tmp_path, WITH_ADAPTERS)
        with pytest.raises(ConfigEditRefused, match="not registered"):
            rewrite_adapter(path, entry("absent"))

    def test_a_refusal_leaves_the_file_exactly_as_it_was(self, tmp_path: Path) -> None:
        path = write(tmp_path, WITH_ADAPTERS)
        before = path.read_bytes()
        for bad in (entry("mcp-proxy-ci"),):
            with pytest.raises(ConfigEditRefused):
                add_adapter(path, bad)
        assert path.read_bytes() == before


class TestTheCheckAfterwards:
    """The textual edit is a guess; this is what makes it safe.

    A file that parses but means something else is the failure worth paying
    for, because it is invisible: the command prints success and the adapter
    is registered somewhere nothing reads.
    """

    def test_an_edit_that_changed_anything_else_is_rolled_back(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        path = write(tmp_path, HAND_WRITTEN)
        before = path.read_text(encoding="utf-8")

        import qed.infra.config_edit as module

        real = module._render

        def sabotage(entry: AdapterCredential, indent: int) -> list[str]:
            # Still valid YAML -- a column-0 key simply ends the sequence --
            # so the parse succeeds and says something the operator did not
            # ask for. That is the case the check exists for.
            return [*real(entry, indent), "instance_id: somewhere-else"]

        monkeypatch.setattr(module, "_render", sabotage)
        with pytest.raises(ConfigEditRefused, match="other than the adapter list"):
            add_adapter(path, entry())
        assert path.read_text(encoding="utf-8") == before

    def test_an_edit_that_broke_the_file_is_rolled_back(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        path = write(tmp_path, HAND_WRITTEN)
        before = path.read_text(encoding="utf-8")

        import qed.infra.config_edit as module

        monkeypatch.setattr(module, "_render", lambda entry, indent: ["  : : not yaml ["])
        with pytest.raises(ConfigEditRefused):
            add_adapter(path, entry())
        assert path.read_text(encoding="utf-8") == before


class TestRotation:
    def test_the_entry_is_replaced_in_place(self, tmp_path: Path) -> None:
        """Rotation changes which variables an entry names and nothing else,
        so the comment above it stays above it."""
        path = write(tmp_path, WITH_ADAPTERS)
        rewrite_adapter(
            path,
            entry(
                "mcp-proxy-ci",
                secret_env="QED_SECRET_CI_V2",
                previous_secret_env="QED_SECRET_CI",
            ),
        )
        after = path.read_text(encoding="utf-8")
        assert "  # The CI runner. Rotated quarterly." in after
        assert after.index("# The CI runner") < after.index("adapter_id: mcp-proxy-ci")
        config = load_config(path).config
        registered = config.registered_adapters[0]
        assert registered.secret_env == "QED_SECRET_CI_V2"
        assert registered.previous_secret_env == "QED_SECRET_CI"

    def test_finishing_removes_the_previous_variable(self, tmp_path: Path) -> None:
        path = write(tmp_path, WITH_ADAPTERS)
        rewrite_adapter(
            path,
            entry("mcp-proxy-ci", secret_env="QED_SECRET_CI_V2", previous_secret_env="X"),
        )
        rewrite_adapter(path, entry("mcp-proxy-ci", secret_env="QED_SECRET_CI_V2"))
        assert "previous_secret_env" not in path.read_text(encoding="utf-8")
        assert load_config(path).config.registered_adapters[0].previous_secret_env == ""

    def test_an_entry_whose_id_is_not_its_first_key_is_still_found(self, tmp_path: Path) -> None:
        """`- kind: mcp` with `adapter_id` underneath is the same mapping to
        YAML. Matching only the `- ` line would refuse an adapter the config
        reader can see."""
        path = write(
            tmp_path,
            "instance_id: x\n\nadapters:\n  - kind: mcp\n    adapter_id: odd-order\n"
            "    secret_env: QED_SECRET_ODD\n",
        )
        rewrite_adapter(path, entry("odd-order", secret_env="QED_SECRET_ODD_V2"))
        assert load_config(path).config.registered_adapters[0].secret_env == "QED_SECRET_ODD_V2"
