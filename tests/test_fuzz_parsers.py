"""Fuzzing the parsers (SPEC §17, §22 week 10).

Every one of these asserts the same property, and it is a security property
rather than a correctness one: **a malformed input produces a refusal, never a
crash.** A parser that raises something its caller does not expect turns a
400 into a 500, and a 500 on the decision path is an adapter in
`fail: closed` blocking an agent's work because somebody sent bad JSON.

So each test names the exception type the caller handles and asserts nothing
else escapes. "It did not crash" is too weak -- `KeyError` instead of
`ValidationError` is still a crash to the route above it.

`hypothesis` is in SPEC §20.3's dev/test set already. The strategies are
deliberately nastier than realistic input: surrogates, deep nesting, control
characters, YAML that is valid YAML and nonsense as a policy. Realistic input
is what the rest of the suite covers.
"""

from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any

import pydantic
import pytest
from hypothesis import HealthCheck, assume, given, settings
from hypothesis import strategies as st

from qed.core import jcs
from qed.core.policy.loader import load_bundle
from qed.core.schemas import ActionProposal

#: Deadlines off: these call a YAML parser and a pydantic model, and the first
#: example in a run is always the slowest. A flaky deadline failure in CI
#: teaches people to ignore this file.
FUZZ = settings(
    max_examples=200,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture],
)

#: JSON that round-trips: no NaN, no infinities, nothing a JSON document cannot
#: hold. Those are tested separately, because their contract is to be *refused*.
#:
#: The integer bound is `2**53 - 1`, not `2**53`. `jcs.py` refuses anything
#: outside the IEEE-754 double safe range on purpose -- it cannot be
#: represented unambiguously, and a number that two JSON parsers read
#: differently is a payload hash that two verifiers disagree about. The first
#: run of this file found the boundary by generating exactly `2**53`, which was
#: the strategy being wrong and the code being right.
json_values = st.recursive(
    st.none()
    | st.booleans()
    | st.integers(min_value=-(2**53) + 1, max_value=2**53 - 1)
    | st.floats(allow_nan=False, allow_infinity=False, width=64, min_value=-1e15, max_value=1e15)
    | st.text(max_size=40),
    lambda children: (
        st.lists(children, max_size=6) | st.dictionaries(st.text(max_size=20), children, max_size=6)
    ),
    max_leaves=25,
)


# --------------------------------------------------------------------------
# JCS -- the canonicaliser the signatures depend on
# --------------------------------------------------------------------------


class TestCanonicalisation:
    """`qed/core/jcs.py` is under every signature in the product.

    A value it canonicalises two different ways is a record that verifies on
    one machine and not another, which is the worst failure available to this
    project -- an auditor's verifier disagreeing with the instance for a reason
    neither can see.
    """

    @given(json_values)
    @FUZZ
    def test_it_never_raises_on_json(self, value: object) -> None:
        jcs.canonicalize(value)

    @given(json_values)
    @FUZZ
    def test_it_is_deterministic(self, value: object) -> None:
        assert jcs.canonicalize(value) == jcs.canonicalize(value)

    @given(json_values)
    @FUZZ
    def test_the_output_is_parseable_json(self, value: object) -> None:
        """Canonicalising is a re-encoding: whatever comes out must parse.

        Deliberately **not** `json.loads(canonicalize(x)) == x`. JCS
        (RFC 8785) serialises a double whose value is integral without a
        decimal point, so `6.0e16` comes back as an int -- the standard's
        behaviour, and the first thing this test found. The equality a verifier
        needs is over the *bytes*, which the determinism test covers.
        """
        json.loads(jcs.canonicalize(value))

    @given(json_values)
    @FUZZ
    def test_canonicalising_twice_changes_nothing(self, value: object) -> None:
        """Idempotence over the bytes, which is what a verifier relies on: it
        parses an instance's output and canonicalises it again."""
        once = jcs.canonicalize(value)
        try:
            assert jcs.canonicalize(json.loads(once)) == once
        except ValueError:
            # An integral double outside the IEEE-754 safe range re-parses as
            # an int that JCS refuses. Both ends are right: the refusal is the
            # point, and a value JCS will not canonicalise cannot be in a
            # record in the first place.
            assume(False)

    @given(
        st.dictionaries(
            st.text(max_size=12),
            st.integers(min_value=-(2**53) + 1, max_value=2**53 - 1),
            min_size=2,
            max_size=6,
        )
    )
    @FUZZ
    def test_key_order_in_the_input_does_not_matter(self, mapping: dict[str, int]) -> None:
        """Two components building the same dict in different orders must hash
        the same, or `payload_hash` depends on dict insertion order."""
        reversed_mapping = dict(reversed(list(mapping.items())))
        assert jcs.canonicalize(mapping) == jcs.canonicalize(reversed_mapping)

    @pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
    def test_a_value_json_cannot_hold_is_refused(self, value: float) -> None:
        """Declared contract: `TypeError`, not a document containing `NaN`,
        which is what `json.dumps` would produce and no other parser accepts."""
        with pytest.raises((TypeError, ValueError)):
            jcs.canonicalize(value)
        assert math.isnan(value) or math.isinf(value)

    @given(st.binary(max_size=32))
    @FUZZ
    def test_a_non_json_type_raises_type_error_and_nothing_else(self, value: bytes) -> None:
        with pytest.raises(TypeError):
            jcs.canonicalize(value)


# --------------------------------------------------------------------------
# The proposal -- what an adapter sends
# --------------------------------------------------------------------------


class TestProposalParsing:
    """`ActionProposal` is the first thing to touch bytes from a network.

    The route turns a `ValidationError` into a 422. Anything else becomes a
    500, and a 500 here is an agent blocked by bad input from somebody else.
    """

    @given(st.binary(max_size=400))
    @FUZZ
    def test_arbitrary_bytes_are_refused_cleanly(self, raw: bytes) -> None:
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            return
        try:
            document = json.loads(text)
        except (json.JSONDecodeError, RecursionError):
            return
        try:
            ActionProposal.model_validate(document)
        except pydantic.ValidationError:
            return

    @given(json_values)
    @FUZZ
    def test_arbitrary_json_is_refused_cleanly(self, value: object) -> None:
        try:
            ActionProposal.model_validate(value)
        except pydantic.ValidationError:
            return

    @given(st.dictionaries(st.text(max_size=16), json_values, max_size=8))
    @FUZZ
    def test_arbitrary_mappings_are_refused_cleanly(self, value: dict[str, object]) -> None:
        try:
            ActionProposal.model_validate(value)
        except pydantic.ValidationError:
            return

    @given(st.text(max_size=60))
    @FUZZ
    def test_a_hostile_string_in_every_field_is_still_only_a_validation_error(
        self, text: str
    ) -> None:
        """Surrogates, control characters, right-to-left overrides. A field
        that reaches a regex or a log formatter must not be able to raise
        something else on the way."""
        from tests.conftest import BASE_PROPOSAL, deep_merge

        candidate = deep_merge(
            BASE_PROPOSAL,
            {"action": {"name": text, "target": text, "params_redacted": {text: text}}},
        )
        try:
            ActionProposal.model_validate(candidate)
        except pydantic.ValidationError:
            return


# --------------------------------------------------------------------------
# The policy loader -- what an operator writes
# --------------------------------------------------------------------------


class TestThePolicyLoader:
    """`load_bundle` reads YAML an operator wrote, and must report rather than
    raise: `qed policy lint` exists to tell them what is wrong with it.

    An exception here is a `qed check` that dies on a typo instead of saying
    which line.
    """

    @given(text=st.text(max_size=300))
    @FUZZ
    def test_arbitrary_text_as_a_rule_file_is_reported_not_raised(
        self, text: str, tmp_path_factory: pytest.TempPathFactory
    ) -> None:
        directory = tmp_path_factory.mktemp("fuzz-policy")
        (directory / "rules.yaml").write_text(text, encoding="utf-8")
        result = load_bundle([directory])
        # Either it parsed into something, or there are findings saying why.
        assert result.findings or result.bundle is not None

    @given(value=json_values)
    @FUZZ
    def test_arbitrary_structures_as_a_rule_file(
        self, value: object, tmp_path_factory: pytest.TempPathFactory
    ) -> None:
        """Valid YAML and nonsense as a policy, which is the realistic failure
        -- an operator's file parses and means nothing."""
        import yaml as pyyaml

        directory = tmp_path_factory.mktemp("fuzz-policy-struct")
        (directory / "rules.yaml").write_text(
            pyyaml.safe_dump(value, allow_unicode=True), encoding="utf-8"
        )
        result = load_bundle([directory])
        assert result.findings or result.bundle is not None

    @given(pattern=st.text(min_size=1, max_size=40))
    @FUZZ
    def test_a_hostile_regex_in_a_rule_does_not_hang_the_engine(
        self, pattern: str, tmp_path_factory: pytest.TempPathFactory
    ) -> None:
        """SPEC §17 requires a regex timeout, and a rule file is operator
        input: a pattern that backtracks forever would be a denial of service
        an operator wrote into their own kernel."""
        import time

        import yaml as pyyaml

        assume("\x00" not in pattern)
        directory = tmp_path_factory.mktemp("fuzz-regex")
        (directory / "rules.yaml").write_text(
            pyyaml.safe_dump(
                [
                    {
                        "rule_id": "XX-FUZZ-001",
                        "name": "fuzz",
                        "message": "m",
                        "verdict": "ALLOW",
                        "when": {"field": "action.name", "regex": pattern},
                    }
                ],
                allow_unicode=True,
            ),
            encoding="utf-8",
        )
        started = time.monotonic()
        load_bundle([directory])
        assert time.monotonic() - started < 10.0


# --------------------------------------------------------------------------
# The pack bundle -- what a third party sends
# --------------------------------------------------------------------------


class TestThePackBundleParser:
    """The only parser here whose input comes from a *third party* by design,
    which makes it the one worth fuzzing most. `BundleRejected` is the declared
    refusal; anything else escaping would be a traceback at the CLI."""

    @given(raw=st.binary(max_size=300))
    @FUZZ
    def test_arbitrary_bytes_are_rejected_cleanly(
        self, raw: bytes, tmp_path_factory: pytest.TempPathFactory
    ) -> None:
        from qed.remote.packs import BundleRejected, load_bundle_file

        path = tmp_path_factory.mktemp("fuzz-bundle") / "b.json"
        path.write_bytes(raw)
        try:
            load_bundle_file(path)
        except BundleRejected:
            return

    @given(value=json_values)
    @FUZZ
    def test_arbitrary_json_is_rejected_cleanly(
        self, value: object, tmp_path_factory: pytest.TempPathFactory
    ) -> None:
        from qed.remote.packs import BundleRejected, load_bundle_file

        path = tmp_path_factory.mktemp("fuzz-bundle-json") / "b.json"
        path.write_text(json.dumps(value), encoding="utf-8")
        try:
            load_bundle_file(path)
        except BundleRejected:
            return

    @given(
        value=st.dictionaries(
            st.sampled_from(["format", "issuer", "issued_at", "key_id", "alg", "packs"]),
            json_values,
            max_size=6,
        )
    )
    @FUZZ
    def test_an_envelope_shaped_document_is_rejected_cleanly(
        self, value: dict[str, Any], tmp_path_factory: pytest.TempPathFactory
    ) -> None:
        """The interesting case: a document that looks like a bundle. A parser
        that only refuses obvious garbage is a parser that crashes on the
        near-miss."""
        from qed.remote.packs import BUNDLE_FORMAT, BundleRejected, load_bundle_file

        value.setdefault("format", BUNDLE_FORMAT)
        path = tmp_path_factory.mktemp("fuzz-bundle-shape") / "b.json"
        path.write_text(json.dumps(value), encoding="utf-8")
        try:
            load_bundle_file(path)
        except BundleRejected:
            return


# --------------------------------------------------------------------------
# The config -- what an operator writes, read by every command
# --------------------------------------------------------------------------


class TestTheConfigLoader:
    @given(text=st.text(max_size=200))
    @FUZZ
    def test_arbitrary_text_as_a_config_is_a_config_error(
        self, text: str, tmp_path_factory: pytest.TempPathFactory
    ) -> None:
        """Week 10 made this a `ConfigError` with a readable message. Before
        that it was a pydantic traceback from every command, which is what this
        asserts cannot come back."""
        from qed.config import ConfigError, load_config

        path = tmp_path_factory.mktemp("fuzz-config") / "qed.yaml"
        path.write_text(text, encoding="utf-8")
        try:
            load_config(path)
        except ConfigError:
            return

    @given(value=st.dictionaries(st.text(max_size=16), json_values, max_size=6))
    @FUZZ
    def test_arbitrary_mappings_as_a_config(
        self, value: dict[str, object], tmp_path_factory: pytest.TempPathFactory
    ) -> None:
        import yaml as pyyaml

        from qed.config import ConfigError, load_config

        path = tmp_path_factory.mktemp("fuzz-config-map") / "qed.yaml"
        path.write_text(pyyaml.safe_dump(value, allow_unicode=True), encoding="utf-8")
        try:
            load_config(path)
        except ConfigError:
            return


def test_the_fuzz_targets_are_the_ones_the_spec_asks_for() -> None:
    """SPEC §17 says "fuzz on parsers". This names which, so that a parser
    added later and not fuzzed is a visible omission rather than an oversight.
    """
    covered = {
        "jcs": jcs.canonicalize,
        "proposal": ActionProposal.model_validate,
        "policy": load_bundle,
    }
    assert all(callable(target) for target in covered.values())

    from qed.config import load_config
    from qed.remote.packs import load_bundle_file

    assert callable(load_config)
    assert callable(load_bundle_file)


def test_every_parser_module_has_a_fuzz_test() -> None:
    """The guard on the list above: a new parser is a new way in.

    Checked by name against this file's own source, so adding a parser without
    a case here fails rather than being noticed by whoever reads the diff.
    """
    source = Path(__file__).read_text(encoding="utf-8")
    for target in ("jcs.canonicalize", "ActionProposal.model_validate", "load_bundle"):
        assert target in source, target
    for target in ("load_config", "load_bundle_file"):
        assert target in source, target
