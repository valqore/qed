"""RFC 8785 canonicalisation."""

from __future__ import annotations

import pytest

from qed.core import jcs


def test_object_keys_are_sorted() -> None:
    assert jcs.dumps({"b": 1, "a": 2, "A": 3}) == '{"A":3,"a":2,"b":1}'


def test_no_whitespace_anywhere() -> None:
    assert jcs.dumps({"a": [1, 2, {"b": None}]}) == '{"a":[1,2,{"b":null}]}'


def test_keys_sort_by_utf16_code_unit_not_code_point() -> None:
    """RFC 8785 §3.2.3. The two orders differ for astral characters.

    U+1F600 is a surrogate pair in UTF-16 (0xD83D 0xDE00), so it sorts *before*
    U+FF01 (0xFF01) even though its code point is larger.
    """
    rendered = jcs.dumps({"！": 1, "\U0001f600": 2})
    assert rendered.index("\U0001f600") < rendered.index("！")


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (0, "0"),
        (-0, "0"),
        (1, "1"),
        (-17, "-17"),
        (2**53 - 1, "9007199254740991"),
        (0.0, "0"),
        (-0.0, "0"),
        (1.0, "1"),
        (1.5, "1.5"),
        (-2.25, "-2.25"),
        (1e21, "1e+21"),
        (1e-7, "1e-7"),
        (0.000001, "0.000001"),
        (1e20, "100000000000000000000"),
    ],
)
def test_numbers_follow_ecmascript_tostring(value: float, expected: str) -> None:
    assert jcs.dumps(value) == expected


def test_integers_beyond_the_safe_range_are_refused() -> None:
    with pytest.raises(ValueError, match="safe range"):
        jcs.dumps(2**53)


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_nan_and_infinity_are_refused(value: float) -> None:
    with pytest.raises(ValueError):
        jcs.dumps(value)


def test_control_characters_use_the_short_escapes() -> None:
    assert jcs.dumps('a\nb\tc"d\\e') == r'"a\nb\tc\"d\\e"'


def test_other_control_characters_use_lowercase_hex() -> None:
    assert jcs.dumps("\x00\x1f") == '"\\u0000\\u001f"'


def test_non_ascii_is_not_escaped() -> None:
    assert jcs.dumps("Ünïcode") == '"Ünïcode"'


def test_non_string_keys_are_refused() -> None:
    with pytest.raises(TypeError):
        jcs.dumps({1: "a"})


def test_unsupported_types_are_refused() -> None:
    with pytest.raises(TypeError):
        jcs.dumps(object())


def test_deeply_nested_input_is_refused() -> None:
    value: object = 1
    for _ in range(200):
        value = [value]
    with pytest.raises(ValueError, match="nested"):
        jcs.dumps(value)


def test_hash_is_stable_across_key_insertion_order() -> None:
    a = {"x": 1, "y": {"b": 2, "a": 3}}
    b = {"y": {"a": 3, "b": 2}, "x": 1}
    assert jcs.sha256_hex(a) == jcs.sha256_hex(b)
