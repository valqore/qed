"""The Secret wrapper (SPEC §7.2).

"Never log a credential" is a rule people break by accident: an exception
handler that formats its locals, a debug print left in, a model dumped to
JSON. Every test here is one of those accidents, and the point is that the
accident produces `<redacted>` rather than the token.
"""

from __future__ import annotations

import json
import logging
import pprint
import traceback

import pytest

from qed.core.broker.model import REDACTED, Secret

TOKEN = "ghp_realLookingTokenThatMustNeverAppear"


class TestItCannotBePrintedByAccident:
    def test_str(self) -> None:
        assert str(Secret(TOKEN)) == REDACTED

    def test_repr(self) -> None:
        assert TOKEN not in repr(Secret(TOKEN))

    def test_an_f_string(self) -> None:
        assert TOKEN not in f"token is {Secret(TOKEN)}"

    def test_percent_formatting(self) -> None:
        # noqa: the point of this test is the old-style path, which is
        # exactly where an accidental leak still happens.
        assert TOKEN not in "token is %s" % (Secret(TOKEN),)  # noqa: UP031

    def test_format_with_a_spec(self) -> None:
        assert TOKEN not in f"{Secret(TOKEN):>40}"

    def test_pprint(self) -> None:
        assert TOKEN not in pprint.pformat({"credential": Secret(TOKEN)})

    def test_inside_a_container(self) -> None:
        assert TOKEN not in repr({"a": [Secret(TOKEN)]})

    def test_a_log_record(self, caplog: pytest.LogCaptureFixture) -> None:
        """The most common accident of all."""
        with caplog.at_level(logging.DEBUG):
            logging.getLogger("test").info("resolved %s", Secret(TOKEN))
        assert TOKEN not in caplog.text

    def test_a_traceback_that_formats_locals(self) -> None:
        def boom(credential: Secret) -> None:
            raise RuntimeError(f"failed with {credential}")

        try:
            boom(Secret(TOKEN))
        except RuntimeError as exc:
            rendered = "".join(traceback.format_exception(exc))
        assert TOKEN not in rendered

    def test_json_dumps_refuses_rather_than_leaking(self) -> None:
        """Refusing is the right failure: a Secret silently serialised into a
        payload is the leak this class exists to prevent."""
        with pytest.raises(TypeError):
            json.dumps({"credential": Secret(TOKEN)})


class TestGettingTheValueOut:
    def test_reveal_returns_it(self) -> None:
        assert Secret(TOKEN).reveal() == TOKEN

    def test_reveal_is_the_only_way(self) -> None:
        """Deliberately awkward to type, so a leak has to be written on
        purpose rather than reached by habit."""
        public = {name for name in dir(Secret) if not name.startswith("_")}
        assert public == {"reveal"}


class TestUsefulWithoutRevealing:
    def test_emptiness_is_knowable(self) -> None:
        assert bool(Secret("")) is False
        assert bool(Secret(TOKEN)) is True

    def test_length_is_knowable(self) -> None:
        """Enough for a health check to say "set but empty" without printing
        anything."""
        assert len(Secret(TOKEN)) == len(TOKEN)

    def test_two_secrets_compare(self) -> None:
        assert Secret(TOKEN) == Secret(TOKEN)
        assert Secret(TOKEN) != Secret("other")

    def test_it_is_not_usable_as_a_dict_key(self) -> None:
        """A hash of the value in a dict is a value in a dict."""
        with pytest.raises(TypeError, match="not hashable"):
            {Secret(TOKEN): 1}
