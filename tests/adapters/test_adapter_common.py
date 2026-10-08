"""The shared adapter library (``gate/adapters/common.py``).

Two things here are load-bearing for the chain and easy to get wrong:

* ``params_hash`` is over the *whole* parameters, so it still identifies the
  real call when ``params_redacted`` had to be trimmed.
* ``params_redacted`` must NOT be masked by the adapter. ``AG-DAT-001`` BLOCKs a
  call whose parameters carry secret material, and it can only do that if it
  sees the material. Masking happens on the way into the chain, after the
  decision.
"""

from __future__ import annotations

import pytest

from gate.adapters.common import (
    MAX_PARAMS_BYTES,
    OMITTED_KEY,
    AdapterInfo,
    bounded_params,
    build_proposal,
    new_proposal_id,
    params_hash,
)
from gate.core import jcs
from gate.core.evidence.hashing import principal_hash
from gate.core.policy.engine import evaluate
from gate.core.policy.model import PolicyBundle
from gate.core.schemas import (
    ActionKind,
    BudgetState,
    Decision,
    Enforcement,
    EvalContext,
    Mode,
)
from tests.conftest import NOW

ADAPTER = AdapterInfo("test-adapter/1.0", "adp_test")


def proposal(params: object, **kwargs: object) -> object:
    defaults: dict[str, object] = {
        "kind": ActionKind.mcp_tool,
        "name": "srv.tool",
        "target": "thing:one",
        "params": params,
        "adapter": ADAPTER,
        "environment": "prod",
        "enforcement": Enforcement.enforcing,
        "mode": Mode.shadow,
        "token_jti": "jti-1",
        "human_hash": "a" * 64,
    }
    defaults.update(kwargs)
    return build_proposal(**defaults)  # type: ignore[arg-type]


class TestParamsHash:
    def test_it_is_stable_and_independent_of_key_order(self) -> None:
        assert params_hash({"a": 1, "b": 2}) == params_hash({"b": 2, "a": 1})

    def test_different_parameters_hash_differently(self) -> None:
        assert params_hash({"sql": "SELECT 1"}) != params_hash({"sql": "SELECT 2"})

    def test_it_is_the_jcs_hash_of_the_canonical_form(self) -> None:
        assert params_hash({"a": 1}) == jcs.sha256_hex({"a": 1})

    def test_it_covers_the_whole_value_even_when_the_copy_is_trimmed(self) -> None:
        """The hash identifies the real call; the redacted copy is a summary."""
        big = {"sql": "x" * (MAX_PARAMS_BYTES * 2)}
        bounded = bounded_params(big)
        assert bounded is not None
        assert len(jcs.dumps(bounded)) <= MAX_PARAMS_BYTES
        assert params_hash(big) != params_hash(bounded)
        assert params_hash(big) == params_hash({"sql": "x" * (MAX_PARAMS_BYTES * 2)})

    def test_an_unserialisable_value_does_not_take_the_call_out_of_the_chain(self) -> None:
        class Opaque:
            def __repr__(self) -> str:
                return "<opaque>"

        assert params_hash({"thing": Opaque()})
        assert bounded_params({"thing": Opaque()}) == {"thing": "<opaque>"}


class TestBoundedParams:
    def test_empty_parameters_become_null(self) -> None:
        """``null`` and ``{}`` are different to the predicate evaluator."""
        assert bounded_params({}) is None
        assert bounded_params(None) is None

    def test_small_parameters_pass_through_unchanged(self) -> None:
        assert bounded_params({"sql": "SELECT 1"}) == {"sql": "SELECT 1"}

    def test_an_oversized_value_is_trimmed_and_says_so(self) -> None:
        bounded = bounded_params({"body": "y" * 100_000})
        assert bounded is not None
        assert "[trimmed:" in str(bounded["body"])
        assert len(jcs.dumps(bounded)) <= MAX_PARAMS_BYTES

    def test_the_keys_survive_trimming(self) -> None:
        """Which parameters were present is often what a rule matches on."""
        bounded = bounded_params({"sql": "z" * 100_000, "table": "orders", "dry_run": False})
        assert bounded is not None
        assert set(bounded) == {"sql", "table", "dry_run"}
        assert bounded["table"] == "orders"

    def test_many_large_values_still_fit(self) -> None:
        bounded = bounded_params({f"k{i}": "q" * 5_000 for i in range(20)})
        assert bounded is not None
        assert len(jcs.dumps(bounded)) <= MAX_PARAMS_BYTES
        assert len(bounded) == 20

    def test_thousands_of_short_values_still_fit(self) -> None:
        """Nothing is long enough to shorten, so keys have to go too.

        An adapter that returned more than the limit here would have the whole
        proposal refused at the API edge (SPEC §17) and the call would leave no
        record at all -- worse than a lossy record.
        """
        bounded = bounded_params({f"k{i}": "ab" for i in range(10_000)})
        assert bounded is not None
        assert len(jcs.dumps(bounded)) <= MAX_PARAMS_BYTES
        assert "9" in str(bounded[OMITTED_KEY]), "the omission must be stated, not silent"
        assert "params_hash still covers" in str(bounded[OMITTED_KEY])

    def test_dropping_keys_is_deterministic(self) -> None:
        """Two adapters with the same parameters must write the same record."""
        params = {f"k{i}": "ab" for i in range(10_000)}
        first = bounded_params(params)
        second = bounded_params(dict(reversed(list(params.items()))))
        assert first == second

    @pytest.mark.parametrize("count", [1, 2, 500, 5_000, 20_000])
    def test_the_limit_is_never_exceeded(self, count: int) -> None:
        bounded = bounded_params({f"key_number_{i}": "x" * 40 for i in range(count)})
        assert bounded is not None
        assert len(jcs.dumps(bounded)) <= MAX_PARAMS_BYTES

    def test_a_deeply_nested_value_terminates(self) -> None:
        nested: object = "leaf"
        for _ in range(100):
            nested = {"a": nested}
        bounded = bounded_params({"root": nested})
        assert bounded is not None
        assert "depth limit" in jcs.dumps(bounded)


class TestTheAdapterMustNotMask:
    def test_a_secret_in_the_parameters_reaches_the_engine(
        self, baseline_bundle: PolicyBundle
    ) -> None:
        """AG-DAT-001 can only BLOCK what it can see.

        If an adapter masked ``params_redacted`` before sending, the rule would
        not fire, the call would be forwarded, and the chain would record a
        clean ALLOW. Masking belongs on the write path, not the decision path.
        """
        built = proposal({"body": "AKIAIOSFODNN7EXAMPLE"})
        verdict = evaluate(
            built,  # type: ignore[arg-type]
            baseline_bundle,
            BudgetState(token_jti="jti-1"),
            EvalContext(now=NOW),
        )
        assert verdict.decision is Decision.BLOCK
        assert "AG-DAT-001" in [hit.rule_id for hit in verdict.hits]

    def test_the_value_is_carried_verbatim(self) -> None:
        built = proposal({"body": "AKIAIOSFODNN7EXAMPLE"})
        assert built.action.params_redacted == {"body": "AKIAIOSFODNN7EXAMPLE"}  # type: ignore[union-attr]


class TestProposalIds:
    def test_they_are_unique(self) -> None:
        assert len({new_proposal_id() for _ in range(500)}) == 500

    def test_they_sort_by_time(self) -> None:
        ids = [new_proposal_id() for _ in range(50)]
        assert ids == sorted(ids)

    def test_a_proposal_gets_one_automatically(self) -> None:
        assert proposal({"a": 1}).id != proposal({"a": 1}).id  # type: ignore[union-attr]


class TestBuildProposal:
    def test_the_hints_land_where_the_rules_look(self) -> None:
        built = proposal({}, writes=True, deletes=True, scope="account")
        hints = built.context.blast_radius_hints  # type: ignore[union-attr]
        assert (hints.writes, hints.deletes, hints.scope) == (True, True, "account")

    def test_the_identity_note_goes_in_the_advisory_field(self) -> None:
        """``client_fingerprint`` is documented as spoofable and never enforced."""
        built = proposal({}, client_fingerprint="adapter-asserted:--human:local")
        assert built.principal.client_fingerprint == "adapter-asserted:--human:local"  # type: ignore[union-attr]

    def test_a_mandate_id_is_carried(self) -> None:
        built = proposal({}, mandate_id="md_01", human_hash=None)
        assert built.principal.mandate_id == "md_01"  # type: ignore[union-attr]


def test_principal_hash_is_stable_and_issuer_scoped() -> None:
    """The same person must hash the same way in every component (SPEC §10.6)."""
    assert principal_hash("ali@acme.com", issuer="okta") == principal_hash(
        "ali@acme.com", issuer="okta"
    )
    assert principal_hash("ali@acme.com", issuer="okta") != principal_hash(
        "ali@acme.com", issuer="keycloak"
    ), "the same `sub` at two issuers is two different people"
    assert len(principal_hash("ali@acme.com")) == 64


def test_the_subject_itself_never_appears_in_the_hash() -> None:
    assert "ali@acme.com" not in principal_hash("ali@acme.com")


@pytest.mark.parametrize("subject", ["", "a", "x" * 1000, "ünïcødé@acme.com"])
def test_principal_hash_accepts_any_subject(subject: str) -> None:
    assert len(principal_hash(subject)) == 64
