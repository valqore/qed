"""Signed control catalogues and the air-gap import (SPEC §11, week 9).

An imported catalogue decides what `qed packs list` reports and what an OSCAL
finding's `control-label` says. So the question this file exists to pin down is
**who vouches for these control titles**, and the answers are all refusals:

* an unsigned bundle needs a flag, and the flag is recorded;
* a bundle naming its own key proves nothing, so the key comes from elsewhere;
* a modified bundle does not verify, and a modification that changed nothing
  is not a test (the earlier validation script taught that one);
* a bundle older than the installed one is a rollback and is refused;
* and a bundle that would leave a rule citing a control it does not define is
  refused **before anything is written**, because an import that stops the
  kernel deciding is not an import. That one was found by running it.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from typer.testing import CliRunner

from qed.compliance.packs import Control, Pack, pack, packs, use_imported
from qed.core.evidence.signing import key_id_for, sign_with
from qed.core.policy.loader import baseline_pack_dir, load_bundle
from qed.remote.packs import (
    BUNDLE_FORMAT,
    BundleRejected,
    bundle_payload,
    check_not_older,
    installed_dir,
    load_bundle_file,
    load_public_key,
    read_installed,
    sign_bundle,
    verify,
    would_break,
    write_installed,
)

runner = CliRunner()

#: The DORA controls the baseline rules cite. A bundle that keeps all three is
#: a deepening; a bundle that drops any of them orphans the rules citing it.
#:
#: This was one control until week 9 deepened the DORA mapping to Articles 8, 9
#: and 10 -- and the deepening broke four tests here, which is `would_break`
#: doing its job on real data rather than on a fixture built to trip it.
SHIPPED_DORA_CONTROLS = ("Art. 8", "Art. 9", "Art. 10")
SHIPPED_DORA_CONTROL = SHIPPED_DORA_CONTROLS[0]


@pytest.fixture(autouse=True)
def shipped_only() -> Any:
    """Every test starts from the shipped catalogues.

    `use_imported` is module state by design (the policy loader and the OSCAL
    export both ask, and neither has a state directory in scope), so it has to
    be put back or one test's import decides another test's coverage.
    """
    use_imported(None)
    yield
    use_imported(None)


@pytest.fixture(scope="module")
def rules():  # type: ignore[no-untyped-def]
    """The baseline rules, loaded once.

    **Module scope, not class scope.** A class-scoped fixture sitting under the
    function-scoped autouse fixture above trips pytest's own
    `assert not self._finalizers` -- which this project has now hit three times
    in three different files.
    """
    return load_bundle([baseline_pack_dir()]).bundle.rules


@pytest.fixture
def publisher() -> Any:
    private = Ed25519PrivateKey.generate()
    return private, private.public_key(), key_id_for(private.public_key())


def catalogue(*, drop_shipped: bool = False) -> Pack:
    """A DORA catalogue, optionally missing what the shipped rules cite.

    `drop_shipped=True` drops `Art. 8` only. The other two stay, so the test
    for a bundle that orphans a rule is about one identifiable control rather
    than about a bundle that happens to be smaller.
    """
    controls = [
        Control(id="Art. 5", label="Governance and organisation"),
        Control(id="Art. 9", label="Protection and prevention"),
        Control(id="Art. 10", label="Detection"),
    ]
    if not drop_shipped:
        controls.insert(0, Control(id=SHIPPED_DORA_CONTROL, label="Identification"))
    return Pack(
        framework="dora",
        source="https://eur-lex.europa.eu/eli/reg/2022/2554/oj",
        catalogue="partial",
        scope="The ICT risk-management articles this bundle maps.",
        controls=controls,
    )


def envelope(
    publisher: Any,
    *,
    issued: str = "2026-10-10T12:00:00+00:00",
    drop_shipped: bool = False,
    packs_override: list[Pack] | None = None,
) -> dict[str, Any]:
    private, _public, kid = publisher
    return sign_bundle(
        packs_override or [catalogue(drop_shipped=drop_shipped)],
        issuer="test-publisher",
        issued_at=datetime.fromisoformat(issued).astimezone(UTC),
        sign=lambda payload: sign_with(private, payload),
        key_id=kid,
    )


def write(tmp_path: Path, data: dict[str, Any], name: str = "bundle.qedpack.json") -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return path


def write_key(tmp_path: Path, publisher: Any) -> Path:
    _private, public, _kid = publisher
    path = tmp_path / "pack-key.pem"
    path.write_bytes(public.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))
    return path


# --------------------------------------------------------------------------
# The format
# --------------------------------------------------------------------------


class TestTheEnvelope:
    def test_a_signed_bundle_verifies(self, tmp_path: Path, publisher: Any) -> None:
        bundle = load_bundle_file(write(tmp_path, envelope(publisher)))
        verify(bundle, publisher[1])
        assert bundle.signed
        assert bundle.key_id == publisher[2]

    def test_the_signature_covers_everything_but_itself(self, publisher: Any) -> None:
        data = envelope(publisher)
        assert "signature" not in json.loads(bundle_payload(data))
        assert set(json.loads(bundle_payload(data))) == set(data) - {"signature"}

    def test_relabelling_the_key_breaks_it(self, tmp_path: Path, publisher: Any) -> None:
        """`key_id` is inside the signature. Otherwise anyone could restate
        which key signed a bundle, and the name would mean nothing."""
        data = envelope(publisher)
        data["key_id"] = "ed25519:0000000000000000"
        bundle = load_bundle_file(write(tmp_path, data))
        with pytest.raises(BundleRejected, match="signed by key"):
            verify(bundle, publisher[1])

    def test_moving_issued_at_breaks_it(self, tmp_path: Path, publisher: Any) -> None:
        """Otherwise the rollback check is defeated by editing one string."""
        data = envelope(publisher)
        before = data["issued_at"]
        data["issued_at"] = "2030-01-01T00:00:00.000Z"
        assert data["issued_at"] != before
        bundle = load_bundle_file(write(tmp_path, data))
        with pytest.raises(BundleRejected, match="does not verify"):
            verify(bundle, publisher[1])

    def test_changing_a_control_label_breaks_it(self, tmp_path: Path, publisher: Any) -> None:
        """The label is the thing an auditor reads, so it is the thing worth
        tampering with. The assertion that the value *changed* is deliberate:
        a tamper that set a field to what it already held once produced a
        verifier that looked like it accepted a forgery."""
        data = envelope(publisher)
        before = data["packs"][0]["controls"][0]["label"]
        data["packs"][0]["controls"][0]["label"] = "Something else entirely"
        assert data["packs"][0]["controls"][0]["label"] != before
        bundle = load_bundle_file(write(tmp_path, data))
        with pytest.raises(BundleRejected, match="does not verify"):
            verify(bundle, publisher[1])

    def test_another_key_does_not_verify_it(self, tmp_path: Path, publisher: Any) -> None:
        other = Ed25519PrivateKey.generate().public_key()
        bundle = load_bundle_file(write(tmp_path, envelope(publisher)))
        with pytest.raises(BundleRejected):
            verify(bundle, other)

    def test_an_unsigned_bundle_is_not_quietly_accepted(
        self, tmp_path: Path, publisher: Any
    ) -> None:
        data = envelope(publisher)
        data.pop("signature")
        bundle = load_bundle_file(write(tmp_path, data))
        assert not bundle.signed
        with pytest.raises(BundleRejected, match="--unsigned"):
            verify(bundle, publisher[1])

    def test_a_foreign_algorithm_is_refused(self, tmp_path: Path, publisher: Any) -> None:
        """There is no second code path to fall back to: Ed25519 only, and
        `tests/evidence/test_no_hmac.py` fails the build if one appears."""
        data = envelope(publisher)
        data["alg"] = "HS256"
        bundle = load_bundle_file(write(tmp_path, data))
        with pytest.raises(BundleRejected, match="Ed25519 only"):
            verify(bundle, publisher[1])

    def test_an_unknown_format_version_is_refused(self, tmp_path: Path, publisher: Any) -> None:
        data = envelope(publisher)
        data["format"] = "qed-pack-bundle/99"
        with pytest.raises(BundleRejected, match="needs a newer qed"):
            load_bundle_file(write(tmp_path, data))

    def test_two_catalogues_for_one_framework_are_refused(
        self, tmp_path: Path, publisher: Any
    ) -> None:
        """Which one wins would decide what a control reference resolves to."""
        data = envelope(publisher, packs_override=[catalogue(), catalogue()])
        with pytest.raises(BundleRejected, match="two catalogues"):
            load_bundle_file(write(tmp_path, data))

    def test_a_bundle_with_no_issued_at_is_refused(self, tmp_path: Path, publisher: Any) -> None:
        data = envelope(publisher)
        data.pop("issued_at")
        with pytest.raises(BundleRejected, match="issued_at"):
            load_bundle_file(write(tmp_path, data))

    def test_the_bundle_hash_covers_the_signature(self, tmp_path: Path, publisher: Any) -> None:
        """Two bundles with the same catalogues and different signatures are
        different things to an auditor asking which one was installed."""
        first = load_bundle_file(write(tmp_path, envelope(publisher), "a.json"))
        second_data = envelope(publisher)
        second_data["signature"] = "x" + (second_data["signature"] or "")[1:]
        second = load_bundle_file(write(tmp_path, second_data, "b.json"))
        assert first.bundle_hash != second.bundle_hash

    def test_not_json_says_what_the_format_is(self, tmp_path: Path) -> None:
        path = tmp_path / "nope.json"
        path.write_text("framework: dora\n", encoding="utf-8")
        with pytest.raises(BundleRejected, match="single signed JSON"):
            load_bundle_file(path)

    def test_a_missing_file_says_so(self, tmp_path: Path) -> None:
        with pytest.raises(BundleRejected, match="cannot read"):
            load_bundle_file(tmp_path / "absent.json")

    def test_the_format_constant_carries_no_version_of_qed(self) -> None:
        """ADR-0006: a format name that moved with the product version would
        make every chain and bundle look stale after a release."""
        assert BUNDLE_FORMAT == "qed-pack-bundle/1"


class TestThePublicKey:
    def test_a_non_ed25519_key_is_refused(self, tmp_path: Path) -> None:
        from cryptography.hazmat.primitives.asymmetric import rsa

        path = tmp_path / "rsa.pem"
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()
        path.write_bytes(key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))
        with pytest.raises(BundleRejected, match="Ed25519 only"):
            load_public_key(path)

    def test_garbage_is_refused(self, tmp_path: Path) -> None:
        path = tmp_path / "not-a-key.pem"
        path.write_text("hello", encoding="utf-8")
        with pytest.raises(BundleRejected, match="not a PEM public key"):
            load_public_key(path)


# --------------------------------------------------------------------------
# Installing
# --------------------------------------------------------------------------


class TestInstalling:
    def test_the_catalogue_is_written_as_yaml_like_the_shipped_ones(
        self, tmp_path: Path, publisher: Any
    ) -> None:
        """So one loader reads both, and an operator can diff them."""
        bundle = load_bundle_file(write(tmp_path, envelope(publisher)))
        written = write_installed(bundle, tmp_path / "state")
        catalogues = [item for item in written if item.suffix == ".yaml"]
        assert [item.name for item in catalogues] == ["dora.yaml"]
        text = catalogues[0].read_text(encoding="utf-8")
        assert "framework: dora" in text
        assert "Imported, not shipped" in text

    def test_the_imported_flag_is_never_in_a_file(self, tmp_path: Path, publisher: Any) -> None:
        """It comes from *where a file was read*. A bundle that could declare
        itself shipped could hide where its control titles came from."""
        bundle = load_bundle_file(write(tmp_path, envelope(publisher)))
        written = write_installed(bundle, tmp_path / "state")
        text = next(item for item in written if item.suffix == ".yaml").read_text(encoding="utf-8")
        assert "imported" not in text
        assert "imported" not in json.dumps(envelope(publisher))

    def test_an_imported_catalogue_replaces_the_shipped_one(
        self, tmp_path: Path, publisher: Any
    ) -> None:
        state = tmp_path / "state"
        write_installed(load_bundle_file(write(tmp_path, envelope(publisher))), state)
        use_imported(installed_dir(state))

        found = pack("dora")
        assert found is not None
        assert found.imported is True
        assert len(found.controls) == 4
        assert {item.framework for item in packs() if item.imported} == {"dora"}

    def test_the_other_catalogues_stay_shipped(self, tmp_path: Path, publisher: Any) -> None:
        state = tmp_path / "state"
        write_installed(load_bundle_file(write(tmp_path, envelope(publisher))), state)
        use_imported(installed_dir(state))
        eu = pack("eu_ai_act")
        assert eu is not None
        assert eu.imported is False

    def test_the_manifest_records_which_bundle(self, tmp_path: Path, publisher: Any) -> None:
        state = tmp_path / "state"
        bundle = load_bundle_file(write(tmp_path, envelope(publisher)))
        write_installed(bundle, state)
        manifest = read_installed(state)
        assert manifest is not None
        assert manifest["bundle_hash"] == bundle.bundle_hash
        assert manifest["signed"] is True
        assert manifest["installed_at"]

    def test_no_manifest_is_not_an_error(self, tmp_path: Path) -> None:
        assert read_installed(tmp_path / "empty") is None

    def test_an_unreadable_manifest_does_not_block_an_import(self, tmp_path: Path) -> None:
        """Refusing would leave an operator with no way forward but deleting
        files by hand."""
        state = tmp_path / "state"
        installed_dir(state).mkdir(parents=True)
        (installed_dir(state) / "bundle.json").write_text("{ broken", encoding="utf-8")
        assert read_installed(state) is None


class TestRollback:
    def test_an_older_bundle_is_refused(self, tmp_path: Path, publisher: Any) -> None:
        """Replaying an old bundle is how a control mapping is taken away
        without anybody noticing."""
        state = tmp_path / "state"
        new = load_bundle_file(write(tmp_path, envelope(publisher), "new.json"))
        write_installed(new, state)
        old = load_bundle_file(
            write(tmp_path, envelope(publisher, issued="2026-01-01T00:00:00+00:00"), "old.json")
        )
        with pytest.raises(BundleRejected, match="roll the catalogues back"):
            check_not_older(old, state)

    def test_the_same_issue_time_is_allowed(self, tmp_path: Path, publisher: Any) -> None:
        """A re-import of the same bundle is a repair, not a rollback."""
        state = tmp_path / "state"
        bundle = load_bundle_file(write(tmp_path, envelope(publisher)))
        write_installed(bundle, state)
        check_not_older(bundle, state)

    def test_a_first_import_has_nothing_to_compare(self, tmp_path: Path, publisher: Any) -> None:
        bundle = load_bundle_file(write(tmp_path, envelope(publisher)))
        check_not_older(bundle, tmp_path / "fresh")


# --------------------------------------------------------------------------
# The one found by running it
# --------------------------------------------------------------------------


class TestABundleThatWouldStopTheKernel:
    """An imported catalogue replaces the shipped one, so a bundle that omits a
    control an installed rule cites leaves that rule citing nothing -- which is
    a lint **error**, and the engine refuses to decide against a bundle with
    errors.

    This is not hypothetical. A three-article DORA bundle replaced the shipped
    catalogue's one article and the next `qed check` answered "the policy
    bundle has errors; refusing to decide against a broken bundle". The import
    had succeeded. The instance governed nothing.
    """

    def test_dropping_a_cited_control_is_detected(
        self, tmp_path: Path, publisher: Any, rules
    ) -> None:  # type: ignore[no-untyped-def]
        bundle = load_bundle_file(write(tmp_path, envelope(publisher, drop_shipped=True)))
        orphans = would_break(bundle, rules)
        assert orphans
        assert all(framework == "dora" for _rule, framework, _control in orphans)
        assert all(control == SHIPPED_DORA_CONTROL for _r, _f, control in orphans)

    def test_a_superset_is_fine(self, tmp_path: Path, publisher: Any, rules) -> None:  # type: ignore[no-untyped-def]
        """A deepening adds; it does not take away."""
        bundle = load_bundle_file(write(tmp_path, envelope(publisher)))
        assert would_break(bundle, rules) == []

    def test_a_framework_the_bundle_does_not_touch_is_ignored(
        self, tmp_path: Path, publisher: Any, rules
    ) -> None:  # type: ignore[no-untyped-def]
        """The bundle carries DORA only, so the 27 rules citing SOC 2 are not
        its business."""
        bundle = load_bundle_file(write(tmp_path, envelope(publisher, drop_shipped=True)))
        touched = {framework for _rule, framework, _control in would_break(bundle, rules)}
        assert touched == {"dora"}

    def test_an_alias_in_a_rule_still_matches(self, tmp_path: Path, publisher: Any) -> None:
        """A rule may write `DORA` where the bundle says `dora`; the check
        normalises, or it would miss the orphan it exists to catch."""
        bundle = load_bundle_file(write(tmp_path, envelope(publisher, drop_shipped=True)))

        class Rule:
            rule_id = "XX-001"
            compliance = (
                type("Ref", (), {"framework": "DORA", "control": SHIPPED_DORA_CONTROL})(),
            )

        assert would_break(bundle, [Rule()]) == [("XX-001", "dora", SHIPPED_DORA_CONTROL)]


# --------------------------------------------------------------------------
# The commands
# --------------------------------------------------------------------------


class TestPacksVerify:
    def test_it_shows_the_contents_without_a_key(self, tmp_path: Path, publisher: Any) -> None:
        """Whether to trust a catalogue is a decision somebody should make with
        the contents in front of them."""
        path = write(tmp_path, envelope(publisher))
        result = runner.invoke(app(), ["packs", "verify", str(path)])
        assert result.exit_code == 0, result.output
        assert "test-publisher" in result.output
        assert "dora" in result.output
        assert "not verified" in result.output

    def test_it_installs_nothing(self, tmp_path: Path, publisher: Any) -> None:
        path = write(tmp_path, envelope(publisher))
        runner.invoke(app(), ["packs", "verify", str(path)])
        assert not (tmp_path / "packs").exists()

    def test_it_verifies_with_a_key(self, tmp_path: Path, publisher: Any) -> None:
        path = write(tmp_path, envelope(publisher))
        result = runner.invoke(
            app(),
            ["packs", "verify", str(path), "--public-key", str(write_key(tmp_path, publisher))],
        )
        assert result.exit_code == 0, result.output
        assert "verifies under" in result.output

    def test_it_refuses_a_tampered_bundle(self, tmp_path: Path, publisher: Any) -> None:
        data = envelope(publisher)
        data["packs"][0]["controls"][0]["label"] = "Not what was signed"
        path = write(tmp_path, data)
        result = runner.invoke(
            app(),
            ["packs", "verify", str(path), "--public-key", str(write_key(tmp_path, publisher))],
        )
        assert result.exit_code == 1
        assert "Do not import it" in result.output

    def test_the_output_is_ascii(self, tmp_path: Path, publisher: Any) -> None:
        path = write(tmp_path, envelope(publisher))
        output = runner.invoke(app(), ["packs", "verify", str(path)]).output
        assert all(ord(char) < 127 for char in output)


class TestPacksImport:
    """The command, against a real chain.

    Every one of these runs `keys init` first and then imports, because the
    `admin_action` record is the point: a control title an auditor reads has to
    be traceable to a moment and a key, and a test that skipped the chain would
    not be testing the thing that makes an import trustworthy.
    """

    @pytest.fixture
    def state(self, tmp_path: Path) -> Path:
        directory = tmp_path / "state"
        result = runner.invoke(app(), ["keys", "init", "--dir", str(directory)])
        assert result.exit_code == 0, result.output
        return directory

    def records(self, state: Path) -> list[dict[str, Any]]:
        result = runner.invoke(app(), ["export", "--dir", str(state)])
        assert result.exit_code == 0, result.output
        return [json.loads(line) for line in result.output.splitlines() if line.strip()]

    def test_a_signed_import_is_recorded_in_the_chain(
        self, tmp_path: Path, state: Path, publisher: Any
    ) -> None:
        path = write(tmp_path, envelope(publisher))
        result = runner.invoke(
            app(),
            [
                "packs",
                "import",
                str(path),
                "--dir",
                str(state),
                "--public-key",
                str(write_key(tmp_path, publisher)),
            ],
        )
        assert result.exit_code == 0, result.output

        admin = [item for item in self.records(state) if item["type"] == "admin_action"]
        assert len(admin) == 1
        payload = admin[0]["payload"]
        assert payload["action"] == "packs_imported"
        assert payload["signed"] is True
        assert payload["unsigned"] is False
        assert payload["key_id"] == publisher[2]
        assert payload["frameworks"] == ["dora"]
        assert payload["bundle_hash"]

    def test_the_chain_still_verifies_afterwards(
        self, tmp_path: Path, state: Path, publisher: Any
    ) -> None:
        """The record is signed like any other, so this would only fail if the
        payload carried something unserialisable -- which is exactly the kind
        of thing a dict assembled from a parsed file can do."""
        from qed_verify.verify import verify_records

        from qed.infra.keys.file import PUBLIC_DIR_NAME, load_public_keys

        runner.invoke(
            app(),
            [
                "packs",
                "import",
                str(write(tmp_path, envelope(publisher))),
                "--dir",
                str(state),
                "--public-key",
                str(write_key(tmp_path, publisher)),
            ],
        )
        report = verify_records(self.records(state), load_public_keys(state / PUBLIC_DIR_NAME))
        assert report.ok, report.summary()

    def test_without_a_key_it_says_what_to_pass(
        self, tmp_path: Path, state: Path, publisher: Any
    ) -> None:
        """There is no default key: a publisher's key has to arrive by some
        route other than the bundle, or the signature checks the bundle against
        itself."""
        result = runner.invoke(
            app(),
            ["packs", "import", str(write(tmp_path, envelope(publisher))), "--dir", str(state)],
        )
        assert result.exit_code == 1
        assert "--public-key" in result.output
        assert "--unsigned" in result.output
        assert not installed_dir(state).exists()

    def test_unsigned_on_a_signed_bundle_is_refused(
        self, tmp_path: Path, state: Path, publisher: Any
    ) -> None:
        """Importing a signed bundle as unsigned throws away the one thing that
        makes its control titles traceable."""
        result = runner.invoke(
            app(),
            [
                "packs",
                "import",
                str(write(tmp_path, envelope(publisher))),
                "--dir",
                str(state),
                "--unsigned",
            ],
        )
        assert result.exit_code == 1
        assert "is signed" in result.output

    def test_an_unsigned_import_is_loud_and_recorded(
        self, tmp_path: Path, state: Path, publisher: Any
    ) -> None:
        """Allowed, because refusing outright would push people to edit the
        installed files by hand where nothing records it at all."""
        data = envelope(publisher)
        data.pop("signature")
        data.pop("key_id")
        result = runner.invoke(
            app(),
            ["packs", "import", str(write(tmp_path, data)), "--dir", str(state), "--unsigned"],
        )
        assert result.exit_code == 0, result.output
        assert "UNSIGNED" in result.output

        payload = next(
            item["payload"] for item in self.records(state) if item["type"] == "admin_action"
        )
        assert payload["unsigned"] is True
        assert payload["signed"] is False
        assert payload["key_id"] is None

    def test_a_bundle_that_would_orphan_a_rule_writes_nothing(
        self, tmp_path: Path, state: Path, publisher: Any
    ) -> None:
        """The one found by running it. An import that stops the kernel
        deciding is not an import."""
        result = runner.invoke(
            app(),
            [
                "packs",
                "import",
                str(write(tmp_path, envelope(publisher, drop_shipped=True))),
                "--dir",
                str(state),
                "--public-key",
                str(write_key(tmp_path, publisher)),
            ],
        )
        assert result.exit_code == 1
        assert "Nothing was written" in result.output
        assert SHIPPED_DORA_CONTROL in result.output
        assert not installed_dir(state).exists()
        assert [item for item in self.records(state) if item["type"] == "admin_action"] == []

    def test_the_kernel_still_decides_after_a_refused_import(
        self, tmp_path: Path, state: Path, publisher: Any
    ) -> None:
        """The point of refusing before writing: the instance is untouched."""
        runner.invoke(
            app(),
            [
                "packs",
                "import",
                str(write(tmp_path, envelope(publisher, drop_shipped=True))),
                "--dir",
                str(state),
                "--public-key",
                str(write_key(tmp_path, publisher)),
            ],
        )
        proposal = Path("examples/proposals/github-read.json").resolve()
        result = runner.invoke(app(), ["check", str(proposal), "--dir", str(state)])
        assert result.exit_code in {0, 2, 3}, result.output

    def test_an_orphaning_bundle_can_be_forced(
        self, tmp_path: Path, state: Path, publisher: Any
    ) -> None:
        """For somebody who intends to fix the rules next. It is a flag, not a
        default, and the record says it was used."""
        result = runner.invoke(
            app(),
            [
                "packs",
                "import",
                str(write(tmp_path, envelope(publisher, drop_shipped=True))),
                "--dir",
                str(state),
                "--public-key",
                str(write_key(tmp_path, publisher)),
                "--allow-orphaned-rules",
            ],
        )
        assert result.exit_code == 0, result.output
        assert installed_dir(state).exists()

    def test_a_rollback_is_refused_and_writes_nothing(
        self, tmp_path: Path, state: Path, publisher: Any
    ) -> None:
        key = str(write_key(tmp_path, publisher))
        first = write(tmp_path, envelope(publisher), "new.json")
        assert (
            runner.invoke(
                app(), ["packs", "import", str(first), "--dir", str(state), "--public-key", key]
            ).exit_code
            == 0
        )
        before = (installed_dir(state) / "dora.yaml").read_text(encoding="utf-8")

        older = write(tmp_path, envelope(publisher, issued="2026-01-01T00:00:00+00:00"), "old.json")
        result = runner.invoke(
            app(), ["packs", "import", str(older), "--dir", str(state), "--public-key", key]
        )
        assert result.exit_code == 1
        assert "roll the catalogues back" in result.output
        assert (installed_dir(state) / "dora.yaml").read_text(encoding="utf-8") == before

    def test_a_tampered_bundle_never_reaches_the_disk(
        self, tmp_path: Path, state: Path, publisher: Any
    ) -> None:
        data = envelope(publisher)
        before = data["packs"][0]["controls"][0]["label"]
        data["packs"][0]["controls"][0]["label"] = "Not what was signed"
        assert data["packs"][0]["controls"][0]["label"] != before
        result = runner.invoke(
            app(),
            [
                "packs",
                "import",
                str(write(tmp_path, data)),
                "--dir",
                str(state),
                "--public-key",
                str(write_key(tmp_path, publisher)),
            ],
        )
        assert result.exit_code == 1
        assert not installed_dir(state).exists()

    def test_packs_list_shows_the_imported_catalogue(
        self, tmp_path: Path, state: Path, publisher: Any
    ) -> None:
        runner.invoke(
            app(),
            [
                "packs",
                "import",
                str(write(tmp_path, envelope(publisher))),
                "--dir",
                str(state),
                "--public-key",
                str(write_key(tmp_path, publisher)),
            ],
        )
        report = json.loads(
            runner.invoke(app(), ["packs", "list", "--dir", str(state), "--json"]).output
        )
        dora = next(item for item in report["catalogues"] if item["framework"] == "dora")
        assert dora["controls"] == 4
        assert "Art. 5" in dora["unmapped"]

    def test_an_import_needs_a_signing_key_first(self, tmp_path: Path, publisher: Any) -> None:
        """A missing signing key has to fail *before* the catalogues land on
        disk, or the import happened and nothing recorded it."""
        bare = tmp_path / "no-keys"
        bare.mkdir()
        result = runner.invoke(
            app(),
            [
                "packs",
                "import",
                str(write(tmp_path, envelope(publisher))),
                "--dir",
                str(bare),
                "--public-key",
                str(write_key(tmp_path, publisher)),
            ],
        )
        assert result.exit_code == 1
        assert "recordable before it is allowed to happen" in result.output
        assert not installed_dir(bare).exists()


class TestPolicyLoadedCarriesTheProvenance:
    """SPEC §11: `unsigned: true` on `policy_loaded`, not only on the import.

    `policy_loaded` is the record every verdict points at. An auditor holding
    one verdict should be able to see that the control labels behind it had
    nobody vouching for them, without going looking for an `admin_action` that
    may be a year earlier in the chain.

    The subtlety, and the reason this class exists: **importing a catalogue
    does not change the policy hash**, and `policy_loaded` is appended once per
    hash. So the first version of this recorded `unsigned: false` forever after
    an unsigned import -- the reading side worked and nothing re-read it. The
    import now drops the de-duplication marks, and the next session appends a
    fresh `policy_loaded` with the same `policy_hash` and the new catalogue
    state. Two records for one hash is the honest outcome: the bundle was
    loaded twice and meant something different the second time.
    """

    @pytest.fixture
    def state(self, tmp_path: Path) -> Path:
        directory = tmp_path / "state"
        assert runner.invoke(app(), ["keys", "init", "--dir", str(directory)]).exit_code == 0
        return directory

    def loaded(self, state: Path) -> list[dict[str, Any]]:
        result = runner.invoke(app(), ["export", "--dir", str(state)])
        assert result.exit_code == 0, result.output
        return [
            json.loads(line)["payload"]
            for line in result.output.splitlines()
            if line.strip() and json.loads(line)["type"] == "policy_loaded"
        ]

    def decide(self, state: Path) -> None:
        proposal = Path("examples/proposals/github-read.json").resolve()
        result = runner.invoke(app(), ["check", str(proposal), "--dir", str(state)])
        assert result.exit_code in {0, 2, 3}, result.output

    def unsigned_bundle(self, tmp_path: Path, publisher: Any) -> Path:
        data = envelope(publisher)
        data.pop("signature")
        data.pop("key_id")
        return write(tmp_path, data, "unsigned.json")

    def test_the_ordinary_case_says_false_rather_than_nothing(
        self, state: Path, publisher: Any
    ) -> None:
        """Present either way. A field that appears only when something is
        wrong is a field an auditor cannot tell from one this build never
        wrote."""
        self.decide(state)
        records = self.loaded(state)
        assert records
        assert all(item["unsigned"] is False for item in records)
        assert all("unsigned_catalogues" not in item for item in records)

    def test_an_unsigned_import_shows_up_in_the_next_policy_loaded(
        self, tmp_path: Path, state: Path, publisher: Any
    ) -> None:
        runner.invoke(
            app(),
            [
                "packs",
                "import",
                str(self.unsigned_bundle(tmp_path, publisher)),
                "--dir",
                str(state),
                "--unsigned",
            ],
        )
        self.decide(state)

        records = self.loaded(state)
        assert len(records) >= 2, "the import did not cause a fresh policy_loaded"
        latest = records[-1]
        assert latest["unsigned"] is True
        assert latest["unsigned_catalogues"] == ["dora"]

    def test_the_earlier_record_is_left_alone(
        self, tmp_path: Path, state: Path, publisher: Any
    ) -> None:
        """Re-recording appends; it does not rewrite. The chain says the policy
        was loaded under a vouched-for catalogue and then under an unsigned
        one, which is what happened."""
        runner.invoke(
            app(),
            [
                "packs",
                "import",
                str(self.unsigned_bundle(tmp_path, publisher)),
                "--dir",
                str(state),
                "--unsigned",
            ],
        )
        self.decide(state)
        records = self.loaded(state)
        assert records[0]["unsigned"] is False
        assert records[-1]["unsigned"] is True
        assert records[0]["policy_hash"] == records[-1]["policy_hash"], (
            "the policy did not change -- only what its control references mean"
        )

    def test_a_signed_import_does_not_set_the_flag(
        self, tmp_path: Path, state: Path, publisher: Any
    ) -> None:
        runner.invoke(
            app(),
            [
                "packs",
                "import",
                str(write(tmp_path, envelope(publisher))),
                "--dir",
                str(state),
                "--public-key",
                str(write_key(tmp_path, publisher)),
            ],
        )
        self.decide(state)
        assert all(item["unsigned"] is False for item in self.loaded(state))

    def test_catalogues_with_no_manifest_count_as_unsigned(self, tmp_path: Path) -> None:
        """Somebody dropped YAML files into the directory by hand, which is
        exactly as unvouched-for as an unsigned bundle -- and is the path an
        operator takes if the import is too strict, so it must not read as
        signed."""
        from qed.compliance.packs import unsigned_catalogues

        directory = tmp_path / "packs"
        directory.mkdir()
        (directory / "dora.yaml").write_text("framework: dora" + chr(10), encoding="utf-8")
        use_imported(directory)
        assert unsigned_catalogues() == ("dora",)

    def test_provenance_comes_from_the_manifest_not_the_catalogue(
        self, tmp_path: Path, publisher: Any
    ) -> None:
        """A catalogue cannot be allowed to describe its own provenance."""
        from qed.compliance.packs import unsigned_catalogues

        state = tmp_path / "state"
        write_installed(load_bundle_file(write(tmp_path, envelope(publisher))), state)
        use_imported(installed_dir(state))
        assert unsigned_catalogues() == ()

        # Claiming to be signed inside the YAML changes nothing.
        path = installed_dir(state) / "dora.yaml"
        path.write_text(
            path.read_text(encoding="utf-8") + "signed: true" + chr(10), encoding="utf-8"
        )
        manifest = installed_dir(state) / "bundle.json"
        data = json.loads(manifest.read_text(encoding="utf-8"))
        data["signed"] = False
        manifest.write_text(json.dumps(data), encoding="utf-8")
        assert unsigned_catalogues() == ("dora",)

    def test_nothing_imported_is_not_unsigned(self) -> None:
        from qed.compliance.packs import unsigned_catalogues

        use_imported(None)
        assert unsigned_catalogues() == ()


def app():  # type: ignore[no-untyped-def]
    from qed.cli import app as cli

    return cli
