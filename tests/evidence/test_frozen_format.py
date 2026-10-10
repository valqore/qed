"""Records written under a frozen `schema_version` verify under today's code.

SPEC §25.6 promises that any change to hashing or record fields bumps
`schema_version` "with an ADR and keeps `qed-verify` able to verify all prior
versions (cross-version fixtures in CI)". For eleven weeks there were no
cross-version fixtures, so the promise was a sentence. This is the fixture, and
these are the checks.

The distinction that matters: `tests/evidence/test_chain.py` writes a chain with
today's code and verifies it with today's verifier. That passes if the producer
and the verifier change together -- which is exactly the failure a format freeze
exists to catch, because the records already in a customer's chain do not change
with them. So the input here is a committed artefact produced once, on
2026-10-10, by the code at that commit, and never regenerated
(`fixtures/generate_1_0.py` refuses without `--i-mean-it` and says why).

Four layers, each catching something the one above cannot:

1. `qed-verify` verifies the frozen export. The whole auditor claim in one line.
2. `qed.core.evidence.hashing.record_hash` -- the *producer's* function --
   recomputes the hash of every frozen record. The verifier agreeing proves the
   verifier can read 1.0; this proves the producer still writes it.
3. `qed.core.jcs` and `qed_verify.jcs` agree on every frozen payload. Two
   independent canonicalisers; a divergence between them is a record one side
   can hash and the other cannot.
4. The fixture's digest is pinned in this file, so regenerating it is a visible,
   deliberate act in two places rather than a quiet refresh that makes layers
   1--3 tautological again.

And one structural check: every `schema_version` the code can write must have a
fixture directory. That is what turns the freeze into a rule rather than a
habit -- a bump to "1.1" fails here until 1.1 has records of its own, and 1.0
goes on being verified afterwards.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

import pytest
from qed_verify import jcs as verifier_jcs
from qed_verify.verify import load_jsonl, verify_records

from qed.core import jcs as producer_jcs
from qed.core.evidence.hashing import genesis_prev_hash, record_hash
from qed.infra.keys.file import load_public_keys

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = Path(__file__).parent / "fixtures"

#: sha256 over the fixture's own files, in sorted path order, with the path
#: names mixed in. Pinned here and not inside the fixture, because a digest a
#: regeneration rewrites alongside the thing it describes checks nothing.
#:
#: If this test fails on this line and nothing else, someone re-ran
#: `generate_1_0.py`. That is almost never right: the fixture is the record of
#: what 1.0 looked like when it was frozen, and the point of it is that it was
#: *not* produced by the code under test. A genuinely new format version gets a
#: new directory and a new entry below.
DIGESTS = {
    "evidence-format-1.0": "ad532b46a7e4fcbee03b96940147ca13ef541ad49648a9ae210cb9a3ad73a2fb",
}


def fixture_dirs() -> list[Path]:
    return sorted(path for path in FIXTURES.glob("evidence-format-*") if path.is_dir())


def fixture_ids() -> list[str]:
    return [path.name for path in fixture_dirs()]


def digest_of(directory: Path) -> str:
    """One digest over the fixture's evidence, path names included.

    Names are hashed as well as contents: a public key renamed to a `key_id` it
    does not belong to would otherwise pass, and the verifier looks keys up by
    the id inside the PEM rather than by filename, so nothing else would notice.

    Markdown is excluded. The pin exists to stop the *records* being refreshed,
    and covering the README as well would mean every improvement to the prose
    looked identical to a regenerated chain -- which is how a guard stops being
    read and starts being updated reflexively.
    """
    accumulator = hashlib.sha256()
    for path in sorted(directory.rglob("*")):
        if not path.is_file() or path.suffix == ".md":
            continue
        accumulator.update(path.relative_to(directory).as_posix().encode())
        accumulator.update(b"\x00")
        accumulator.update(path.read_bytes())
        accumulator.update(b"\x00")
    return accumulator.hexdigest()


def load(directory: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    records = load_jsonl((directory / "chain.jsonl").read_text(encoding="utf-8"))
    manifest = json.loads((directory / "manifest.json").read_text(encoding="utf-8"))
    return records, manifest


@pytest.fixture(params=fixture_dirs(), ids=fixture_ids())
def frozen(request: pytest.FixtureRequest) -> tuple[Path, list[dict[str, Any]], dict[str, Any]]:
    directory = request.param
    records, manifest = load(directory)
    return directory, records, manifest


class TestTheFixtureIsIntact:
    def test_there_is_at_least_one(self) -> None:
        """A parametrised suite with an empty parameter list passes silently.

        The same vacuous pass as the packaging guard written in `fnmatch`
        (`docs/validation.md`): zero cases, zero failures, green.
        """
        assert fixture_dirs(), f"no frozen fixtures found under {FIXTURES}"

    @pytest.mark.parametrize("name", fixture_ids())
    def test_it_has_not_been_regenerated(self, name: str) -> None:
        """The pin. See `DIGESTS` for why a failure here is rarely a fix."""
        assert name in DIGESTS, f"{name} has no pinned digest in DIGESTS"
        assert digest_of(FIXTURES / name) == DIGESTS[name], (
            f"{name} differs from the frozen fixture. If this is a regeneration, it "
            "should not be: these records are the evidence that a chain written "
            "before today's code still verifies, and re-running the generator "
            "replaces them with records today's code produced. A new format "
            "version gets a new directory."
        )

    def test_every_pinned_digest_has_a_fixture(self) -> None:
        """A digest for a directory that was deleted hides the deletion."""
        assert set(DIGESTS) == set(fixture_ids())

    @pytest.mark.parametrize("name", fixture_ids())
    def test_no_fixture_file_carries_a_carriage_return(self, name: str) -> None:
        """LF only, because the digest is over bytes.

        The generator's first run used `Path.write_text`, which on Windows
        translates `\\n` to `\\r\\n`. That produced a fixture whose pinned digest
        matched on the machine that made it and on no other: `.gitattributes`
        checks the repository out as LF, so CI would have failed the pin and the
        failure would have read as a format regression rather than as a line
        ending.

        Asserted on the bytes rather than trusted to `.gitattributes`, because
        the thing being checked is what the hash sees -- which is also why the
        scope is `digest_of`'s, Markdown excluded.
        """
        for path in sorted((FIXTURES / name).rglob("*")):
            if path.is_file() and path.suffix != ".md":
                assert b"\r" not in path.read_bytes(), (
                    f"{name}/{path.name} contains CR; the digest in DIGESTS would "
                    "only match on a machine with the same line endings"
                )

    def test_every_fixture_file_is_tracked_by_git(self) -> None:
        """A fixture file present locally and absent from the repository.

        This is not hypothetical. `.gitignore` carries `*.pem` under "never
        commit keys or chains", which is right for a private key and matched
        the fixture's **public** ones -- so the first commit of this directory
        would have shipped a chain with no keys to verify it against. Locally
        everything passed, because the files were on disk.

        The symptom in CI would have been `unknown_key` on a frozen fixture,
        which reads exactly like a format regression. It is the same shape as
        the wheel that shipped without `compliance/packs/*.yaml`
        (`docs/validation.md`), and the guard is the same: ask the thing that
        actually decides.
        """
        import subprocess

        def git(*args: str) -> subprocess.CompletedProcess[str]:
            return subprocess.run(
                ["git", *args], capture_output=True, text=True, check=False, cwd=ROOT
            )

        # Whether this is a checkout is established separately from the
        # listing, because `git ls-files` on an untracked path exits 0 with no
        # output -- so a returncode check would read "nothing is tracked" as
        # "there is no git here" and skip in exactly the case it exists for.
        if git("rev-parse", "--git-dir").returncode != 0:  # pragma: no cover - no git
            pytest.skip("not a git checkout")

        for directory in fixture_dirs():
            result = git("ls-files", "--", str(directory))
            assert result.returncode == 0, result.stderr
            tracked = {Path(line).name for line in result.stdout.splitlines() if line.strip()}
            on_disk = {path.name for path in directory.rglob("*") if path.is_file()}
            missing = sorted(on_disk - tracked)
            assert not missing, (
                f"{directory.name} has files on disk that git is not tracking: "
                f"{missing}. Check `.gitignore` -- `*.pem` matches a public key "
                "just as readily as a private one."
            )


class TestTheIndependentVerifierStillReadsIt:
    def test_the_frozen_chain_verifies(
        self, frozen: tuple[Path, list[dict[str, Any]], dict[str, Any]]
    ) -> None:
        """`qed-verify` on a committed export and committed public keys.

        Nothing in this test touches the producer. It is the auditor's whole
        position: a file, a key, and a verifier that shares no code with
        whatever wrote the file.
        """
        directory, records, manifest = frozen
        report = verify_records(
            records,
            load_public_keys(directory / "public"),
            instance_id=manifest["instance_id"],
        )
        assert report.ok, report.summary()
        assert report.records == manifest["records"]
        assert report.purged == len(manifest["purged_seqs"])

    def test_the_facts_the_manifest_states_are_the_facts_in_the_file(
        self, frozen: tuple[Path, list[dict[str, Any]], dict[str, Any]]
    ) -> None:
        """The manifest is a reader's index, so it must not drift from the chain."""
        _, records, manifest = frozen
        assert len(records) == manifest["records"]
        assert records[-1]["seq"] == manifest["head_seq"]
        assert records[-1]["hash"] == manifest["head_hash"]
        assert sorted({record["type"] for record in records}) == manifest["types"]
        assert [r["seq"] for r in records if r.get("payload") is None] == manifest["purged_seqs"]

    def test_the_genesis_binding_is_to_the_stated_instance(
        self, frozen: tuple[Path, list[dict[str, Any]], dict[str, Any]]
    ) -> None:
        """Computed with the *producer's* function against the frozen bytes.

        `verify_records` already checks this with its own copy of the domain
        string; this is the other side of the same equality, and it is the one
        that fails if `GENESIS_DOMAIN` is ever edited in `qed`.
        """
        _, records, manifest = frozen
        assert records[0]["prev_hash"] == genesis_prev_hash(manifest["instance_id"])

    def test_a_purged_payload_still_verifies(
        self, frozen: tuple[Path, list[dict[str, Any]], dict[str, Any]]
    ) -> None:
        """The property the whole retention design rests on, on frozen bytes.

        The fixture was built with one five-day-old proposal and a two-day
        retention on `proposal` exactly so this assertion has something to
        stand on. Without a purged record in it, the fixture would be silent
        about the one record type an auditor is most likely to meet years
        later.
        """
        _, _, manifest = frozen
        assert manifest["purged_seqs"], "the fixture has no purged record; it should"


class TestTheProducerStillWritesIt:
    def test_record_hash_agrees_with_every_frozen_record(
        self, frozen: tuple[Path, list[dict[str, Any]], dict[str, Any]]
    ) -> None:
        """The cross-version check SPEC §25.6 asks for, in one assertion.

        `record_hash` is the function the kernel uses *today*. The hashes it is
        compared against were written by the kernel as it was on 2026-10-10. A
        change to the hash input -- a new field, a different separator, a
        different timestamp spelling -- fails here, which is the signal to bump
        `schema_version` and write an ADR rather than to edit the fixture.
        """
        _, records, manifest = frozen
        for record in records:
            recomputed = record_hash(
                schema_version=record["schema_version"],
                seq=record["seq"],
                ts=record["ts"],
                type_=record["type"],
                payload_hash_hex=record["payload_hash"],
                prev_hash=record["prev_hash"],
            )
            assert recomputed == record["hash"], (
                f"{manifest['schema_version']} record {record['seq']} "
                f"({record['type']}) hashes differently under today's "
                "`record_hash`. This is a format change: bump `schema_version`, "
                "write an ADR, and add a fixture for the new version."
            )

    def test_both_canonicalisers_agree_on_every_frozen_payload(
        self, frozen: tuple[Path, list[dict[str, Any]], dict[str, Any]]
    ) -> None:
        """Producer JCS and verifier JCS, over payloads neither has seen.

        The two are separate implementations on purpose, so that a bug in the
        producer's canonicalisation does not verify cleanly. That only helps
        while they agree on real input, and real input is what this is.
        """
        _, records, _ = frozen
        for record in records:
            payload = record.get("payload")
            if payload is None:
                continue
            assert producer_jcs.dumps(payload) == verifier_jcs.dumps(payload), (
                f"record {record['seq']} canonicalises differently in the producer and the verifier"
            )
            assert producer_jcs.sha256_hex(payload) == record["payload_hash"]


class TestTheFrozenChainIsTamperEvident:
    """The conformance table in the fixture's README, applied to the fixture.

    `test_chain.py` already tampers with a chain it wrote a moment earlier.
    These run against the committed bytes, which is what a second implementation
    will be pointed at -- and it makes the README a tested document rather than
    a list of claims about one. The row numbers match the table there.
    """

    @pytest.fixture
    def kit(self) -> tuple[list[dict[str, Any]], dict[str, Any], str]:
        directory = FIXTURES / "evidence-format-1.0"
        records, manifest = load(directory)
        return records, load_public_keys(directory / "public"), manifest["instance_id"]

    def codes(self, records: list[dict[str, Any]], keys: Any, instance: str | None) -> set[str]:
        report = verify_records(records, keys, instance_id=instance)
        return {problem.code for problem in report.problems}

    def test_1_an_edited_payload(self, kit: Any) -> None:
        records, keys, instance = kit
        records[3]["payload"]["verdict"]["decision"] = "ALLOW_EVERYTHING"
        assert "payload_tampered" in self.codes(records, keys, instance)

    def test_2_a_deleted_record(self, kit: Any) -> None:
        records, keys, instance = kit
        del records[7]
        assert "sequence_gap" in self.codes(records, keys, instance)

    def test_3_two_records_swapped(self, kit: Any) -> None:
        records, keys, instance = kit
        records[5], records[6] = records[6], records[5]
        assert self.codes(records, keys, instance) & {"broken_link", "sequence_gap"}

    def test_4_an_edited_prev_hash(self, kit: Any) -> None:
        records, keys, instance = kit
        records[9]["prev_hash"] = "0" * 64
        assert "broken_link" in self.codes(records, keys, instance)

    def test_5_an_edited_timestamp(self, kit: Any) -> None:
        """A backdated record. The `ts` is a hash input precisely for this."""
        records, keys, instance = kit
        records[4]["ts"] = "2026-01-01T00:00:00.000Z"
        assert "hash_mismatch" in self.codes(records, keys, instance)

    def test_6_a_signature_from_another_record(self, kit: Any) -> None:
        records, keys, instance = kit
        records[3]["sig"] = records[4]["sig"]
        assert "bad_signature" in self.codes(records, keys, instance)

    def test_7_genesis_removed(self, kit: Any) -> None:
        records, keys, instance = kit
        assert "not_from_genesis" in self.codes(records[1:], keys, instance)

    def test_8_a_different_instance_id(self, kit: Any) -> None:
        records, keys, _ = kit
        assert "genesis_mismatch" in self.codes(records, keys, "someone-elses-instance")

    def test_9_a_withheld_public_key(self, kit: Any) -> None:
        """The row that matters most: an unvouchable record must fail, not skip.

        The chain rotates at seq 10, so holding back the second key leaves
        three records signed by a key the verifier was never given. A verifier
        that treats that as "nothing to check here" reports a forged chain as
        clean.
        """
        records, keys, instance = kit
        head_key = records[-1]["key_id"]
        partial = {key_id: key for key_id, key in keys.items() if key_id != head_key}
        assert partial, "the fixture should have more than one key"
        assert "unknown_key" in self.codes(records, partial, instance)

    def test_10_an_edited_merkle_root(self, kit: Any) -> None:
        records, keys, instance = kit
        checkpoints = [r for r in records if r["type"] == "checkpoint"]
        assert checkpoints, "the fixture should contain checkpoints"
        checkpoints[0]["payload"]["merkle_root"] = "0" * 64
        codes = self.codes(records, keys, instance)
        # `payload_tampered` too: editing the payload also breaks its digest,
        # which is the right answer and not the one being asserted.
        assert "checkpoint_mismatch" in codes

    def test_12_an_empty_export(self, kit: Any) -> None:
        """Reported as a failure. An auditor handed nothing has verified nothing."""
        _, keys, instance = kit
        assert "empty" in self.codes([], keys, instance)

    def test_the_readme_table_matches_these_tests(self) -> None:
        """The document and the tests do not get to drift.

        Row 11 is deliberately absent from this class -- re-signing needs a
        private key the fixture does not ship -- and the README says where it
        lives instead. Every other row must have a test here.
        """
        readme = (FIXTURES / "evidence-format-1.0" / "README.md").read_text(encoding="utf-8")
        # Scoped to rows ending in a backticked code, so the "what is in it"
        # table above -- whose first column is also a number -- is not read as
        # a list of mutations. Written without the scope, this test demanded
        # tests for `seq` 0 and 13.
        rows = dict(re.findall(r"^\|\s*(\d+)\s*\|[^|]*\|\s*`([a-z_]+)`\s*\|", readme, re.MULTILINE))
        assert rows, "the README's mutation table has no numbered rows"
        tested = {name.split("_")[1] for name in dir(self) if re.match(r"test_\d", name)}
        missing = sorted(set(rows) - tested - {"11"}, key=int)
        assert not missing, f"the README lists mutations with no test: rows {missing}"

        # And every code it promises is one the verifier can actually emit. A
        # table naming a code that no longer exists would send a second
        # implementation looking for a string nothing produces.
        verifier = (ROOT / "packages" / "qed-verify" / "qed_verify" / "verify.py").read_text(
            encoding="utf-8"
        )
        unknown = sorted(code for code in rows.values() if f'"{code}"' not in verifier)
        assert not unknown, f"the README promises codes the verifier never reports: {unknown}"


class TestTheFreezeIsARule:
    def test_every_schema_version_the_code_can_write_has_a_fixture(self) -> None:
        """A `schema_version` bump without a fixture fails here.

        This is the mechanism, and it is the reason this file is worth more than
        the fixture it loads. `schema_version` is a `Literal` in three places in
        `qed/core/schemas.py`; a bump is one edit, and without this test the
        promise to verify every prior version would survive it untouched.
        """
        source = (ROOT / "qed" / "core" / "schemas.py").read_text(encoding="utf-8")
        declared = set(re.findall(r'schema_version:\s*Literal\["([^"]+)"\]', source))
        assert declared, "no `schema_version: Literal[...]` found; has schemas.py moved?"
        covered = {name.removeprefix("evidence-format-") for name in fixture_ids()}
        missing = sorted(declared - covered)
        assert not missing, (
            f"schema_version {missing} can be written and has no frozen fixture. "
            "SPEC §25.6: a format version is only frozen once there are records "
            "in it that a later verifier is tested against. Run "
            "`tests/evidence/fixtures/generate_1_0.py --out "
            "tests/evidence/fixtures/evidence-format-<version>` and pin its digest."
        )

    def test_the_documented_format_is_not_marked_draft(self) -> None:
        """`docs/evidence-format.md` was "draft until week 12 freezes it".

        Week 12 froze it. A document still saying draft, next to a fixture
        asserting permanence, is the kind of disagreement a reader resolves in
        the wrong direction.
        """
        text = (ROOT / "docs" / "evidence-format.md").read_text(encoding="utf-8")
        heading = text.splitlines()[0]
        assert "draft" not in heading.lower(), heading
        assert "Frozen" in text, "the document should say what freezing commits to"
