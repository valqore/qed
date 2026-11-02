"""One version, in every place that states one (SPEC §25.6).

This exists because they drifted. Before `qed/version.py` there were eight
literals and four distinct answers: `pyproject.toml` said `0.1.0`,
`qed/__init__.py` said `0.1.0.dev1`, the Dockerfile label and
`docs/deployment.md` said `0.5.0`, the Helm chart's `appVersion` said `0.5.0`
while its own `version` said `0.1.0`.

The one that mattered most was `ENGINE_VERSION`, which goes into **every
verdict record** and still said `0.1.0` after seven weeks. An auditor reading a
verdict and asking which engine decided it would get an answer wrong by six
releases, and the record is immutable — there is nothing to correct afterwards.

Python imports the constant. The four places that cannot — `pyproject.toml`,
the chart, the Dockerfile label, the docs — are checked here, and the release
workflow refuses a tag that disagrees with any of them.
"""

from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path
from typing import Any, ClassVar

import pytest
import yaml

import qed
from qed.api.app import API_VERSION
from qed.core.schemas import ENGINE_VERSION, SCHEMA_VERSION
from qed.version import VERSION

ROOT = Path(__file__).resolve().parents[1]


def pyproject(path: Path) -> dict[str, object]:
    with path.open("rb") as handle:
        return tomllib.load(handle)


class TestPython:
    def test_the_package_version(self) -> None:
        assert qed.__version__ == VERSION

    def test_the_engine_version_in_every_verdict(self) -> None:
        """The one an auditor reads off a record. Immutable once written, so a
        stale literal here is a wrong answer nothing can correct."""
        assert ENGINE_VERSION == VERSION

    def test_the_openapi_document_version(self) -> None:
        assert API_VERSION == VERSION

    def test_the_verifier(self) -> None:
        """`qed-verify` ships from this tag, and "I verified with qed-verify
        0.6.0" is the sentence an auditor writes down."""
        import qed_verify

        assert qed_verify.__version__ == VERSION

    @pytest.mark.parametrize(
        "module",
        [
            "qed.adapters.mcp.proxy",
            "qed.adapters.http_proxy.proxy",
            "qed.adapters.hooks.claude_code",
        ],
    )
    def test_every_adapter_names_this_build(self, module: str) -> None:
        """`context.adapter` goes into the proposal. An adapter claiming
        `mcp-proxy/0.1.0` from a 0.6.0 build makes the field useless for
        working out which build produced a record."""
        import importlib

        name = importlib.import_module(module).ADAPTER_NAME
        assert name.endswith(f"/{VERSION}"), name


class TestTheFilesThatCannotImportIt:
    def test_pyproject(self) -> None:
        assert pyproject(ROOT / "pyproject.toml")["project"]["version"] == VERSION  # type: ignore[index]

    def test_the_verifiers_pyproject(self) -> None:
        config = pyproject(ROOT / "packages" / "qed-verify" / "pyproject.toml")
        assert config["project"]["version"] == VERSION  # type: ignore[index]

    def test_the_helm_chart_app_version(self) -> None:
        """`appVersion` is the image tag the chart installs by default. Stale,
        it points at an image that does not exist, and the failure is a
        `ImagePullBackOff` nobody connects to a version string."""
        chart = yaml.safe_load((ROOT / "deploy" / "helm" / "qed" / "Chart.yaml").read_text())
        assert chart["appVersion"] == VERSION

    def test_the_chart_version_too(self) -> None:
        """The chart's own version. It may legitimately move on its own — a
        template fix with no app change — but it must never be *behind*, and
        keeping them equal is simpler than a rule about when they may differ.
        """
        chart = yaml.safe_load((ROOT / "deploy" / "helm" / "qed" / "Chart.yaml").read_text())
        assert chart["version"] == VERSION

    def test_the_dockerfile_label(self) -> None:
        """`org.opencontainers.image.version` is what `docker inspect` reports
        and what a scanner indexes."""
        text = (ROOT / "deploy" / "Dockerfile").read_text(encoding="utf-8")
        assert f'org.opencontainers.image.version="{VERSION}"' in text

    #: Every page that tells a reader what to `docker run`. The four under
    #: `docs/` were the whole list until 1.1.0, and the two most-read pages in
    #: the project were not on it: `README.md`, which is the first screen of the
    #: repository *and* the body of the PyPI page, and the landing page, whose
    #: install transcript is the one a reader copies. Both named `qed:1.0.0`
    #: with nothing checking them -- the same shape as finding #58, a fix
    #: applied to one of the two places that needed it.
    PAGES_NAMING_AN_IMAGE_TAG = (
        "docs/deployment.md",
        "docs/checkpoints.md",
        "docs/ci.md",
        "docs/siem.md",
        "README.md",
        "landing/index.html",
    )

    #: `docs/validation.md` is deliberately absent. It is a table of what pages
    #: said on given dates, so it names `qed:1.0.0` correctly and forever: a
    #: history a version bump rewrites has stopped being a history.
    EXEMPT = ("docs/validation.md",)

    @pytest.mark.parametrize("relative", PAGES_NAMING_AN_IMAGE_TAG)
    def test_no_stale_image_tag_on_a_page_that_tells_a_reader_to_run_one(
        self, relative: str
    ) -> None:
        """A tag that was never published is a first five minutes that fails."""
        path = ROOT / relative
        if not path.exists():
            pytest.skip(f"{relative} does not exist")
        for tag in re.findall(
            r"ghcr\.io/valqore/qed:([0-9][^\s`<]*)", path.read_text(encoding="utf-8")
        ):
            assert tag == VERSION, f"{relative} names qed:{tag}, this is {VERSION}"

    def test_no_stale_version_pin_on_any_page(self) -> None:
        """`pip install valqore-qed==X` tells a reader which version to pin.

        `docs/ci.md` says to pin it, for a good reason -- a gate that silently
        changes which rules it enforces between two deploys is not a gate -- and
        that makes the pinned number a thing a reader copies into their own
        workflow. Unlike the image tag, nothing was checking it, so the example
        pinned 1.0.0 while this file said 1.1.0.

        No exempt list here. A page recording what another page used to say
        quotes `pip install valqore-qed` without a pin, so every pin in the tree
        is a live instruction.
        """
        stale = []
        for pattern in ("*.md", "*.html", "*.yml", "*.yaml"):
            for path in ROOT.rglob(pattern):
                relative = path.relative_to(ROOT).as_posix()
                if relative.startswith(("site/", ".venv/", "node_modules/")):
                    continue
                if relative == "CHANGELOG.md":
                    continue
                for pin in re.findall(
                    r"valqore-qed==([0-9][^\s`'\"]*)", path.read_text(encoding="utf-8")
                ):
                    if pin != VERSION:
                        stale.append(f"{relative} pins {pin}")
        assert not stale, f"these pages pin a version that is not {VERSION}: {stale}"

    def test_the_list_of_pages_is_not_missing_one(self) -> None:
        """The guard above checks a list, and the list is the failure surface.

        So the list is checked against the filesystem: any tracked page naming
        an image tag must be on it, or deliberately exempt. Adding a page that
        tells a reader to `docker run` something is then a decision about this
        list rather than a silent omission.
        """
        found = set()
        for pattern in ("*.md", "*.html"):
            for path in ROOT.rglob(pattern):
                relative = path.relative_to(ROOT).as_posix()
                if relative.startswith(("site/", ".venv/", "node_modules/")):
                    continue
                if relative == "CHANGELOG.md":
                    # Release notes are a record of what each version shipped.
                    continue
                if "ghcr.io/valqore/qed:" in path.read_text(encoding="utf-8"):
                    found.add(relative)
        known = set(self.PAGES_NAMING_AN_IMAGE_TAG) | set(self.EXEMPT)
        assert not (found - known), (
            f"these pages name a qed image tag and nothing checks it: {sorted(found - known)}. "
            "Add each to PAGES_NAMING_AN_IMAGE_TAG, or to EXEMPT with a reason."
        )


class TestWhatIsDeliberatelyIndependent:
    def test_the_record_schema_version_is_not_the_package_version(self) -> None:
        """SPEC §25.6. `schema_version` changes only when the record format
        does, and `qed-verify` has to verify every version ever written -- so
        tying it to the release would make every release a format change.
        """
        assert SCHEMA_VERSION == "1.0"
        assert SCHEMA_VERSION != VERSION

    def test_the_api_path_is_versioned_by_being_a_path(self) -> None:
        """`/v1` is the contract; `API_VERSION` is the document describing it.
        A 0.7.0 release does not make it `/v2`."""
        from qed.api.routers import proposals

        assert proposals.router.prefix == "/v1"


class TestTheVersionItself:
    def test_it_is_a_release_version(self) -> None:
        """No `.dev`, `.rc` or local segment. The tag, the wheel and the image
        tag are all this string, and a PEP 440 suffix in an OCI tag is a
        different kind of problem."""
        assert re.fullmatch(r"\d+\.\d+\.\d+", VERSION), VERSION

    def test_it_is_a_valid_oci_tag(self) -> None:
        assert re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9._-]{0,127}", VERSION)


class TestTheNpmStubIsNotAVersionedThing:
    """The one published artifact that must **not** track `qed/version.py`.

    Every other test in this file exists because a version literal lives
    somewhere that cannot import `VERSION`. This class is the opposite case
    and belongs beside them so nobody later "fixes" the inconsistency: npm's
    `valqore-qed` is a **name reservation**, not a release, and a stub
    advertising the real version number would read as a usable JavaScript
    client that happens to be empty. QED is a Python program and a JS client
    has never existed.

    `deploy/npm/` is the source of what gets published, for the same reason
    `.github/environments/pypi.json` is a file: a published artifact nobody
    can review is a claim nobody can check. Publishing it needs the account's
    hardware 2FA and npm's staged-publish flow, so the file is where the
    change is made and the publish is a separate, human step.
    """

    PACKAGE: ClassVar[Path] = ROOT / "deploy" / "npm" / "package.json"

    def manifest(self) -> dict[str, Any]:
        loaded = json.loads(self.PACKAGE.read_text(encoding="utf-8"))
        assert isinstance(loaded, dict)
        return loaded

    def test_the_stub_stays_at_0_0_0(self) -> None:
        assert self.manifest()["version"] == "0.0.0", (
            "the npm stub is a name reservation; a real version number there "
            "advertises a JavaScript client that does not exist"
        )

    def test_it_does_not_accidentally_track_the_kernel(self) -> None:
        assert self.manifest()["version"] != VERSION

    def test_the_description_says_it_installs_nothing(self) -> None:
        """The sentence a reader sees on npmjs.com before they install.

        `README.md` makes the same promise and `tests/docs/test_claims.py`
        guards it there; this guards the half that is published rather than
        written.
        """
        assert "installs nothing" in self.manifest()["description"].lower()

    def test_it_points_back_at_the_repository(self) -> None:
        """What was missing, and the reason this file exists at all.

        The published 0.0.0 carries a homepage and **no** `repository`, so the
        npm page offers a reader no way to reach the source. Same shape as the
        blank PyPI pages: a surface the repository never reached, so nothing
        here could see it was thin.
        """
        manifest = self.manifest()
        assert manifest["repository"]["url"].endswith("github.com/valqore/qed.git")
        assert "github.com/valqore/qed" in manifest["bugs"]["url"]

    def test_it_declares_no_entry_point(self) -> None:
        """A stub with a `bin` or a `main` is a stub somebody can run."""
        manifest = self.manifest()
        assert "bin" not in manifest
        assert "main" not in manifest

    def test_the_readme_sends_the_reader_somewhere_real(self) -> None:
        readme = (ROOT / "deploy" / "npm" / "README.md").read_text(encoding="utf-8")
        assert "installs nothing" in readme.lower()
        assert "pip install valqore-qed" in readme, "the stub should name the thing that does work"
        assert "github.com/valqore/qed" in readme
