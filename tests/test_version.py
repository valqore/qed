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

import re
import tomllib
from pathlib import Path

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

    def test_no_stale_image_tag_in_the_docs(self) -> None:
        """`docs/deployment.md` tells an operator what to `docker run`. A tag
        that was never published is a first five minutes that fails."""
        for name in ("deployment.md", "checkpoints.md", "ci.md", "siem.md"):
            path = ROOT / "docs" / name
            if not path.exists():
                continue
            for tag in re.findall(
                r"ghcr\.io/valqore/qed:([0-9][^\s`]*)", path.read_text(encoding="utf-8")
            ):
                assert tag == VERSION, f"{name} names qed:{tag}, this is {VERSION}"


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
