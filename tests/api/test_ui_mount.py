"""Finding and mounting the separate UI package (SPEC §19, §20.4, ADR-0007).

The assertion that matters is the first one. SPEC §20.4 licenses the kernel
Apache-2.0 and the UI AGPL-3.0, in a separate wheel, so that a third party
cannot offer a hosted QED-as-a-service without releasing their changes while a
customer running it internally is unaffected. A single HTML file committed to
this repository would quietly undo that, and the scan below is what notices.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from qed.api.ui import UI_PACKAGE, UiUnavailable, install_hint, mount_ui, ui_assets

ROOT = Path(__file__).resolve().parents[2]


class TestTheApacheWheelHasNoUi:
    """SPEC §20.4's licence separation, as a test rather than a promise."""

    def test_the_kernel_ships_no_html(self) -> None:
        found = [path.relative_to(ROOT) for path in (ROOT / "qed").rglob("*.html")]
        assert not found, (
            f"{found} is inside the Apache-2.0 wheel. The web pages are AGPL-3.0 and "
            "belong in the separate qed-ui package (SPEC 20.4); a page in here makes "
            "this wheel either AGPL or the pages Apache, and both answers are wrong."
        )

    @pytest.mark.parametrize("suffix", [".css", ".js", ".jsx", ".ts", ".tsx", ".svelte", ".vue"])
    def test_the_kernel_ships_no_frontend_assets(self, suffix: str) -> None:
        found = [path.relative_to(ROOT) for path in (ROOT / "qed").rglob(f"*{suffix}")]
        assert not found, f"{found} belongs in qed-ui, not in the kernel wheel"

    def test_the_mount_module_imports_nothing_from_the_ui(self) -> None:
        """It knows how to *find* the package and nothing about what is in it,
        so the UI can be rebuilt or rewritten without touching the kernel."""
        import ast

        source = (ROOT / "qed" / "api" / "ui.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        imported = {
            node.module.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module
        } | {
            alias.name.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        assert UI_PACKAGE not in imported


class TestWhenItIsNotInstalled:
    def test_the_assets_lookup_says_what_to_install(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Absence is simulated rather than assumed.

        The first version of this test just called `ui_assets()` and expected
        it to fail, which held in CI and stopped holding the moment somebody
        installed the extra on a dev box to look at the pages. A test whose
        result depends on what happens to be in the environment is not testing
        the code.
        """
        monkeypatch.setattr("qed.api.ui.find_spec", lambda name: None)
        with pytest.raises(UiUnavailable, match="not installed"):
            ui_assets()

    def test_the_hint_names_the_extra_and_the_reason(self) -> None:
        hint = install_hint()
        assert "valqore-qed[ui]" in hint
        assert "AGPL-3.0" in hint
        assert "The API runs without it" in hint

    def test_the_hint_is_ascii(self) -> None:
        """It is printed to a terminal, and a section sign arrives as a
        replacement character on a Windows console."""
        assert install_hint().isascii()

    def test_the_api_still_serves_without_it(self, client: TestClient) -> None:
        assert client.get("/healthz").status_code == 200


class TestWhenItIsInstalled:
    """A stand-in package, built in a tmp dir and put on `sys.path`.

    Faking the distribution rather than the directory, because what is under
    test is the contract between the two wheels: one function, `assets()`,
    returning a directory with an index.html in it.
    """

    def install(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, **files: str) -> Path:
        site = tmp_path / "site"
        package = site / UI_PACKAGE
        package.mkdir(parents=True)
        static = package / "static"
        static.mkdir()
        for name, content in files.items():
            (static / name.replace("__", ".")).write_text(content, encoding="utf-8")
        (package / "__init__.py").write_text(
            "from pathlib import Path\n\n\ndef assets():\n"
            "    return Path(__file__).parent / 'static'\n",
            encoding="utf-8",
        )
        monkeypatch.syspath_prepend(str(site))
        monkeypatch.delitem(sys.modules, UI_PACKAGE, raising=False)
        from importlib import invalidate_caches

        invalidate_caches()
        return static

    def test_the_pages_are_served_under_ui(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self.install(tmp_path, monkeypatch, index__html="<h1>approvals</h1>")
        app = FastAPI()
        mount_ui(app)
        with TestClient(app) as client:
            response = client.get("/ui/")
        assert response.status_code == 200
        assert "approvals" in response.text

    def test_a_deep_path_reaches_the_single_page(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """`/ui/approvals` is the URL SPEC §12.2 and §19 both write, and it has
        to reach the app rather than a 404 from the static handler."""
        self.install(tmp_path, monkeypatch, index__html="<h1>approvals</h1>")
        app = FastAPI()
        mount_ui(app)
        with TestClient(app) as client:
            assert client.get("/ui/index.html").status_code == 200

    def test_a_package_without_assets_is_a_broken_wheel(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Different words from "not installed": one the operator can fix by
        installing, the other by upgrading."""
        site = tmp_path / "site"
        package = site / UI_PACKAGE
        package.mkdir(parents=True)
        (package / "__init__.py").write_text("", encoding="utf-8")
        monkeypatch.syspath_prepend(str(site))
        monkeypatch.delitem(sys.modules, UI_PACKAGE, raising=False)
        from importlib import invalidate_caches

        invalidate_caches()
        with pytest.raises(UiUnavailable, match="exposes no `assets"):
            ui_assets()

    def test_a_directory_without_an_index_is_incomplete(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self.install(tmp_path, monkeypatch, other__txt="nothing useful")
        with pytest.raises(UiUnavailable, match=r"no index\.html"):
            ui_assets()
