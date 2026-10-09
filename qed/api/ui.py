"""Mounting the separate UI package (SPEC §19, §20.4).

**This wheel contains no UI code, and this module is the reason that stays
true.** SPEC §20.4 licenses the kernel Apache-2.0 and the UI AGPL-3.0, in a
separate repository and a separate wheel, so that a third party cannot offer a
hosted QED-as-a-service without releasing their changes while a customer
running it internally is unaffected. A single HTML file checked in here would
quietly undo that: the Apache wheel would then contain AGPL work, or the UI
would be Apache-licensed, and either answer is the wrong one.

So this module knows how to *find* the UI and nothing about what is in it. It
imports ``qed_ui`` if it is installed, asks it for a directory of static files,
and mounts it. If the package is absent the API runs exactly as before and
``qed serve --ui`` says what to install.

Why a package and not a path
----------------------------

``--ui /some/directory`` would have been less code and would also mean the
server happily serves whatever is in that directory. Resolving through an
installed distribution means the assets came from a wheel somebody chose to
install, with a version and a licence, which is the same reasoning that puts
policy packs inside the distribution rather than behind a path flag.
"""

from __future__ import annotations

import logging
from importlib import import_module
from importlib.util import find_spec
from pathlib import Path
from typing import Final

__all__ = ["UI_PACKAGE", "UiUnavailable", "install_hint", "mount_ui", "ui_assets"]

logger = logging.getLogger("qed.api.ui")

#: The distribution is ``qed-ui``; the import name has the underscore.
UI_PACKAGE: Final = "qed_ui"

#: Where the UI is served. SPEC §12.2 and §19 both write it as `/ui/approvals`,
#: so the mount is at `/ui` and the page routes below it.
UI_MOUNT: Final = "/ui"


class UiUnavailable(RuntimeError):
    """The UI package is not installed, or is installed and has no assets."""


def install_hint() -> str:
    return (
        "the web UI is a separate package, licensed AGPL-3.0 and shipped apart from this "
        # ASCII: this reaches a terminal, and a section sign arrives as a
        # replacement character on a Windows console.
        "Apache-2.0 wheel on purpose (SPEC 20.4). Install it with:\n"
        "    pip install 'valqore-qed[ui]'\n"
        "The API runs without it; only the pages are missing."
    )


def ui_assets() -> Path:
    """The directory of static files inside the installed ``qed_ui``.

    Raises :class:`UiUnavailable` rather than returning None, because the two
    failures want different words: a package that is not installed is a thing
    the operator can fix, and a package that is installed but ships no assets
    is a broken wheel.
    """
    if find_spec(UI_PACKAGE) is None:
        raise UiUnavailable(f"{UI_PACKAGE} is not installed. {install_hint()}")

    module = import_module(UI_PACKAGE)
    # `assets()` is the one thing this wheel asks of that one: a callable
    # returning a directory. Keeping the contract to a single function means
    # the UI can be rebuilt, restructured or rewritten without touching the
    # kernel.
    getter = getattr(module, "assets", None)
    if getter is None:
        raise UiUnavailable(
            f"{UI_PACKAGE} is installed but exposes no `assets()`; it is too old or broken "
            "for this kernel. Reinstall with: pip install -U 'valqore-qed[ui]'"
        )
    directory = Path(getter())
    if not directory.is_dir():
        raise UiUnavailable(f"{UI_PACKAGE} points at {directory}, which is not a directory")
    if not (directory / "index.html").is_file():
        raise UiUnavailable(f"{directory} has no index.html; the UI wheel is incomplete")
    return directory


def mount_ui(app: object) -> Path:
    """Mount the UI on ``app`` at ``/ui`` and return where it came from.

    ``app`` is typed loosely so that this module imports no FastAPI symbol at
    module scope -- it is reached only from ``qed serve``, and `qed check`
    should not pay for a Starlette import to find out the UI is absent.
    """
    from fastapi import FastAPI
    from starlette.staticfiles import StaticFiles

    assert isinstance(app, FastAPI)
    directory = ui_assets()
    # `html=True` serves index.html for a directory request, which is what a
    # single-page app needs so that `/ui/approvals` reaches the page rather
    # than a 404 from the static handler.
    app.mount(UI_MOUNT, StaticFiles(directory=directory, html=True), name="ui")
    logger.info("serving the UI from %s", directory)
    return directory
