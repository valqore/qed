# PyInstaller spec for the single-file `qed` binary (SPEC §22 week 10, §24.1).
#
# Why a spec file rather than a command line: the data files and the hidden
# imports below are not discoverable by static analysis, and a flag soup in a
# CI step is a thing nobody can run locally to reproduce a failure.
#
# Build:
#   pyinstaller deploy/qed.spec --noconfirm --clean
#   dist/qed --help
#
# The binary is for somebody who wants `qed check` and `qed verify` without a
# Python install -- a CI runner, a laptop, an air-gapped box. `qed serve` works
# too, but the container (`ghcr.io/valqore/qed`) is the better answer for a
# long-running process: it is the artifact that gets an SBOM and a signature.

from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files, collect_submodules

HERE = Path(SPECPATH).resolve().parent  # noqa: F821 - PyInstaller injects it

# Every non-Python file `qed` reads at runtime. The same list as
# `pyproject.toml`'s `package-data`, and for the same reason: a file left out
# here is a binary that starts and dies on the first request.
#
# `tests/test_packaging.py` already checks the wheel's list against the
# filesystem; `tests/deploy/test_binary.py` checks that this one agrees with
# that one, because two lists of the same files are two chances to be wrong.
datas = [
    *collect_data_files("qed", includes=["**/*.yaml", "**/*.sql"]),
]

# Imports nothing reaches by name.
#
# `qed.cli` imports its heavy adapters lazily and by string, which is
# deliberate -- SPEC 20.3 keeps `qed check` from paying for the MCP SDK -- and
# is exactly what PyInstaller's static analysis cannot see. So the adapters and
# the API are collected explicitly.
hiddenimports = [
    *collect_submodules("qed"),
    *collect_submodules("qed_verify"),
    # `uvicorn` resolves its loop and protocol implementations from strings in
    # its own config, so none of them is reachable from an import graph.
    *collect_submodules("uvicorn"),
    # `keyring` finds its OS backend through entry points.
    *collect_submodules("keyring"),
    # psycopg is an optional extra; included when installed so one binary
    # serves both backends. `collect_submodules` returns nothing when it is
    # absent, which is what makes this safe to list unconditionally.
    *collect_submodules("psycopg"),
]

analysis = Analysis(  # noqa: F821
    [str(HERE / "qed" / "cli.py")],
    # Both roots. `qed_verify` lives in `packages/qed-verify/` and is an
    # editable install, so `collect_submodules` resolves its names through the
    # editable finder while the *bundler* still needs the directory on the
    # path. Without it the binary builds, `qed verify` fails to import, and
    # the message tells a user with no Python to run `pip install`.
    pathex=[str(HERE), str(HERE / "packages" / "qed-verify")],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    # `tkinter` and `test` are large and unreachable. Excluding them is worth
    # roughly ten megabytes and no functionality.
    excludes=["tkinter", "test", "unittest", "pydoc_data"],
    noarchive=False,
)

pyz = PYZ(analysis.pure)  # noqa: F821

executable = EXE(  # noqa: F821
    pyz,
    analysis.scripts,
    analysis.binaries,
    analysis.datas,
    name="qed",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    # UPX off. It breaks code signing on macOS, and a binary that cannot be
    # notarised is a binary Homebrew users cannot run without a warning.
    upx=False,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
