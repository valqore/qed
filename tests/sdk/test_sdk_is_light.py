"""`import qed.sdk` must not drag a server into the application.

The SDK is embedded in somebody else's process -- a LangGraph worker, a Celery
task, a web handler. An SDK that pulls FastAPI, Starlette, Uvicorn and Click
into that process is an SDK people route around, and routing around it means
their actions stop being recorded. The governance is only worth what people
leave switched on.

This is why ``canonical_string`` and ``sign`` moved out of ``qed/api/auth.py``
into ``qed/adapters/signing.py``: the SDK has to sign, and importing the API
module to do it cost a web framework.
"""

from __future__ import annotations

import subprocess
import sys

#: Things an application that only wants to propose an action should not have
#: to load.
#:
#: `httpx` is absent on purpose: the SDK is an HTTP client and that is the one
#: dependency it is entitled to. `click` is absent for a duller reason --
#: `httpx` exports a command-line entry point and so imports it itself, so its
#: presence says nothing about what QED loaded. `typer` stays on the list,
#: because that one would mean the CLI itself had been dragged in.
FORBIDDEN = (
    "fastapi",
    "starlette",
    "uvicorn",
    "typer",
    "mcp",
    "joserfc",
    "keyring",
    "yaml",
)


def imported_by(statement: str) -> set[str]:
    """Top-level modules present after `statement`, in a fresh interpreter.

    A subprocess rather than `sys.modules` in this one: pytest has already
    imported most of the repository, so an in-process check would pass no
    matter what the SDK pulled in. That is the mistake the equivalent check in
    the Phase-0 inventory made, and it is why this file exists.
    """
    code = (
        f"{statement}\n"
        "import sys, json\n"
        "print(json.dumps(sorted({m.split('.')[0] for m in sys.modules})))\n"
    )
    out = subprocess.run(
        [sys.executable, "-I", "-c", code], capture_output=True, text=True, check=True
    )
    import json

    return set(json.loads(out.stdout))


def test_the_sdk_imports_no_server() -> None:
    loaded = imported_by("import qed.sdk")
    offenders = sorted(set(FORBIDDEN) & loaded)
    assert not offenders, (
        f"`import qed.sdk` pulls in {offenders}. The SDK runs inside somebody else's "
        "application; an SDK that loads a web framework is one people route around, and "
        "routing around it means their actions stop being recorded."
    )


def test_the_signing_module_imports_nothing_heavy() -> None:
    """The reason it is not in `qed.api`."""
    loaded = imported_by("import qed.adapters.signing")
    assert not sorted(set(FORBIDDEN) & loaded)


def test_the_sdk_really_was_imported() -> None:
    """Guards the two above against passing because the import failed."""
    assert "qed" in imported_by("import qed.sdk")


def test_the_api_still_shares_one_signing_implementation() -> None:
    """Moving the definitions must not have left two of them.

    The canonical string is a wire format: the signer and the verifier agree on
    it byte for byte, or adapter auth silently stops working for one of them.

    Compared by *output* rather than by object identity. `is` was the first
    version and it failed in the full suite but passed alone, because
    `tests/adapters/test_import_boundary.py` deletes every `qed.adapters.*`
    entry from `sys.modules` to prove the classifier imports cleanly -- after
    which a fresh import builds new function objects while `qed.api.auth`
    still holds the old ones. Byte agreement is the property that matters
    anyway; identity was only a proxy for it.
    """
    from qed.adapters import signing
    from qed.api import auth

    fixture = {
        "method": "post",
        "path": "/v1/proposals",
        "timestamp": "2026-10-09T00:00:00.000Z",
        "nonce": "01JB",
        "body": b'{"id": "x"}',
    }
    assert auth.canonical_string(**fixture) == signing.canonical_string(**fixture)
    canonical = signing.canonical_string(**fixture)
    assert auth.sign("a-secret", canonical) == signing.sign("a-secret", canonical)
    for name in ("HEADER_ADAPTER", "HEADER_TIMESTAMP", "HEADER_NONCE", "HEADER_SIGNATURE"):
        assert getattr(auth, name) == getattr(signing, name)
