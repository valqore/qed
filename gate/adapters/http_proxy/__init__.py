"""The HTTP forward proxy adapter (SPEC §12.3).

``gate proxy`` listens as an ordinary HTTP forward proxy. An agent configured
with ``HTTPS_PROXY=http://127.0.0.1:8888`` sends every outbound call through
it, each one becomes an :class:`~gate.core.schemas.ActionProposal`, and the
same ``check_proposal`` the MCP proxy and ``gate check`` use decides it.

Two transports arrive on the same port and they are not equally governable:

* **Plain HTTP** (``GET http://host/path``) is fully visible. Method, path and
  query go into the proposal, the agent's own credentials are stripped, and
  the broker's credential is attached. The gate is *enforcing*.
* **CONNECT** (``CONNECT host:443``) is a TLS tunnel. The gate can refuse to
  open it, which is real, but once open it sees ciphertext: no method, no
  path, no body, and no way to replace the credential inside. The gate is
  *advisory* for every tunnel, and says so rather than letting the evidence
  imply more.

That second bullet is the honest limit of SPEC §12.3's ``host_path`` mode and
the entire reason the optional ``mitm`` mode exists. It is stated at startup,
recorded on every proposal, and printed in the closing summary.
"""

from __future__ import annotations

from gate.adapters.http_proxy.proxy import (
    ADAPTER_NAME,
    HttpProxyOptions,
    HttpProxyStats,
    build_http_proposal,
    run_http_proxy,
    serving,
)

__all__ = [
    "ADAPTER_NAME",
    "HttpProxyOptions",
    "HttpProxyStats",
    "build_http_proposal",
    "run_http_proxy",
    "serving",
]
