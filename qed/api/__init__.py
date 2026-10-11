"""HTTP API (SPEC §13).

``qed serve`` runs this. The router's only job is to turn a request into the
arguments ``qed.runtime.check_proposal`` already takes and to turn its result
back into JSON. It holds no policy logic of its own: ``POST /v1/proposals`` and
``qed check`` must return the same verdict for the same input, and the only way
to guarantee that is for both to call the same function.

Endpoints that do not exist are absent rather than stubbed, for the same reason
SPEC §14 gives for the CLI: a route that answers "not implemented" ends up in
somebody's script. What SPEC §19 has not built yet -- the live stream and the
budget pages -- is therefore not routable, and ``README.md`` says so.
"""

from __future__ import annotations

from qed.api.app import create_app

__all__ = ["create_app"]
