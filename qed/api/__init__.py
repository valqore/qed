"""HTTP API (SPEC §13).

``qed serve`` runs this. The router's only job is to turn a request into the
arguments ``qed.runtime.check_proposal`` already takes and to turn its result
back into JSON. It holds no policy logic of its own: ``POST /v1/proposals`` and
``qed check`` must return the same verdict for the same input, and the only way
to guarantee that is for both to call the same function.

Week 2 implements the subset SPEC §22 asks for: ``/v1/proposals``,
``/v1/evidence``, ``/healthz`` and ``/readyz``. Tokens (``/v1/token``) are week 3,
approvals week 4, and the rest follows the build order. Endpoints that do not
exist are absent rather than stubbed, for the same reason SPEC §14 gives for the
CLI: a route that answers "not implemented" ends up in somebody's script.
"""

from __future__ import annotations

from qed.api.app import create_app

__all__ = ["create_app"]
