"""RFC 9457 ``application/problem+json`` errors (SPEC §13).

One error shape for the whole API. FastAPI's default is
``{"detail": ...}``, which SPEC §13 does not allow, so the handlers registered
in :func:`install_handlers` replace it everywhere -- including for validation
failures and for routes that do not exist, which is where a half-converted API
usually leaks its old format.
"""

from __future__ import annotations

from typing import Final

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.responses import JSONResponse

__all__ = ["CONTENT_TYPE", "Problem", "install_handlers", "problem_response"]

CONTENT_TYPE: Final = "application/problem+json"

#: Base for the ``type`` URI. Not fetched at runtime; it is an identifier that
#: happens to be a URL, which is what RFC 9457 asks for.
_TYPE_BASE: Final = "https://valqore.io/qed/problems"


class Problem(Exception):
    """Raise this anywhere in a handler to emit a problem document."""

    def __init__(
        self,
        *,
        status: int,
        code: str,
        title: str,
        detail: str,
        extra: dict[str, object] | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.status = status
        self.code = code
        self.title = title
        self.detail = detail
        self.extra = extra or {}
        #: Response headers the status code requires. SPEC §13's 429 has to
        #: carry `Retry-After`, and a client reading that header is a client
        #: that backs off correctly without parsing the body -- which is the
        #: whole reason the header exists rather than only the JSON field.
        self.headers = headers or {}
        super().__init__(detail)


def problem_response(
    *,
    status: int,
    code: str,
    title: str,
    detail: str,
    instance: str | None = None,
    extra: dict[str, object] | None = None,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    body: dict[str, object] = {
        "type": f"{_TYPE_BASE}/{code}",
        "title": title,
        "status": status,
        "detail": detail,
    }
    if instance is not None:
        body["instance"] = instance
    body.update(extra or {})
    return JSONResponse(body, status_code=status, media_type=CONTENT_TYPE, headers=headers or None)


def install_handlers(app: FastAPI) -> None:
    @app.exception_handler(Problem)
    async def _problem(request: Request, exc: Problem) -> JSONResponse:
        return problem_response(
            status=exc.status,
            code=exc.code,
            title=exc.title,
            detail=exc.detail,
            instance=str(request.url.path),
            extra=exc.extra,
            headers=exc.headers,
        )

    @app.exception_handler(StarletteHTTPException)
    async def _http(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        return problem_response(
            status=exc.status_code,
            code=_slug(exc.status_code),
            title=_title(exc.status_code),
            detail=str(exc.detail),
            instance=str(request.url.path),
        )

    @app.exception_handler(RequestValidationError)
    async def _validation(request: Request, exc: RequestValidationError) -> JSONResponse:
        # 422 and not 400: the body parsed as JSON but did not satisfy the
        # schema. An adapter needs to tell the two apart to know whether to
        # retry or to fix itself.
        return problem_response(
            status=422,
            code="invalid-body",
            title="The request body does not match the schema",
            detail=(
                "See `errors` for the failing fields. The schema is "
                "ActionProposal from SPEC 3.1; unknown fields are rejected."
            ),
            instance=str(request.url.path),
            extra={"errors": _safe_errors(exc)},
        )


def _safe_errors(exc: RequestValidationError) -> list[dict[str, object]]:
    """Field paths and messages only.

    Pydantic's raw errors carry the offending *input* in ``ctx``, and a rejected
    proposal body can hold the very secret ``AG-DAT-001`` exists to stop. An
    error response is not part of the evidence chain and is not masked on the
    way out, so the value never leaves this process.
    """
    return [
        {"loc": [str(part) for part in error.get("loc", ())], "msg": str(error.get("msg", ""))}
        for error in exc.errors()
    ]


def _slug(status: int) -> str:
    return {
        400: "bad-request",
        401: "unauthenticated",
        403: "forbidden",
        404: "not-found",
        405: "method-not-allowed",
        409: "conflict",
        413: "payload-too-large",
        429: "rate-limited",
        503: "not-ready",
    }.get(status, f"http-{status}")


def _title(status: int) -> str:
    return {
        400: "The request could not be understood",
        401: "The request is not authenticated",
        403: "The adapter is not allowed to do this",
        404: "No such resource",
        405: "That method is not allowed here",
        409: "That conflicts with something already recorded",
        413: "The request body is too large",
        429: "Too many requests",
        503: "The service is not ready",
    }.get(status, "Request failed")
