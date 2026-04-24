"""API-wide error envelope schemas.

FastAPI returns ``{"detail": ...}`` by default for ``HTTPException``.
We publish typed schemas here so OpenAPI consumers (clients, SDKs)
get a stable contract and the error codes used across auth + future
endpoints stay consistent.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class ErrorResponse(BaseModel):
    """Generic error envelope: ``{"detail": "<machine_code>"}``.

    ``detail`` is a stable machine-readable identifier (e.g.
    ``"unauthorized"``, ``"rate_limit_exceeded"``, ``"email_not_verified"``),
    NOT a human message. Clients branch on ``detail``; humans get
    messages from i18n'd strings in the frontend.
    """

    model_config = ConfigDict(json_schema_extra={"example": {"detail": "unauthorized"}})

    detail: str
