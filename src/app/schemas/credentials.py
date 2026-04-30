"""Project-credential request/response schemas (Task 3.X).

Request shape: a Pydantic v2 discriminated union on ``auth_type``.
Each variant validates exactly the fields its credential type needs
— a basic-auth body without ``password`` 422s at the schema layer
without ever reaching the route handler.

Response shape: write-only contract — only ``auth_type`` + a
``configured`` boolean + ``updated_at``. NEVER returns decrypted
secret fields. Pinned by
``test_patch_response_never_returns_decrypted_credential``.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, HttpUrl


# ---------------------------------------------------------------- request variants


class _StrictBase(BaseModel):
    """Reject extra fields in any variant — prevents typos like
    ``passwrd`` from being silently encrypted into the blob."""

    model_config = ConfigDict(extra="forbid")


class BasicCredentialRequest(_StrictBase):
    auth_type: Literal["basic"]
    username: str = Field(min_length=1, max_length=255)
    password: str = Field(min_length=1, max_length=1000)


class BearerCredentialRequest(_StrictBase):
    auth_type: Literal["bearer"]
    token: str = Field(min_length=1, max_length=4000)


class CookieCredentialRequest(_StrictBase):
    auth_type: Literal["cookie"]
    cookie_name: str = Field(min_length=1, max_length=255)
    cookie_value: str = Field(min_length=1, max_length=4000)


class CustomHeaderCredentialRequest(_StrictBase):
    auth_type: Literal["custom_header"]
    header_name: str = Field(min_length=1, max_length=255)
    header_value: str = Field(min_length=1, max_length=4000)


class FormCredentialRequest(_StrictBase):
    """Form-based authentication — five canonical fields. Additional
    custom fields (``additional_fields`` map) deferred for MVP; see
    DRIFT-LOG 2026-04-30 entry 3."""

    auth_type: Literal["form"]
    login_url: HttpUrl
    username_field: str = Field(min_length=1, max_length=255)
    password_field: str = Field(min_length=1, max_length=255)
    username: str = Field(min_length=1, max_length=255)
    password: str = Field(min_length=1, max_length=1000)


# Discriminated union — Pydantic dispatches on the ``auth_type``
# literal and validates the matching variant. Unknown auth_type
# values 422 with a clear "Input should be 'basic', 'bearer', ..."
# message.
CredentialRequest = Annotated[
    BasicCredentialRequest
    | BearerCredentialRequest
    | CookieCredentialRequest
    | CustomHeaderCredentialRequest
    | FormCredentialRequest,
    Field(discriminator="auth_type"),
]


# ---------------------------------------------------------------- response


class CredentialResponse(BaseModel):
    """200 body for ``PATCH /credentials``. Write-only contract:
    no decrypted secret fields are surfaced. Same one-way-write
    discipline as API key plaintext (visible only at create-time).
    """

    auth_type: str
    configured: bool = True
    updated_at: datetime
