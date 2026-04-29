"""Mobile-upload response schema (Task 3.3).

The request side of the endpoint is multipart/form-data, not JSON, so
no Pydantic request model — the route reads ``UploadFile`` directly.
Only the response shape needs a schema.

``uploaded_by_user_id`` is ``UUID | None``. Null for API-key uploads
(no user actor) — see DRIFT-LOG 2026-04-26 entry 5 + ADR-012's pattern
for actor-less actions. Clients render this as "uploaded via API key".
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class MobileUploadResponse(BaseModel):
    """201 body returned by ``POST /v1/orgs/{org}/projects/{id}/mobile-uploads``."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    project_id: UUID
    uploaded_by_user_id: UUID | None
    filename: str
    file_extension: str
    file_size_bytes: int
    platform: str
    r2_key: str
    created_at: datetime
