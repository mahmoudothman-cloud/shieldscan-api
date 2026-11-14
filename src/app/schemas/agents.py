"""On-prem agent schemas (M14)."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


# ---------------------------------------------------------------- org-facing


class AgentCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=80)
    description: str | None = Field(default=None, max_length=500)


class AgentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    description: str | None
    status: str  # pending | active | offline | revoked (offline is derived)
    key_prefix: str | None
    enrolled_at: datetime | None
    last_seen_at: datetime | None
    version: str | None
    hostname: str | None
    platform: str | None
    tools: dict[str, Any]
    project_count: int = 0
    created_at: datetime


class AgentCreatedResponse(BaseModel):
    """The enrolment token is shown ONCE, here."""

    agent: AgentResponse
    enrolment_token: str
    enrolment_expires_at: datetime
    enrol_command: str


class AgentListResponse(BaseModel):
    agents: list[AgentResponse]


# ---------------------------------------------------------------- gateway (agent-facing)


class EnrolRequest(BaseModel):
    token: str = Field(min_length=10, max_length=200)
    version: str | None = Field(default=None, max_length=40)
    hostname: str | None = Field(default=None, max_length=255)
    platform: str | None = Field(default=None, max_length=40)


class EnrolResponse(BaseModel):
    agent_id: UUID
    organization_id: UUID
    name: str
    agent_key: str  # shown once


class HeartbeatRequest(BaseModel):
    version: str | None = Field(default=None, max_length=40)
    hostname: str | None = Field(default=None, max_length=255)
    platform: str | None = Field(default=None, max_length=40)
    tools: dict[str, Any] | None = None


class HeartbeatResponse(BaseModel):
    agent_id: UUID
    name: str
    cancel_scan_ids: list[str]
    requeued_job_ids: list[str]
    poll_wait_s: int = 25


class JobEventsRequest(BaseModel):
    events: list[dict[str, Any]] = Field(max_length=500)


class JobFailRequest(BaseModel):
    error_message: str = Field(min_length=1, max_length=500)
