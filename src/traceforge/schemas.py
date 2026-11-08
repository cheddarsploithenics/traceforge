"""Data models shared by the API and its clients.

Keeping these in one place guarantees the web dashboard, the terminal UI and
the server agree on the shape of every response. The TypeScript mirror lives
in ``web/src/api/client.ts``.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import AwareDatetime, BaseModel, Field, model_validator

ComponentState = Literal["ok", "error"]


class HealthResponse(BaseModel):
    """Payload returned by ``GET /health``."""

    status: Literal["ok", "degraded"] = Field(description="Overall service status.")
    version: str = Field(description="TraceForge version string.")
    database: ComponentState = Field(description="SQLite connectivity.")


# --- authentication ------------------------------------------------------------


class LoginRequest(BaseModel):
    code: str = Field(min_length=1, max_length=256)


class SessionInfo(BaseModel):
    method: Literal["token", "session"]
    csrf_token: str | None = Field(
        default=None, description="Send in X-TraceForge-CSRF on state-changing requests."
    )
    expires_at: datetime | None = None


class LoginCode(BaseModel):
    code: str
    url: str
    expires_at: datetime


# --- projects & scope ------------------------------------------------------------


class ProjectCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    authorization_ref: str = Field(
        min_length=1,
        max_length=500,
        description="Reference to the written authorization (e.g. contract or SOW id).",
    )
    authorized_from: AwareDatetime | None = None
    authorized_until: AwareDatetime | None = None

    @model_validator(mode="after")
    def _window_is_ordered(self) -> ProjectCreate:
        start, end = self.authorized_from, self.authorized_until
        if start and end and end <= start:
            raise ValueError("authorized_until must be after authorized_from")
        return self


class Project(BaseModel):
    id: int
    name: str
    authorization_ref: str
    authorized_from: datetime | None
    authorized_until: datetime | None
    created_at: datetime
    scope_rule_count: int


class ScopeRuleCreate(BaseModel):
    kind: Literal["include", "exclude"]
    value: str = Field(min_length=1, max_length=300)
    note: str | None = Field(default=None, max_length=500)


class ScopeRule(BaseModel):
    id: int
    project_id: int
    kind: Literal["include", "exclude"]
    value: str
    note: str | None
    created_at: datetime


class TargetList(BaseModel):
    targets: list[str] = Field(min_length=1, max_length=1024)


class ScopeDecision(BaseModel):
    target: str
    allowed: bool
    reason: str


class ScopeCheckResponse(BaseModel):
    allowed: bool = Field(description="True only if every target is in scope.")
    decisions: list[ScopeDecision]


class ScanLaunch(TargetList):
    tool: str = Field(min_length=1, max_length=64)


class ScanLaunchResult(BaseModel):
    scan_id: int
    tool: str
    targets: list[str]
