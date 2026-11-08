"""Data models shared by the API and its clients.

Keeping these in one place guarantees the web dashboard, the terminal UI and
the server agree on the shape of every response. The TypeScript mirror lives
in ``web/src/api/client.ts``.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, field_validator, model_validator

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


class ScopeDecisionDetail(ScopeDecision):
    addresses: list[str] = Field(
        default_factory=list, description="Addresses a hostname resolved to during the check."
    )


class ScopeCheckResponse(BaseModel):
    allowed: bool = Field(description="True only if every target is in scope.")
    decisions: list[ScopeDecisionDetail]


# --- scans ------------------------------------------------------------------------

ScanStatus = Literal["queued", "running", "completed", "failed", "cancelled"]
ACTIVE_SCAN_STATUSES: frozenset[str] = frozenset({"queued", "running"})

_PORT_SPEC = re.compile(r"^\d{1,5}(?:-\d{1,5})?(?:,\d{1,5}(?:-\d{1,5})?)*$")


class NmapScanOptions(BaseModel):
    """The complete set of Nmap options a client may choose.

    There is deliberately no way to pass raw arguments: every flag TraceForge
    emits is derived from these fields (see ``traceforge.execution.nmap``).
    TCP connect scanning (``-sT``) is always used. Stealth/evasion timing
    templates (``-T0``/``-T1``) and ``-T5`` are not offered.
    """

    model_config = ConfigDict(extra="forbid")

    service_detection: bool = Field(default=True, description="Probe open ports (-sV).")
    ports: str | None = Field(
        default=None,
        max_length=512,
        description="Port list such as '22,80,443,8000-8100' (-p). Default: Nmap's top 1000.",
        examples=["22,80,443"],
    )
    top_ports: int | None = Field(
        default=None, ge=1, le=65535, description="Scan the N most common ports (--top-ports)."
    )
    timing: Literal[2, 3, 4] = Field(default=3, description="Timing template -T2 … -T4.")
    skip_host_discovery: bool = Field(default=False, description="Treat all hosts as online (-Pn).")

    @field_validator("ports")
    @classmethod
    def _valid_ports(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not _PORT_SPEC.match(value):
            raise ValueError("ports must look like '22,80,443' or '1-1024' (no spaces)")
        for part in value.split(","):
            low, _, high = part.partition("-")
            start, end = int(low), int(high or low)
            if not 1 <= start <= end <= 65535:
                raise ValueError(f"invalid port range {part!r} (ports are 1-65535)")
        return value

    @model_validator(mode="after")
    def _one_port_selection(self) -> NmapScanOptions:
        if self.ports is not None and self.top_ports is not None:
            raise ValueError("choose either ports or top_ports, not both")
        return self


class ScanLaunch(TargetList):
    tool: str = Field(default="nmap", min_length=1, max_length=64)
    options: dict[str, Any] = Field(
        default_factory=dict,
        description="Tool options; for nmap see NmapScanOptions.",
        examples=[{"service_detection": True, "ports": "22,80,443"}],
    )
    timeout_seconds: int | None = Field(
        default=None, ge=10, le=7 * 86400, description="Kill the scan after this long."
    )


class ScanLaunchResult(BaseModel):
    scan_id: int
    tool: str
    targets: list[str]
    scan_addresses: list[str] = Field(
        default_factory=list, description="What the tool actually scans (hostnames pinned to IPs)."
    )
    status: ScanStatus = "queued"


class EvidenceRef(BaseModel):
    """Reference to the raw tool output kept on disk."""

    file: str = Field(description="File name inside the evidence directory.")
    sha256: str
    size_bytes: int


class Scan(BaseModel):
    id: int
    project_id: int | None
    tool: str | None
    name: str
    status: ScanStatus
    targets: list[str]
    scan_addresses: list[str]
    options: dict[str, Any]
    command: list[str] = Field(description="Exact argument vector executed (no shell).")
    actor: str | None
    timeout_seconds: int | None
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    exit_code: int | None
    error: str | None
    tool_version: str | None
    evidence: EvidenceRef | None
    hosts_up: int
    open_ports: int
    ports_scanned: dict[str, str] | None = Field(
        default=None,
        description="Ports the scan probed, per protocol (e.g. {'tcp': '1-1024'}); "
        "null when unknown.",
    )


class ScanPort(BaseModel):
    protocol: str
    port: int
    state: str
    reason: str | None
    service_name: str | None
    service_product: str | None
    service_version: str | None
    service_extrainfo: str | None
    service_tunnel: str | None
    service_method: str | None
    service_confidence: int | None
    cpe: list[str]


class ScanHost(BaseModel):
    asset_id: int
    asset_uid: str | None = None
    observed_at: datetime | None = None
    timed_out: bool = False
    address: str
    addr_type: str
    state: str
    reason: str | None
    hostnames: list[str]
    ports: list[ScanPort]


class ScanResults(BaseModel):
    scan: Scan
    hosts: list[ScanHost]


# --- asset inventory (v0.3) --------------------------------------------------------

Identification = Literal["detected", "port-label"]
ASSET_UID_PATTERN = r"^ast_[0-9a-f]{16}$"


class ServiceRef(BaseModel):
    protocol: str
    port: int
    service_name: str | None
    identification: Identification | None = Field(
        description="'detected': Nmap probed and identified the service. 'port-label': only the "
        "conventional service name for that port number."
    )


class AssetSummary(BaseModel):
    uid: str = Field(description="Stable asset identifier.")
    project_id: int
    project_name: str
    address: str
    addr_type: str
    hostnames: list[str]
    first_seen: datetime = Field(description="First observation in which the host responded.")
    last_seen: datetime = Field(description="Latest observation in which the host responded.")
    confirmed: bool = Field(
        description="False if the host was only ever assumed up (-Pn) without answering."
    )
    open_ports: int
    last_scan_id: int | None
    services: list[ServiceRef]


class AssetPort(BaseModel):
    """Current state of a port, derived from every observation of it."""

    protocol: str
    port: int
    state: str = Field(description="State in the latest scan that observed this port.")
    state_scan_id: int | None
    first_seen: datetime
    last_seen: datetime = Field(description="Latest scan that observed this port (any state).")
    last_open_at: datetime | None
    service_name: str | None
    service_product: str | None
    service_version: str | None
    service_extrainfo: str | None
    service_method: str | None
    identification: Identification | None
    service_confidence: int | None
    cpe: list[str]
    service_scan_id: int | None


class ScanConfiguration(BaseModel):
    options: dict[str, Any]
    command: list[str]
    timeout_seconds: int | None
    ports_scanned: dict[str, str] | None
    host_discovery: bool
    service_detection: bool


class Provenance(BaseModel):
    """Where an observation came from, down to the evidence file and its hash."""

    project_id: int
    scan_id: int
    tool: str | None
    tool_version: str | None
    observed_at: datetime
    requested_targets: list[str] = Field(description="Targets the operator asked to scan.")
    scanned_address: str = Field(description="Address the tool actually scanned.")
    configuration: ScanConfiguration
    evidence: EvidenceRef | None


class ObservedPort(BaseModel):
    protocol: str
    port: int
    state: str
    reason: str | None
    service_name: str | None
    service_product: str | None
    service_version: str | None
    service_extrainfo: str | None
    service_method: str | None
    identification: Identification | None
    cpe: list[str]


class AssetObservation(BaseModel):
    scan_id: int
    observed_at: datetime
    state: str
    reason: str | None
    responsive: bool
    timed_out: bool
    hostnames: list[str]
    ports: list[ObservedPort] = Field(description="Ports the scan reported individually.")
    provenance: Provenance


class AssetDetail(AssetSummary):
    ports: list[AssetPort]
    observations: list[AssetObservation] = Field(description="Newest first.")


class AssetStats(BaseModel):
    assets: int
    unconfirmed: int
    assets_with_open_ports: int
    open_ports: int
    detected_services: int


# --- scan comparison (v0.3) --------------------------------------------------------

ChangeCategory = Literal["added", "removed", "changed", "inconclusive"]


class ComparisonSide(BaseModel):
    scan_id: int
    status: ScanStatus
    created_at: datetime
    finished_at: datetime | None
    tool: str | None
    tool_version: str | None
    targets: list[str]
    scan_addresses: list[str]
    ports_scanned: dict[str, str] | None
    host_discovery: bool
    service_detection: bool
    hosts_responsive: int
    evidence: EvidenceRef | None


class ComparisonChange(BaseModel):
    category: ChangeCategory = Field(
        description="added/removed/changed are confirmed by observations in both scans; "
        "inconclusive means one side did not observe it, or the observation is ambiguous."
    )
    kind: str
    address: str
    asset_uid: str | None
    hostnames: list[str]
    protocol: str | None
    port: int | None
    before: dict[str, Any] | None
    after: dict[str, Any] | None
    detail: str


class ComparisonSummary(BaseModel):
    added: int
    removed: int
    changed: int
    inconclusive: int
    unchanged_open_ports: int


class ScanComparison(BaseModel):
    project_id: int
    baseline: ComparisonSide
    comparison: ComparisonSide
    summary: ComparisonSummary
    changes: list[ComparisonChange]
    notes: list[str]


class EvidenceVerification(BaseModel):
    scan_id: int
    file: str
    recorded_sha256: str
    actual_sha256: str | None
    size_bytes: int | None
    verified: bool
    detail: str
