"""Runtime configuration.

Settings are read from environment variables prefixed with ``TRACEFORGE_``
(for example ``TRACEFORGE_PORT=8080``). Every network-facing value is
restricted to loopback addresses: TraceForge controls offensive tooling and
must never be exposed on a network interface, nor send its credentials to a
remote host, by accident. See ``docs/THREAT_MODEL.md``.
"""

from __future__ import annotations

import ipaddress
import os
import stat
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlsplit

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8000
DEFAULT_DASHBOARD_URL = "http://127.0.0.1:5173"
DEFAULT_ALLOWED_ORIGINS = (
    "http://127.0.0.1:5173",  # Vite dev server
    "http://localhost:5173",
    "http://127.0.0.1:4173",  # Vite preview server
    "http://localhost:4173",
)


def default_data_dir() -> Path:
    """Return the per-user data directory, honouring ``XDG_DATA_HOME``."""
    xdg = os.environ.get("XDG_DATA_HOME")
    base = Path(xdg) if xdg else Path.home() / ".local" / "share"
    return base / "traceforge"


def default_db_path() -> Path:
    return default_data_dir() / "traceforge.db"


def _is_private_user_dir(path: Path) -> bool:
    try:
        st = path.stat()
    except OSError:
        return False
    return (
        stat.S_ISDIR(st.st_mode)
        and st.st_uid == os.getuid()
        and not st.st_mode & (stat.S_IRWXG | stat.S_IRWXO)
    )


def default_token_dir() -> Path:
    """Directory holding the per-server API token file.

    ``XDG_RUNTIME_DIR`` is only used when it really is private to this user
    (as the XDG spec requires). Some environments, notably WSLg, provide a
    world-writable runtime directory, which must not hold credentials.
    """
    runtime = os.environ.get("XDG_RUNTIME_DIR")
    if runtime and _is_private_user_dir(Path(runtime)):
        return Path(runtime) / "traceforge"
    return default_data_dir() / "run"


def is_loopback_host(host: str) -> bool:
    """Return True if ``host`` refers only to the local machine."""
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def normalize_loopback_origin(value: str) -> str:
    """Validate a browser origin (``scheme://host[:port]``) that must be loopback."""
    parts = urlsplit(value.strip())
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError(f"{value!r} is not an http(s) origin")
    if parts.path not in ("", "/") or parts.query or parts.fragment or parts.username:
        raise ValueError(f"{value!r} must be a bare origin without path, query or credentials")
    if not is_loopback_host(parts.hostname):
        raise ValueError(f"{value!r} is not a loopback origin")
    host = f"[{parts.hostname}]" if ":" in parts.hostname else parts.hostname
    port = f":{parts.port}" if parts.port else ""
    return f"{parts.scheme}://{host.lower()}{port}"


def _require_loopback_url(value: str, field: str) -> str:
    parts = urlsplit(value)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError(f"{field} must be an http(s) URL, got {value!r}")
    if not is_loopback_host(parts.hostname):
        raise ValueError(
            f"{field} must point to a loopback address, got {parts.hostname!r}; "
            "TraceForge never sends credentials off this machine"
        )
    return value.rstrip("/")


class Settings(BaseSettings):
    """TraceForge settings shared by the API server and its clients."""

    model_config = SettingsConfigDict(env_prefix="TRACEFORGE_", extra="ignore")

    host: str = Field(default=DEFAULT_HOST, description="Address the API binds to (loopback only).")
    port: int = Field(default=DEFAULT_PORT, ge=1, le=65535, description="API port.")
    db_path: Path = Field(default_factory=default_db_path, description="SQLite database file.")
    api_url: str | None = Field(
        default=None,
        description="Base URL clients use to reach the API (loopback only). Derived if unset.",
    )
    dashboard_url: str = Field(
        default=DEFAULT_DASHBOARD_URL,
        description="Where the web dashboard is served; used to build sign-in links.",
    )
    allowed_origins: list[str] = Field(
        default_factory=lambda: list(DEFAULT_ALLOWED_ORIGINS),
        description="Browser origins allowed to call the API (loopback only).",
    )
    token_file: Path | None = Field(
        default=None,
        description="API token file. Defaults to <token dir>/api-<port>.token.",
    )
    session_ttl_seconds: int = Field(default=8 * 3600, ge=60, le=7 * 24 * 3600)
    login_code_ttl_seconds: int = Field(default=300, ge=30, le=3600)
    enable_docs: bool = Field(
        default=False,
        description="Serve /docs and /openapi.json. Off by default (Swagger UI loads CDN scripts).",
    )

    # --- scanning -------------------------------------------------------------
    nmap_path: Path | None = Field(
        default=None, description="Nmap executable. Defaults to `nmap` on PATH."
    )
    evidence_dir: Path | None = Field(
        default=None,
        description="Directory for raw tool output (owner-only). Defaults to <db dir>/evidence.",
    )
    scan_max_concurrent: int = Field(
        default=2, ge=1, le=16, description="Scans that may run at the same time."
    )
    scan_max_queued: int = Field(
        default=20, ge=0, le=500, description="Scans that may wait for a free slot."
    )
    scan_default_timeout_seconds: int = Field(default=1800, ge=10, le=86400)
    scan_max_timeout_seconds: int = Field(default=4 * 3600, ge=10, le=7 * 86400)
    scan_max_addresses: int = Field(
        default=4096,
        ge=1,
        le=1 << 20,
        description="Most IP addresses a single scan may cover (CIDR targets are expanded).",
    )
    scan_max_output_bytes: int = Field(
        default=64 * 1024 * 1024, ge=1024, description="Abort a scan whose XML grows beyond this."
    )

    @field_validator("host")
    @classmethod
    def _require_loopback(cls, value: str) -> str:
        if not is_loopback_host(value):
            raise ValueError(
                f"refusing to bind to non-loopback address {value!r}; "
                "TraceForge only listens on localhost"
            )
        return value

    @field_validator("api_url")
    @classmethod
    def _api_url_loopback(cls, value: str | None) -> str | None:
        return None if value is None else _require_loopback_url(value, "api_url")

    @field_validator("dashboard_url")
    @classmethod
    def _dashboard_url_loopback(cls, value: str) -> str:
        return _require_loopback_url(value, "dashboard_url")

    @field_validator("allowed_origins")
    @classmethod
    def _origins_loopback(cls, value: list[str]) -> list[str]:
        return [normalize_loopback_origin(origin) for origin in value]

    @model_validator(mode="after")
    def _timeouts_consistent(self) -> Settings:
        if self.scan_default_timeout_seconds > self.scan_max_timeout_seconds:
            raise ValueError("scan_default_timeout_seconds exceeds scan_max_timeout_seconds")
        return self

    @property
    def evidence_path(self) -> Path:
        return self.evidence_dir or self.db_path.parent / "evidence"

    @property
    def base_url(self) -> str:
        """URL that clients (TUI, CLI) should use to reach the API."""
        if self.api_url:
            return self.api_url
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"http://{host}:{self.port}"

    @property
    def token_path(self) -> Path:
        """Token file for the server this configuration points at.

        The file name includes the port so several local servers do not
        overwrite each other's credentials.
        """
        if self.token_file is not None:
            return self.token_file
        port = urlsplit(self.base_url).port or self.port
        return default_token_dir() / f"api-{port}.token"


@lru_cache
def get_settings() -> Settings:
    """Return process-wide settings loaded from the environment."""
    return Settings()
