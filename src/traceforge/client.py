"""Async HTTP client for the TraceForge API.

The terminal UI and CLI talk to the backend exclusively through this client,
just as the web dashboard does over HTTP, so every interface goes through the
same authentication, scope enforcement and audit trail.

Authentication uses the per-server API token, read from the owner-only token
file written by ``traceforge serve``. The token rotates on every server
start, so after a 401 the file is re-read once and the request retried.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx

from traceforge.schemas import (
    AssetDetail,
    AssetStats,
    AssetSummary,
    EvidenceVerification,
    HealthResponse,
    LoginCode,
    Project,
    Scan,
    ScanComparison,
    ScanLaunchResult,
    ScanResults,
    ScopeCheckResponse,
    ScopeRule,
)
from traceforge.security.tokens import InsecureTokenFileError, read_token_file

TokenProvider = Callable[[], str | None]


class BackendUnavailableError(RuntimeError):
    """Raised when the API cannot be reached or returns an unusable response."""


class AuthenticationError(RuntimeError):
    """No valid API token is available for this server."""


class ApiError(RuntimeError):
    def __init__(self, status_code: int, detail: Any) -> None:
        self.status_code = status_code
        self.detail = detail
        super().__init__(f"HTTP {status_code}: {detail}")


def file_token_provider(path: Path) -> TokenProvider:
    def provide() -> str | None:
        try:
            return read_token_file(path)
        except InsecureTokenFileError as exc:
            raise AuthenticationError(str(exc)) from exc

    return provide


class TraceForgeClient:
    def __init__(
        self,
        base_url: str,
        *,
        token_provider: TokenProvider | None = None,
        timeout: float = 10.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self._token_provider = token_provider or (lambda: None)
        self._token: str | None = None
        self._http = httpx.AsyncClient(base_url=self.base_url, timeout=timeout, transport=transport)

    # -- transport ---------------------------------------------------------------

    async def _send(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        try:
            return await self._http.request(method, path, **kwargs)
        except httpx.HTTPError as exc:
            raise BackendUnavailableError(f"cannot reach {self.base_url}: {exc}") from exc

    async def _request(self, method: str, path: str, **kwargs: Any) -> Any:
        """Send an authenticated request, refreshing the token once on 401."""
        for attempt in range(2):
            if self._token is None or attempt == 1:
                self._token = self._token_provider()
            if self._token is None:
                raise AuthenticationError(
                    "no API token found; is `traceforge serve` running as this user?"
                )
            response = await self._send(
                method, path, headers={"Authorization": f"Bearer {self._token}"}, **kwargs
            )
            if response.status_code != 401:
                break
        if response.status_code == 401:
            raise AuthenticationError("the API rejected the token (server restarted elsewhere?)")
        if response.status_code >= 400:
            try:
                detail = response.json().get("detail")
            except ValueError:
                detail = response.text
            raise ApiError(response.status_code, detail)
        return response.json() if response.content else None

    # -- public endpoints ---------------------------------------------------------

    async def health(self) -> HealthResponse:
        """Fetch ``/health`` (no auth). A 503 still carries a valid payload."""
        response = await self._send("GET", "/health")
        if response.status_code not in (200, 503):
            raise BackendUnavailableError(
                f"unexpected HTTP {response.status_code} from {self.base_url}/health"
            )
        try:
            return HealthResponse.model_validate(response.json())
        except ValueError as exc:
            raise BackendUnavailableError(f"invalid health payload: {exc}") from exc

    # -- authenticated endpoints --------------------------------------------------

    async def create_login_code(self) -> LoginCode:
        return LoginCode.model_validate(await self._request("POST", "/api/v1/auth/login-codes"))

    async def list_projects(self) -> list[Project]:
        data = await self._request("GET", "/api/v1/projects")
        return [Project.model_validate(item) for item in data]

    async def create_project(self, name: str, authorization_ref: str, **window: Any) -> Project:
        body = {"name": name, "authorization_ref": authorization_ref, **window}
        return Project.model_validate(await self._request("POST", "/api/v1/projects", json=body))

    async def list_scope(self, project_id: int) -> list[ScopeRule]:
        data = await self._request("GET", f"/api/v1/projects/{project_id}/scope")
        return [ScopeRule.model_validate(item) for item in data]

    async def add_scope_rule(
        self, project_id: int, kind: str, value: str, note: str | None = None
    ) -> ScopeRule:
        body = {"kind": kind, "value": value, "note": note}
        data = await self._request("POST", f"/api/v1/projects/{project_id}/scope", json=body)
        return ScopeRule.model_validate(data)

    async def remove_scope_rule(self, project_id: int, rule_id: int) -> None:
        await self._request("DELETE", f"/api/v1/projects/{project_id}/scope/{rule_id}")

    async def check_scope(self, project_id: int, targets: list[str]) -> ScopeCheckResponse:
        data = await self._request(
            "POST", f"/api/v1/projects/{project_id}/scope/check", json={"targets": targets}
        )
        return ScopeCheckResponse.model_validate(data)

    async def launch_scan(
        self,
        project_id: int,
        tool: str,
        targets: list[str],
        *,
        options: dict[str, Any] | None = None,
        timeout_seconds: int | None = None,
    ) -> ScanLaunchResult:
        body: dict[str, Any] = {"tool": tool, "targets": targets, "options": options or {}}
        if timeout_seconds is not None:
            body["timeout_seconds"] = timeout_seconds
        data = await self._request("POST", f"/api/v1/projects/{project_id}/scans", json=body)
        return ScanLaunchResult.model_validate(data)

    async def list_scans(
        self, project_id: int | None = None, status: str | None = None, limit: int = 50
    ) -> list[Scan]:
        params: dict[str, Any] = {"limit": limit}
        if project_id is not None:
            params["project_id"] = project_id
        if status is not None:
            params["status"] = status
        data = await self._request("GET", "/api/v1/scans", params=params)
        return [Scan.model_validate(item) for item in data]

    async def get_scan(self, scan_id: int) -> Scan:
        return Scan.model_validate(await self._request("GET", f"/api/v1/scans/{scan_id}"))

    async def get_scan_results(self, scan_id: int) -> ScanResults:
        data = await self._request("GET", f"/api/v1/scans/{scan_id}/results")
        return ScanResults.model_validate(data)

    async def cancel_scan(self, scan_id: int) -> Scan:
        return Scan.model_validate(await self._request("POST", f"/api/v1/scans/{scan_id}/cancel"))

    # -- asset inventory & comparisons (v0.3) ---------------------------------------

    async def list_assets(
        self,
        project_id: int | None = None,
        query: str | None = None,
        *,
        include_unconfirmed: bool = False,
        limit: int = 200,
    ) -> list[AssetSummary]:
        params: dict[str, Any] = {"limit": limit}
        if project_id is not None:
            params["project_id"] = project_id
        if query:
            params["q"] = query
        if include_unconfirmed:
            params["include_unconfirmed"] = "true"
        data = await self._request("GET", "/api/v1/assets", params=params)
        return [AssetSummary.model_validate(item) for item in data]

    async def asset_stats(self, project_id: int | None = None) -> AssetStats:
        params = {"project_id": project_id} if project_id is not None else {}
        return AssetStats.model_validate(
            await self._request("GET", "/api/v1/assets/stats", params=params)
        )

    async def get_asset(self, uid: str) -> AssetDetail:
        return AssetDetail.model_validate(await self._request("GET", f"/api/v1/assets/{uid}"))

    async def compare_scans(
        self, project_id: int, baseline: int, comparison: int
    ) -> ScanComparison:
        data = await self._request(
            "GET",
            f"/api/v1/projects/{project_id}/scans/compare",
            params={"baseline": baseline, "comparison": comparison},
        )
        return ScanComparison.model_validate(data)

    async def verify_evidence(self, scan_id: int) -> EvidenceVerification:
        data = await self._request("GET", f"/api/v1/scans/{scan_id}/evidence/verify")
        return EvidenceVerification.model_validate(data)

    # -- lifecycle ----------------------------------------------------------------

    async def aclose(self) -> None:
        await self._http.aclose()

    async def __aenter__(self) -> TraceForgeClient:
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.aclose()
