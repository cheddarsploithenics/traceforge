"""Asset inventory: hosts discovered by completed scans, with provenance."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Path, Query, status

from traceforge.api.deps import get_executor
from traceforge.db.repositories import NotFoundError
from traceforge.execution.executor import Executor
from traceforge.inventory.store import AssetQueries
from traceforge.schemas import ASSET_UID_PATTERN, AssetDetail, AssetStats, AssetSummary
from traceforge.security.auth import AuthenticatedPrincipal

router = APIRouter(prefix="/api/v1/assets", tags=["assets"])
ExecutorDep = Annotated[Executor, Depends(get_executor)]


def _queries(executor: Executor) -> AssetQueries:
    return AssetQueries(executor.scans.db)


def _require_project(executor: Executor, project_id: int | None) -> None:
    if project_id is None:
        return
    try:
        executor.projects.get(project_id)
    except NotFoundError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc


@router.get("", response_model=list[AssetSummary])
def list_assets(
    _: AuthenticatedPrincipal,
    executor: ExecutorDep,
    project_id: int | None = None,
    q: Annotated[
        str | None,
        Query(max_length=200, description="Match address, hostname, service, product or port."),
    ] = None,
    include_unconfirmed: bool = False,
    limit: Annotated[int, Query(ge=1, le=1000)] = 200,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[dict]:
    """Assets, most recently seen first. Filter by project to keep engagements apart."""
    _require_project(executor, project_id)
    return _queries(executor).list(project_id, q, include_unconfirmed, limit, offset)


@router.get("/stats", response_model=AssetStats)
def asset_stats(
    _: AuthenticatedPrincipal, executor: ExecutorDep, project_id: int | None = None
) -> dict:
    _require_project(executor, project_id)
    return _queries(executor).stats(project_id)


@router.get("/{uid}", response_model=AssetDetail)
def get_asset(
    uid: Annotated[str, Path(pattern=ASSET_UID_PATTERN)],
    _: AuthenticatedPrincipal,
    executor: ExecutorDep,
) -> dict:
    """An asset's current ports and every observation of it, with provenance."""
    asset = _queries(executor).get(uid)
    if asset is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"asset {uid} not found")
    return asset
