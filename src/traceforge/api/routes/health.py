"""Liveness / readiness endpoint."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Response, status

from traceforge import __version__
from traceforge.api.deps import get_database
from traceforge.db import Database
from traceforge.schemas import HealthResponse

router = APIRouter(tags=["system"])


@router.get(
    "/health",
    response_model=HealthResponse,
    responses={status.HTTP_503_SERVICE_UNAVAILABLE: {"model": HealthResponse}},
    summary="Report service health",
)
def health(
    response: Response,
    database: Annotated[Database, Depends(get_database)],
) -> HealthResponse:
    """Return 200 when all components are healthy, 503 otherwise."""
    db_ok = database.ping()
    if not db_ok:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return HealthResponse(
        status="ok" if db_ok else "degraded",
        version=__version__,
        database="ok" if db_ok else "error",
    )
