"""Scan history, status, results, evidence and cancellation.

Scans are created through ``POST /api/v1/projects/{id}/scans`` (which enforces
scope); these routes only read and cancel them.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status

from traceforge.api.deps import get_app_settings, get_executor, get_jobs
from traceforge.config import Settings
from traceforge.db.repositories import NotFoundError
from traceforge.execution.executor import Executor
from traceforge.execution.jobs import ScanJobManager
from traceforge.schemas import (
    ACTIVE_SCAN_STATUSES,
    EvidenceVerification,
    Scan,
    ScanResults,
    ScanStatus,
)
from traceforge.security.auth import AuthenticatedPrincipal

router = APIRouter(prefix="/api/v1/scans", tags=["scans"])
ExecutorDep = Annotated[Executor, Depends(get_executor)]
JobsDep = Annotated[ScanJobManager, Depends(get_jobs)]
SettingsDep = Annotated[Settings, Depends(get_app_settings)]


def _get_scan(executor: Executor, scan_id: int) -> dict:
    try:
        return executor.scans.get(scan_id)
    except NotFoundError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc


@router.get("", response_model=list[Scan])
def list_scans(
    _: AuthenticatedPrincipal,
    executor: ExecutorDep,
    project_id: int | None = None,
    scan_status: Annotated[ScanStatus | None, Query(alias="status")] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[dict]:
    """Scan history, newest first."""
    return executor.scans.list_all(project_id, scan_status, limit, offset)


@router.get("/{scan_id}", response_model=Scan)
def get_scan(scan_id: int, _: AuthenticatedPrincipal, executor: ExecutorDep) -> dict:
    return _get_scan(executor, scan_id)


@router.get("/{scan_id}/results", response_model=ScanResults)
def get_results(scan_id: int, _: AuthenticatedPrincipal, executor: ExecutorDep) -> dict:
    scan = _get_scan(executor, scan_id)
    return {"scan": scan, "hosts": executor.results.for_scan(scan_id)}


@router.post("/{scan_id}/cancel", response_model=Scan)
async def cancel_scan(
    scan_id: int, principal: AuthenticatedPrincipal, executor: ExecutorDep, jobs: JobsDep
) -> dict:
    """Cancel a queued or running scan; the tool process is terminated."""
    scan = _get_scan(executor, scan_id)
    if scan["status"] not in ACTIVE_SCAN_STATUSES:
        raise HTTPException(status.HTTP_409_CONFLICT, f"scan {scan_id} is already {scan['status']}")
    reason = f"cancelled by {principal.actor}"
    executor.audit.record(
        principal.actor, "scan.cancel_requested", scan["project_id"], scan_id=scan_id
    )
    if not await jobs.cancel(scan_id, reason):
        # Not owned by this process's job manager: just record the outcome.
        executor.scans.finish(scan_id, "cancelled", error=reason)
    return _get_scan(executor, scan_id)


def _evidence_bytes(settings: Settings, name: str) -> bytes | None:
    if Path(name).name != name or name.startswith("."):
        return None
    try:
        fd = os.open(settings.evidence_path / name, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        return None
    with os.fdopen(fd, "rb") as handle:
        return handle.read()


@router.get("/{scan_id}/evidence/verify", response_model=EvidenceVerification)
def verify_evidence(
    scan_id: int, _: AuthenticatedPrincipal, executor: ExecutorDep, settings: SettingsDep
) -> EvidenceVerification:
    """Re-hash the evidence file and compare it with the SHA-256 recorded at scan time."""
    scan = _get_scan(executor, scan_id)
    evidence = scan["evidence"]
    if evidence is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"scan {scan_id} has no evidence")
    data = _evidence_bytes(settings, evidence["file"])
    actual = hashlib.sha256(data).hexdigest() if data is not None else None
    verified = actual == evidence["sha256"]
    return EvidenceVerification(
        scan_id=scan_id,
        file=evidence["file"],
        recorded_sha256=evidence["sha256"],
        actual_sha256=actual,
        size_bytes=len(data) if data is not None else None,
        verified=verified,
        detail=(
            "evidence file matches its recorded SHA-256"
            if verified
            else "evidence file is missing"
            if data is None
            else "evidence file does NOT match its recorded SHA-256"
        ),
    )


@router.get(
    "/{scan_id}/evidence",
    response_class=Response,
    responses={200: {"content": {"application/xml": {}}}},
)
def get_evidence(
    scan_id: int, _: AuthenticatedPrincipal, executor: ExecutorDep, settings: SettingsDep
) -> Response:
    """Download the raw tool output, verified against its recorded SHA-256."""
    scan = _get_scan(executor, scan_id)
    evidence = scan["evidence"]
    if evidence is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"scan {scan_id} has no evidence")
    name = evidence["file"]
    if Path(name).name != name or name.startswith("."):
        raise HTTPException(status.HTTP_409_CONFLICT, "invalid evidence reference")
    try:
        fd = os.open(settings.evidence_path / name, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "evidence file is missing") from exc
    with os.fdopen(fd, "rb") as handle:
        data = handle.read()
    if hashlib.sha256(data).hexdigest() != evidence["sha256"]:
        raise HTTPException(
            status.HTTP_409_CONFLICT, "evidence file does not match its recorded SHA-256"
        )
    return Response(
        data,
        media_type="application/xml",
        # Download, never render: tool output contains target-controlled text. The
        # request guard also applies `default-src 'none'; sandbox` to every response.
        headers={"Content-Disposition": f'attachment; filename="{name}"'},
    )
