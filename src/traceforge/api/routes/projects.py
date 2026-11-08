"""Projects, their authorized scope, and scan launches."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Response, status

from traceforge.api.deps import get_executor
from traceforge.db.repositories import ConflictError, NotFoundError
from traceforge.execution.executor import (
    AuthorizationWindowError,
    Executor,
    InvalidOptionsError,
    ToolUnavailableError,
)
from traceforge.execution.jobs import QueueFullError
from traceforge.execution.scope import InvalidTargetError, ScopeViolationError, parse_scope_rule
from traceforge.schemas import (
    Project,
    ProjectCreate,
    ScanLaunch,
    ScanLaunchResult,
    ScopeCheckResponse,
    ScopeDecisionDetail,
    ScopeRule,
    ScopeRuleCreate,
    TargetList,
)
from traceforge.security.auth import AuthenticatedPrincipal

router = APIRouter(prefix="/api/v1/projects", tags=["projects"])
ExecutorDep = Annotated[Executor, Depends(get_executor)]


def _not_found(exc: NotFoundError) -> HTTPException:
    return HTTPException(status.HTTP_404_NOT_FOUND, str(exc))


@router.get("", response_model=list[Project])
def list_projects(_: AuthenticatedPrincipal, executor: ExecutorDep) -> list[dict]:
    return executor.projects.list_all()


@router.post("", response_model=Project, status_code=status.HTTP_201_CREATED)
def create_project(
    body: ProjectCreate, principal: AuthenticatedPrincipal, executor: ExecutorDep
) -> dict:
    try:
        project = executor.projects.create(
            body.name, body.authorization_ref, body.authorized_from, body.authorized_until
        )
    except ConflictError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    executor.audit.record(
        principal.actor, "project.created", project["id"], **body.model_dump(mode="json")
    )
    return project


@router.get("/{project_id}", response_model=Project)
def get_project(project_id: int, _: AuthenticatedPrincipal, executor: ExecutorDep) -> dict:
    try:
        return executor.projects.get(project_id)
    except NotFoundError as exc:
        raise _not_found(exc) from exc


@router.get("/{project_id}/scope", response_model=list[ScopeRule])
def list_scope(project_id: int, _: AuthenticatedPrincipal, executor: ExecutorDep) -> list[dict]:
    try:
        executor.projects.get(project_id)
    except NotFoundError as exc:
        raise _not_found(exc) from exc
    return executor.scope.list_all(project_id)


@router.post("/{project_id}/scope", response_model=ScopeRule, status_code=201)
def add_scope_rule(
    project_id: int,
    body: ScopeRuleCreate,
    principal: AuthenticatedPrincipal,
    executor: ExecutorDep,
) -> dict:
    try:
        executor.projects.get(project_id)
        rule = parse_scope_rule(body.kind, body.value)
        row = executor.scope.add(project_id, rule.kind, rule.value, body.note)
    except NotFoundError as exc:
        raise _not_found(exc) from exc
    except InvalidTargetError as exc:
        raise HTTPException(422, str(exc)) from exc
    except ConflictError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    executor.audit.record(
        principal.actor,
        "scope.added",
        project_id,
        rule_id=row["id"],
        kind=rule.kind,
        value=rule.value,
    )
    return row


@router.delete("/{project_id}/scope/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_scope_rule(
    project_id: int, rule_id: int, principal: AuthenticatedPrincipal, executor: ExecutorDep
) -> Response:
    try:
        row = executor.scope.delete(project_id, rule_id)
    except NotFoundError as exc:
        raise _not_found(exc) from exc
    executor.audit.record(
        principal.actor,
        "scope.removed",
        project_id,
        rule_id=rule_id,
        kind=row["kind"],
        value=row["value"],
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/{project_id}/scope/check", response_model=ScopeCheckResponse)
async def check_scope(
    project_id: int, body: TargetList, _: AuthenticatedPrincipal, executor: ExecutorDep
) -> ScopeCheckResponse:
    """Dry run: evaluate targets against scope without launching anything."""
    try:
        decisions = await executor.check(project_id, body.targets)
    except NotFoundError as exc:
        raise _not_found(exc) from exc
    except InvalidTargetError as exc:
        raise HTTPException(422, str(exc)) from exc
    return ScopeCheckResponse(
        allowed=all(d.allowed for d in decisions),
        decisions=[ScopeDecisionDetail(**vars(d)) for d in decisions],
    )


def _decision(d) -> dict:
    return {**vars(d), "addresses": list(d.addresses)}


@router.post("/{project_id}/scans", response_model=ScanLaunchResult, status_code=202)
async def launch_scan(
    project_id: int, body: ScanLaunch, principal: AuthenticatedPrincipal, executor: ExecutorDep
) -> ScanLaunchResult:
    """Authorize targets against the project's scope and queue a scan.

    Returns ``202`` immediately; poll ``GET /api/v1/scans/{scan_id}`` for progress.
    """
    try:
        result = await executor.launch(
            project_id,
            body.tool,
            body.targets,
            actor=principal.actor,
            options=body.options,
            timeout_seconds=body.timeout_seconds,
        )
    except NotFoundError as exc:
        raise _not_found(exc) from exc
    except ScopeViolationError as exc:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            {
                "message": "Targets outside authorized scope; nothing was launched",
                "decisions": [_decision(d) for d in exc.decisions],
            },
        ) from exc
    except AuthorizationWindowError as exc:
        raise HTTPException(status.HTTP_403_FORBIDDEN, str(exc)) from exc
    except (InvalidTargetError, InvalidOptionsError) as exc:
        raise HTTPException(422, str(exc)) from exc
    except ToolUnavailableError as exc:
        raise HTTPException(status.HTTP_501_NOT_IMPLEMENTED, str(exc)) from exc
    except QueueFullError as exc:
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, str(exc)) from exc
    return ScanLaunchResult(
        scan_id=result.scan_id,
        tool=result.tool,
        targets=result.targets,
        scan_addresses=result.scan_addresses,
    )
