"""FastAPI dependencies that expose application-scoped services to routes."""

from __future__ import annotations

from fastapi import Request

from traceforge.config import Settings
from traceforge.db import Database
from traceforge.execution.executor import Executor


def get_database(request: Request) -> Database:
    return request.app.state.database


def get_app_settings(request: Request) -> Settings:
    return request.app.state.settings


def get_executor(request: Request) -> Executor:
    return request.app.state.executor
