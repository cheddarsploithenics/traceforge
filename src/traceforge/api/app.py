"""Application factory for the TraceForge API."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from traceforge import __version__
from traceforge.api.routes import assets, auth, health, projects, scans
from traceforge.config import Settings, get_settings
from traceforge.db import Database
from traceforge.execution.executor import Executor, Runner
from traceforge.execution.jobs import ScanJobManager
from traceforge.execution.nmap import NmapAdapter, parse_nmap_xml
from traceforge.execution.scope import Resolver, system_resolver
from traceforge.execution.tools import ToolRegistry
from traceforge.inventory.store import backfill_scans
from traceforge.security.guard import LocalRequestGuard
from traceforge.security.sessions import SessionStore
from traceforge.security.tokens import generate_secret, remove_token_file, write_token_file

logger = logging.getLogger("uvicorn.error")

DOCS_PATHS = ("/docs", "/openapi.json")


def create_app(
    settings: Settings | None = None,
    *,
    tools: ToolRegistry | None = None,
    runner: Runner | None = None,
    resolver: Resolver = system_resolver,
) -> FastAPI:
    """Build a configured FastAPI application.

    ``tools``, ``runner`` and ``resolver`` are injection points for tests. By
    default the Nmap adapter is registered and scans run in a background
    :class:`ScanJobManager`.
    """
    settings = settings or get_settings()
    database = Database(settings.db_path)
    api_token = generate_secret()
    sessions = SessionStore(
        session_ttl=settings.session_ttl_seconds,
        login_code_ttl=settings.login_code_ttl_seconds,
    )
    if tools is None:
        tools = ToolRegistry(
            [NmapAdapter(settings.nmap_path, max_addresses=settings.scan_max_addresses)]
        )
    jobs = ScanJobManager(
        database,
        evidence_dir=settings.evidence_path,
        max_concurrent=settings.scan_max_concurrent,
        max_queued=settings.scan_max_queued,
        max_output_bytes=settings.scan_max_output_bytes,
    )

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        database.initialize()
        if interrupted := jobs.recover():
            logger.warning("Marked %d interrupted scan(s) as failed", len(interrupted))
        # Re-read older scans' evidence (hash-verified) to build the asset inventory.
        counts = backfill_scans(database, settings.evidence_path, {"nmap": parse_nmap_xml})
        if counts["scans"]:
            logger.info(
                "Asset inventory: updated %d earlier scan(s) (%d re-read from verified evidence, "
                "%d with unverifiable evidence and unknown coverage)",
                counts["scans"],
                counts["reparsed"],
                counts["unverifiable"],
            )
        token_path = settings.token_path
        write_token_file(token_path, api_token)
        code, _ = sessions.issue_login_code()
        logger.info("API token written to %s (owner-only)", token_path)
        logger.info(
            "Dashboard sign-in link (single use, expires in %d s): %s/#code=%s",
            settings.login_code_ttl_seconds,
            settings.dashboard_url,
            code,
        )
        try:
            yield
        finally:
            await jobs.shutdown()
            remove_token_file(token_path, api_token)

    app = FastAPI(
        title="TraceForge API",
        version=__version__,
        description="Backend for the TraceForge web dashboard and terminal interface.",
        lifespan=lifespan,
        docs_url="/docs" if settings.enable_docs else None,
        redoc_url=None,
        openapi_url="/openapi.json" if settings.enable_docs else None,
    )
    app.state.settings = settings
    app.state.database = database
    app.state.api_token = api_token
    app.state.sessions = sessions
    app.state.jobs = jobs
    app.state.executor = Executor(
        database,
        tools=tools,
        runner=runner or jobs,
        resolver=resolver,
        default_timeout_seconds=settings.scan_default_timeout_seconds,
        max_timeout_seconds=settings.scan_max_timeout_seconds,
    )

    app.add_middleware(
        LocalRequestGuard,
        port=settings.port,
        allowed_origins=settings.allowed_origins,
        extra_hosts=[settings.host],
        csp_exempt_paths=DOCS_PATHS if settings.enable_docs else (),
    )

    app.include_router(health.router)
    app.include_router(auth.router)
    app.include_router(projects.router)
    app.include_router(scans.router)
    app.include_router(assets.router)
    return app
