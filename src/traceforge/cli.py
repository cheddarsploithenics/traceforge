"""Command-line entry point.

``traceforge serve`` runs the API. Every other command is a client of that
API (authenticated with the owner-only API token), so the CLI, the TUI and
the web dashboard all go through the same backend checks.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sqlite3
import sys
from collections.abc import Sequence
from typing import TYPE_CHECKING, Any

from pydantic import ValidationError

from traceforge import __version__
from traceforge.config import Settings

if TYPE_CHECKING:
    from traceforge.client import TraceForgeClient


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="traceforge",
        description="TraceForge penetration testing orchestration platform.",
    )
    parser.add_argument("--version", action="version", version=f"traceforge {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    serve = sub.add_parser("serve", help="Run the API server (localhost only).")
    serve.add_argument("--host", help="Loopback address to bind (default: 127.0.0.1).")
    serve.add_argument("--port", type=int, help="Port to listen on (default: 8000).")
    serve.add_argument("--db", dest="db_path", help="Path to the SQLite database file.")
    serve.add_argument(
        "--reload", action="store_true", help="Restart on source changes (development only)."
    )

    client = argparse.ArgumentParser(add_help=False)
    client.add_argument("--api-url", help="Backend URL (default: http://127.0.0.1:8000).")

    sub.add_parser("tui", parents=[client], help="Launch the terminal interface.")
    sub.add_parser(
        "dashboard-link", parents=[client], help="Print a single-use dashboard sign-in link."
    )

    project = sub.add_parser("project", help="Manage projects.").add_subparsers(
        dest="action", required=True
    )
    create = project.add_parser("create", parents=[client], help="Create a project.")
    create.add_argument("name")
    create.add_argument(
        "--authorization-ref",
        required=True,
        help="Reference to the written authorization (contract, SOW, ticket id).",
    )
    create.add_argument("--authorized-from", help="ISO 8601 start of the testing window.")
    create.add_argument("--authorized-until", help="ISO 8601 end of the testing window.")
    project.add_parser("list", parents=[client], help="List projects.")

    scope = sub.add_parser("scope", help="Manage a project's authorized scope.").add_subparsers(
        dest="action", required=True
    )
    add = scope.add_parser("add", parents=[client], help="Add an include/exclude rule.")
    add.add_argument("project_id", type=int)
    add.add_argument("kind", choices=["include", "exclude"])
    add.add_argument("value", help="IP, CIDR, hostname or *.domain")
    add.add_argument("--note")
    lst = scope.add_parser("list", parents=[client], help="List scope rules.")
    lst.add_argument("project_id", type=int)
    rm = scope.add_parser("remove", parents=[client], help="Remove a scope rule.")
    rm.add_argument("project_id", type=int)
    rm.add_argument("rule_id", type=int)
    check = scope.add_parser("check", parents=[client], help="Check targets against scope.")
    check.add_argument("project_id", type=int)
    check.add_argument("targets", nargs="+")

    sub.add_parser("version", help="Print the version and exit.")
    return parser


def _load_settings(args: argparse.Namespace) -> Settings:
    overrides = {
        key: value
        for key in ("host", "port", "db_path", "api_url")
        if (value := getattr(args, key, None)) is not None
    }
    return Settings(**overrides)


def _serve(settings: Settings, *, reload: bool = False) -> int:
    import uvicorn

    from traceforge.api import create_app
    from traceforge.db import Database
    from traceforge.security.tokens import InsecureTokenFileError, ensure_private_dir

    # Fail fast with readable messages instead of lifespan tracebacks.
    try:
        Database(settings.db_path).initialize()
    except (OSError, sqlite3.Error) as exc:
        print(
            f"traceforge: cannot initialise database at {settings.db_path}: {exc}",
            file=sys.stderr,
        )
        return 1
    try:
        ensure_private_dir(settings.token_path.parent)
    except (OSError, InsecureTokenFileError) as exc:
        print(f"traceforge: unsafe token directory: {exc}", file=sys.stderr)
        return 1

    # Nothing sits in front of the API, so never trust X-Forwarded-* headers.
    options: dict[str, Any] = {"host": settings.host, "port": settings.port, "proxy_headers": False}
    if reload:
        # The reloader re-imports the app in a child process, which rebuilds its
        # settings from the environment, so export the already-validated values.
        os.environ["TRACEFORGE_HOST"] = settings.host
        os.environ["TRACEFORGE_PORT"] = str(settings.port)
        os.environ["TRACEFORGE_DB_PATH"] = str(settings.db_path)
        uvicorn.run(
            "traceforge.api.app:create_app",
            factory=True,
            reload=True,
            reload_dirs=[os.path.dirname(__file__)],
            **options,
        )
    else:
        uvicorn.run(create_app(settings), **options)
    return 0


def _make_client(settings: Settings) -> TraceForgeClient:
    from traceforge.client import TraceForgeClient, file_token_provider

    return TraceForgeClient(
        settings.base_url, token_provider=file_token_provider(settings.token_path)
    )


def _tui(settings: Settings) -> int:
    from traceforge.tui import TraceForgeApp

    TraceForgeApp(_make_client(settings)).run()
    return 0


async def _run_client_command(args: argparse.Namespace, settings: Settings) -> int:
    async with _make_client(settings) as client:
        if args.command == "dashboard-link":
            login = await client.create_login_code()
            print(f"Open within {_seconds_until(login.expires_at)} s (single use):\n{login.url}")
            return 0

        if args.command == "project" and args.action == "create":
            window = {
                key: value
                for key, value in (
                    ("authorized_from", args.authorized_from),
                    ("authorized_until", args.authorized_until),
                )
                if value
            }
            project = await client.create_project(args.name, args.authorization_ref, **window)
            print(f"Created project #{project.id} {project.name!r}. Scope is empty: add rules with")
            print(f"  traceforge scope add {project.id} include <ip|cidr|hostname>")
            return 0
        if args.command == "project":
            for p in await client.list_projects():
                window = ""
                if p.authorized_from or p.authorized_until:
                    window = f"  window {p.authorized_from or '…'} → {p.authorized_until or '…'}"
                print(
                    f"#{p.id}  {p.name}  [{p.authorization_ref}]  "
                    f"{p.scope_rule_count} rule(s){window}"
                )
            return 0

        if args.action == "add":
            rule = await client.add_scope_rule(args.project_id, args.kind, args.value, args.note)
            print(f"Added rule #{rule.id}: {rule.kind} {rule.value}")
        elif args.action == "list":
            for r in await client.list_scope(args.project_id):
                note = f"  # {r.note}" if r.note else ""
                print(f"#{r.id}  {r.kind:<7}  {r.value}{note}")
        elif args.action == "remove":
            await client.remove_scope_rule(args.project_id, args.rule_id)
            print(f"Removed rule #{args.rule_id}")
        else:  # check
            result = await client.check_scope(args.project_id, args.targets)
            for d in result.decisions:
                print(f"{'ALLOW' if d.allowed else 'DENY ':5}  {d.target}  ({d.reason})")
            return 0 if result.allowed else 1
        return 0


def _seconds_until(moment: Any) -> int:
    from datetime import UTC, datetime

    return max(0, int((moment - datetime.now(UTC)).total_seconds()))


def _client_command(args: argparse.Namespace, settings: Settings) -> int:
    from traceforge.client import ApiError, AuthenticationError, BackendUnavailableError

    try:
        return asyncio.run(_run_client_command(args, settings))
    except (AuthenticationError, BackendUnavailableError) as exc:
        print(f"traceforge: {exc}", file=sys.stderr)
        return 1
    except ApiError as exc:
        print(f"traceforge: request failed ({exc.status_code}): {exc.detail}", file=sys.stderr)
        return 1


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    if args.command == "version":
        print(f"traceforge {__version__}")
        return 0

    try:
        settings = _load_settings(args)
    except ValidationError as exc:
        for error in exc.errors():
            print(f"traceforge: configuration error: {error['msg']}", file=sys.stderr)
        return 2

    if args.command == "serve":
        return _serve(settings, reload=args.reload)
    if args.command == "tui":
        return _tui(settings)
    return _client_command(args, settings)


if __name__ == "__main__":
    raise SystemExit(main())
