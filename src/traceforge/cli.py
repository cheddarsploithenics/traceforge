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

    scan = sub.add_parser("scan", help="Run and inspect scans.").add_subparsers(
        dest="action", required=True
    )
    run = scan.add_parser(
        "run",
        parents=[client],
        help="Queue an Nmap TCP connect scan of authorized targets.",
        description="Every target must be inside the project's authorized scope. "
        "Hostnames are resolved once, checked, and scanned by IP address.",
    )
    run.add_argument("project_id", type=int)
    run.add_argument("targets", nargs="+", help="IP, CIDR or hostname (must be in scope)")
    ports = run.add_mutually_exclusive_group()
    ports.add_argument("-p", "--ports", help="Port list, e.g. 22,80,443 or 1-1024")
    ports.add_argument("--top-ports", type=int, help="Scan the N most common ports")
    run.add_argument(
        "--no-version", action="store_true", help="Skip service/version detection (-sV)"
    )
    run.add_argument("--timing", type=int, choices=[2, 3, 4], help="Timing template (default 3)")
    run.add_argument(
        "-Pn", "--skip-host-discovery", action="store_true", help="Treat all hosts as online"
    )
    run.add_argument("--timeout", type=int, help="Kill the scan after this many seconds")
    run.add_argument("--wait", action="store_true", help="Wait for the scan and print results")
    lst_scans = scan.add_parser("list", parents=[client], help="Scan history, newest first.")
    lst_scans.add_argument("--project", type=int, dest="project_id")
    lst_scans.add_argument(
        "--status", choices=["queued", "running", "completed", "failed", "cancelled"]
    )
    lst_scans.add_argument("--limit", type=int, default=20)
    show = scan.add_parser("show", parents=[client], help="Show a scan's status and results.")
    show.add_argument("scan_id", type=int)
    cancel = scan.add_parser("cancel", parents=[client], help="Cancel a queued or running scan.")
    cancel.add_argument("scan_id", type=int)

    compare = scan.add_parser(
        "compare",
        parents=[client],
        help="Compare two completed scans of the same project.",
        description="Lists confirmed changes (added/removed/changed) and inconclusive "
        "observations (not scanned, host timed out, filtered, unknown coverage).",
    )
    compare.add_argument("baseline", type=int, help="earlier scan id (A)")
    compare.add_argument("comparison", type=int, help="later scan id (B)")

    asset = sub.add_parser("asset", help="Browse the asset inventory.").add_subparsers(
        dest="action", required=True
    )
    asset_list = asset.add_parser("list", parents=[client], help="List discovered assets.")
    asset_list.add_argument("--project", type=int, dest="project_id")
    asset_list.add_argument("--search", help="address, hostname, service, product or port")
    asset_list.add_argument(
        "--all", action="store_true", help="include hosts that never answered (-Pn)"
    )
    asset_show = asset.add_parser(
        "show", parents=[client], help="Show an asset's ports and history."
    )
    asset_show.add_argument("uid", help="asset id, e.g. ast_1a2b3c4d5e6f7a8b")

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

        if args.command == "scan":
            return await _run_scan_command(client, args)
        if args.command == "asset":
            return await _run_asset_command(client, args)

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


TERMINAL_STATUSES = ("completed", "failed", "cancelled")


async def _run_scan_command(client: TraceForgeClient, args: argparse.Namespace) -> int:
    if args.action == "run":
        options: dict[str, Any] = {"service_detection": not args.no_version}
        for key in ("ports", "top_ports", "timing"):
            if (value := getattr(args, key)) is not None:
                options[key] = value
        if args.skip_host_discovery:
            options["skip_host_discovery"] = True
        launched = await client.launch_scan(
            args.project_id, "nmap", args.targets, options=options, timeout_seconds=args.timeout
        )
        print(f"Queued scan #{launched.scan_id} of {', '.join(launched.scan_addresses)}")
        if not args.wait:
            print(f"  traceforge scan show {launched.scan_id}")
            return 0
        while (scan := await client.get_scan(launched.scan_id)).status not in TERMINAL_STATUSES:
            await asyncio.sleep(1.0)
        await _print_scan(client, scan.id)
        return 0 if scan.status == "completed" else 1

    if args.action == "list":
        scans = await client.list_scans(args.project_id, args.status, args.limit)
        if not scans:
            print("No scans yet.")
        for s in scans:
            print(
                f"#{s.id:<4} {s.status:<9}  project {s.project_id}  {s.tool}  "
                f"{s.open_ports} open port(s)  {', '.join(s.targets)}  "
                f"({s.created_at:%Y-%m-%d %H:%M})"
            )
        return 0

    if args.action == "cancel":
        scan = await client.cancel_scan(args.scan_id)
        print(f"Scan #{scan.id} {scan.status}")
        return 0

    if args.action == "compare":
        base, other = await client.get_scan(args.baseline), await client.get_scan(args.comparison)
        if base.project_id is None or base.project_id != other.project_id:
            print("traceforge: both scans must belong to the same project", file=sys.stderr)
            return 1
        result = await client.compare_scans(base.project_id, args.baseline, args.comparison)
        _print_comparison(result)
        return 0

    await _print_scan(client, args.scan_id)
    return 0


_CATEGORY_LABELS = {
    "added": "ADDED",
    "removed": "REMOVED",
    "changed": "CHANGED",
    "inconclusive": "INCONCLUSIVE",
}


def _print_comparison(result: Any) -> None:
    a, b, summary = result.baseline, result.comparison, result.summary
    print(f"Scan #{a.scan_id} → #{b.scan_id}  (project {result.project_id})")
    for label, side in (("baseline  ", a), ("comparison", b)):
        ports = ", ".join(f"{k} {v}" for k, v in (side.ports_scanned or {}).items()) or "unknown"
        flags = " ".join(
            f for f, on in (("-Pn", not side.host_discovery), ("-sV", side.service_detection)) if on
        )
        print(f"  {label}  #{side.scan_id}  ports {ports}  {flags}")
    print(
        f"  {summary.added} added · {summary.removed} removed · {summary.changed} changed · "
        f"{summary.inconclusive} inconclusive · "
        f"{summary.unchanged_open_ports} open port(s) unchanged"
    )
    for note in result.notes:
        print(f"  note: {note}")
    if not result.changes:
        print("\nNo differences.")
    current = None
    for change in result.changes:
        if change.category != current:
            current = change.category
            print(f"\n{_CATEGORY_LABELS[current]}")
        where = change.address + (f" {change.port}/{change.protocol}" if change.port else "")
        print(f"  {where:<28} {change.kind:<26} {change.detail}")


async def _run_asset_command(client: TraceForgeClient, args: argparse.Namespace) -> int:
    if args.action == "list":
        assets = await client.list_assets(
            args.project_id, args.search, include_unconfirmed=args.all
        )
        if not assets:
            print("No assets yet. Run a scan: traceforge scan run PROJECT TARGET --wait")
        for a in assets:
            names = f" ({', '.join(a.hostnames)})" if a.hostnames else ""
            services = ", ".join(f"{s.port}/{s.service_name or '?'}" for s in a.services)
            print(
                f"{a.uid}  {a.address}{names}  [{a.project_name}]  "
                f"{a.open_ports} open: {services or '-'}  last seen {a.last_seen:%Y-%m-%d %H:%M}"
                + ("" if a.confirmed else "  (never answered)")
            )
        return 0

    asset = await client.get_asset(args.uid)
    names = f" ({', '.join(asset.hostnames)})" if asset.hostnames else ""
    print(f"{asset.uid}  {asset.address}{names}  project {asset.project_name}")
    print(f"  first seen {asset.first_seen}   last seen {asset.last_seen}")
    print(f"\n{'PORT':<10} {'STATE':<9} {'SERVICE':<14} {'ID':<11} {'VERSION':<30} LAST CHECKED")
    for p in asset.ports:
        version = " ".join(v for v in (p.service_product, p.service_version) if v)
        print(
            f"{p.port}/{p.protocol:<6} {p.state:<9} {p.service_name or '':<14} "
            f"{p.identification or '':<11} {version:<30} {p.last_seen:%Y-%m-%d %H:%M} "
            f"(scan #{p.state_scan_id})"
        )
    print("\nOBSERVATIONS (newest first)")
    for o in asset.observations:
        prov = o.provenance
        evidence = (
            f"{prov.evidence.file} sha256 {prov.evidence.sha256[:16]}…" if prov.evidence else "-"
        )
        print(
            f"  scan #{o.scan_id}  {o.observed_at:%Y-%m-%d %H:%M:%S}  "
            f"{prov.tool} {prov.tool_version}  "
            f"requested {', '.join(prov.requested_targets) or '-'} → {prov.scanned_address}  "
            f"{len([p for p in o.ports if p.state == 'open'])} open  evidence {evidence}"
        )
    return 0


async def _print_scan(client: TraceForgeClient, scan_id: int) -> None:
    results = await client.get_scan_results(scan_id)
    scan = results.scan
    print(f"Scan #{scan.id}  {scan.tool}  {scan.status.upper()}  (project {scan.project_id})")
    print(f"  targets:  {', '.join(scan.targets)}")
    print(f"  scanned:  {', '.join(scan.scan_addresses)}")
    print(f"  command:  {' '.join(scan.command)}")
    print(
        f"  created:  {scan.created_at}  started: {scan.started_at}  finished: {scan.finished_at}"
    )
    if scan.error:
        print(f"  error:    {scan.error}")
    if scan.evidence:
        print(f"  evidence: {scan.evidence.file}  sha256 {scan.evidence.sha256}")
    if scan.status in TERMINAL_STATUSES and not results.hosts:
        print("\nNo hosts found.")
    if results.hosts:
        print(f"\n{'HOST':<40} {'PORT':<10} {'STATE':<10} {'SERVICE':<14} VERSION")
    for host in results.hosts:
        label = host.address + (f" ({', '.join(host.hostnames)})" if host.hostnames else "")
        if not host.ports:
            print(f"{label:<40} {'-':<10} {host.state:<10}")
        for p in host.ports:
            version = " ".join(
                v for v in (p.service_product, p.service_version, p.service_extrainfo) if v
            )
            port = f"{p.port}/{p.protocol}"
            print(f"{label:<40} {port:<10} {p.state:<10} {p.service_name or '':<14} {version}")


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
        detail = exc.detail
        if isinstance(detail, dict) and "decisions" in detail:
            print(f"traceforge: {detail.get('message', 'denied')}", file=sys.stderr)
            for d in detail["decisions"]:
                verdict = "ALLOW" if d.get("allowed") else "DENY "
                print(f"  {verdict}  {d.get('target')}  ({d.get('reason')})", file=sys.stderr)
        else:
            print(f"traceforge: request failed ({exc.status_code}): {detail}", file=sys.stderr)
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
