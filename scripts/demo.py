"""Prepare a safe local demo of TraceForge scanning.

* creates (or reuses) a "Local lab" project whose only scope is 127.0.0.1/32;
* prints a single-use dashboard sign-in link;
* runs a fake SSH service on 127.0.0.1 so there is something to scan.

Nothing leaves the loopback interface. ``make demo`` uses this module through
``scripts/run_local.py``, which also starts the API and dashboard. To add the
demo to an API that is already running: ``.venv/bin/python scripts/demo.py [--port N]``.
"""

from __future__ import annotations

import argparse
import asyncio
import socket
import sys
import time

from traceforge.client import (
    ApiError,
    AuthenticationError,
    BackendUnavailableError,
    TraceForgeClient,
    file_token_provider,
)
from traceforge.config import Settings

PROJECT_NAME = "Local lab"
AUTHORIZATION_REF = "LAB-DEMO (loopback only)"
SCOPE = "127.0.0.1/32"
BANNER = b"SSH-2.0-OpenSSH_9.6p1 Debian-3\r\n"


async def prepare(client: TraceForgeClient) -> tuple[int, str]:
    """Idempotently set up the demo project and scope; return (project id, sign-in URL)."""
    project = next((p for p in await client.list_projects() if p.name == PROJECT_NAME), None)
    if project is None:
        project = await client.create_project(PROJECT_NAME, AUTHORIZATION_REF)
    rules = await client.list_scope(project.id)
    if not any(r.kind == "include" and r.value == SCOPE for r in rules):
        await client.add_scope_rule(project.id, "include", SCOPE, "TraceForge demo")
    login = await client.create_login_code()
    return project.id, login.url


def open_listener(port: int) -> socket.socket:
    # Hard-coded loopback: the demo service is never reachable from the network.
    return socket.create_server(("127.0.0.1", port))


def serve_banner(server: socket.socket) -> None:
    server.settimeout(0.5)  # wake up regularly so Ctrl+C is handled promptly
    while True:
        try:
            conn, _ = server.accept()
        except TimeoutError:
            continue
        except OSError:
            return  # listener closed: stop serving
        with conn:
            try:
                conn.sendall(BANNER)
                time.sleep(0.3)
            except OSError:
                pass  # scanners often reset the connection; that's fine


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "--port", type=int, default=2222, help="Loopback port for the fake SSH service"
    )
    parser.add_argument("--api-url", help="TraceForge API URL (default: http://127.0.0.1:8000)")
    args = parser.parse_args(argv)

    settings = Settings(**({"api_url": args.api_url} if args.api_url else {}))
    try:
        listener = open_listener(args.port)
    except OSError as exc:
        print(f"demo: cannot listen on 127.0.0.1:{args.port}: {exc} (try --port)", file=sys.stderr)
        return 1

    async def setup() -> tuple[int, str]:
        client = TraceForgeClient(
            settings.base_url, token_provider=file_token_provider(settings.token_path)
        )
        async with client:
            return await prepare(client)

    try:
        project_id, url = asyncio.run(setup())
    except (AuthenticationError, BackendUnavailableError) as exc:
        listener.close()
        print(f"demo: {exc}\nStart the API first:  make api", file=sys.stderr)
        return 1
    except ApiError as exc:
        listener.close()
        print(f"demo: API error ({exc.status_code}): {exc.detail}", file=sys.stderr)
        return 1

    port = args.port
    print(
        f"""
Demo ready (everything stays on 127.0.0.1).

  Project #{project_id} "{PROJECT_NAME}" authorizes {SCOPE}
  Fake SSH service listening on 127.0.0.1:{port}

  Dashboard (start it with `make web`), single-use link, valid 5 minutes:
    {url}
  Then: Scans -> New scan -> target 127.0.0.1, ports {port},{port + 1}

  Or from a terminal:
    traceforge scan run {project_id} 127.0.0.1 -p {port},{port + 1} --wait

Press Ctrl+C to stop the service.
""",
        flush=True,
    )
    try:
        serve_banner(listener)
    except KeyboardInterrupt:
        print("\nDemo service stopped.")
    finally:
        listener.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
