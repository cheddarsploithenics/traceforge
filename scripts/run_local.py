"""Run TraceForge locally from a single terminal.

Starts the API and the web dashboard, waits until both respond, prints a
single-use sign-in link, and streams both logs with ``[api]`` / ``[web]``
prefixes. Ctrl+C stops everything (running scans are cancelled cleanly).

    make run                      # API + dashboard (dev server)
    make demo                     # ... plus a loopback-only demo project and target
    python scripts/run_local.py --prod --api-port 8001

Everything listens on 127.0.0.1 only; the security model is unchanged: the
dashboard is still served by Vite and proxies the API same-origin.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

import httpx

from traceforge.client import TraceForgeClient, file_token_provider
from traceforge.config import Settings

ROOT = Path(__file__).resolve().parent.parent
WEB = ROOT / "web"
DEV_PORT, PREVIEW_PORT = 5173, 4173  # fixed in web/vite.config.ts (strictPort)
STARTUP_TIMEOUT = 60.0

_print_lock = threading.Lock()
_COLORS = {"api": "\033[36m", "web": "\033[35m", "demo": "\033[33m"}
_USE_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def say(message: str = "", source: str | None = None) -> None:
    with _print_lock:
        if source is None:
            print(message, flush=True)
            return
        tag = f"[{source}]"
        if _USE_COLOR:
            tag = f"{_COLORS.get(source, '')}{tag}\033[0m"
        print(f"{tag} {message}", flush=True)


class LaunchError(RuntimeError):
    """A precondition failed; the message tells the user what to do."""


# --------------------------------------------------------------------------- plan


@dataclass
class Plan:
    api_port: int
    web_port: int
    prod: bool
    demo: bool
    demo_port: int
    env: dict[str, str] = field(default_factory=dict)

    @property
    def api_url(self) -> str:
        return f"http://127.0.0.1:{self.api_port}"

    @property
    def dashboard_url(self) -> str:
        return f"http://127.0.0.1:{self.web_port}"

    def api_command(self) -> list[str]:
        return [sys.executable, "-m", "traceforge", "serve", "--port", str(self.api_port)]

    def web_command(self, npm: str) -> list[str]:
        return [npm, "run", "preview" if self.prod else "dev"]

    def settings(self) -> Settings:
        return Settings(port=self.api_port, api_url=self.api_url, dashboard_url=self.dashboard_url)


def make_plan(args: argparse.Namespace, base_env: dict[str, str] | None = None) -> Plan:
    plan = Plan(
        api_port=args.api_port,
        web_port=PREVIEW_PORT if args.prod else DEV_PORT,
        prod=args.prod,
        demo=args.demo,
        demo_port=args.demo_port,
    )
    env = dict(os.environ if base_env is None else base_env)
    env.update(
        {
            "TRACEFORGE_PORT": str(plan.api_port),
            # Used by the TUI/CLI and by the Vite proxy to reach the API.
            "TRACEFORGE_API_URL": plan.api_url,
            # Sign-in links must point at whichever dashboard server runs.
            "TRACEFORGE_DASHBOARD_URL": plan.dashboard_url,
        }
    )
    plan.env = env
    return plan


# --------------------------------------------------------------------------- checks


def port_in_use(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.settimeout(0.5)
        return probe.connect_ex(("127.0.0.1", port)) == 0


def preflight(plan: Plan) -> str:
    """Check everything up front; return the npm executable."""
    npm = shutil.which("npm")
    if npm is None:
        raise LaunchError("npm was not found. Install Node.js 22.22+ or 24, then run: make install")
    if not (WEB / "node_modules").is_dir():
        raise LaunchError("dashboard dependencies are missing. Run: make install")
    busy = [
        (port, what)
        for port, what in (
            (plan.api_port, "API (use --api-port to pick another)"),
            (plan.web_port, "dashboard"),
            *([(plan.demo_port, "demo service (use --demo-port)")] if plan.demo else []),
        )
        if port_in_use(port)
    ]
    if busy:
        lines = "\n".join(f"  127.0.0.1:{port} ({what})" for port, what in busy)
        raise LaunchError(
            f"these ports are already in use:\n{lines}\n"
            "Is TraceForge already running in another terminal? Stop it first."
        )
    if shutil.which("nmap") is None and plan.settings().nmap_path is None:
        say("warning: nmap is not installed; scans will fail (sudo apt install nmap)")
    return npm


# --------------------------------------------------------------------------- processes


class Child:
    """A child process in its own process group, with prefixed output."""

    def __init__(
        self,
        name: str,
        argv: list[str],
        *,
        cwd: Path,
        env: dict[str, str],
        hide: tuple[str, ...] = (),
    ) -> None:
        self.name = name
        self.hide = hide
        self.process = subprocess.Popen(
            argv,
            cwd=cwd,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            start_new_session=True,  # Ctrl+C reaches us; we stop children in order
        )
        threading.Thread(target=self._pump, daemon=True).start()

    def _pump(self) -> None:
        assert self.process.stdout is not None
        for line in self.process.stdout:
            if not any(marker in line for marker in self.hide):
                say(line.rstrip(), self.name)

    @property
    def exited(self) -> bool:
        return self.process.poll() is not None

    def stop(self, sig: signal.Signals = signal.SIGTERM, grace: float = 10.0) -> None:
        if self.exited:
            return
        try:
            os.killpg(self.process.pid, sig)
            self.process.wait(timeout=grace)
        except subprocess.TimeoutExpired:
            os.killpg(self.process.pid, signal.SIGKILL)
            self.process.wait()
        except ProcessLookupError:
            pass


def wait_until_ready(url: str, child: Child, what: str, timeout: float = STARTUP_TIMEOUT) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if child.exited:
            raise LaunchError(
                f"the {what} exited during startup (see the [{child.name}] log above)"
            )
        try:
            if httpx.get(url, timeout=1.0).status_code < 500:
                return
        except httpx.HTTPError:
            pass
        time.sleep(0.25)
    raise LaunchError(f"the {what} did not become ready within {timeout:.0f} s")


async def sign_in_link(plan: Plan, demo: bool) -> tuple[str, int | None]:
    settings = plan.settings()
    client = TraceForgeClient(
        settings.base_url, token_provider=file_token_provider(settings.token_path)
    )
    async with client:
        project_id = None
        if demo:
            from demo import prepare  # scripts/demo.py

            project_id, url = await prepare(client)
            return url, project_id
        login = await client.create_login_code()
        return login.url, project_id


def banner(plan: Plan, url: str, project_id: int | None) -> str:
    mode = "production build (strict CSP)" if plan.prod else "development server"
    lines = [
        "",
        "─" * 72,
        f"  TraceForge is running   ·   API {plan.api_url}   ·   dashboard: {mode}",
        "",
        "  Open this sign-in link (single use, valid 5 minutes):",
        f"    {url}",
        "  Need a new one?  "
        + (
            "make link"
            if plan.api_port == 8000
            else f".venv/bin/traceforge dashboard-link --api-url {plan.api_url}"
        ),
    ]
    if plan.demo:
        lines += [
            "",
            f'  Demo: project #{project_id} "Local lab" authorizes 127.0.0.1/32 and a fake',
            f"  SSH service listens on 127.0.0.1:{plan.demo_port}. In the dashboard:",
            f"  Scans → New scan → target 127.0.0.1, ports {plan.demo_port},{plan.demo_port + 1}.",
        ]
    lines += ["", "  Press Ctrl+C to stop.", "─" * 72, ""]
    return "\n".join(lines)


# --------------------------------------------------------------------------- main


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the TraceForge API and dashboard together.")
    parser.add_argument("--api-port", type=int, default=8000)
    parser.add_argument(
        "--prod",
        action="store_true",
        help="build the dashboard and serve it with the hardened preview server (port 4173)",
    )
    parser.add_argument(
        "--demo", action="store_true", help="add a loopback-only demo project and target"
    )
    parser.add_argument("--demo-port", type=int, default=2222)
    return parser.parse_args(argv)


STOP_SIGNALS = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)


def _request_stop(signum: int, _frame: object) -> None:
    raise KeyboardInterrupt


def run(argv: list[str] | None = None) -> int:
    plan = make_plan(parse_args(argv))
    # Ctrl+C, `kill` and closing the terminal all take the same orderly path.
    # Installed explicitly: a SIGINT ignored by a parent shell would otherwise
    # leave the launcher unstoppable except by signals that orphan its children.
    for sig in STOP_SIGNALS:
        signal.signal(sig, _request_stop)
    children: list[Child] = []
    demo_listener: socket.socket | None = None
    try:
        npm = preflight(plan)
        if plan.prod:
            say("building the dashboard…", "web")
            build = subprocess.run([npm, "run", "build"], cwd=WEB, env=plan.env, check=False)
            if build.returncode != 0:
                raise LaunchError("the dashboard build failed")

        # The API prints its own startup sign-in link; the banner below shows
        # the one to use, so hide that line rather than show two links.
        api = Child(
            "api", plan.api_command(), cwd=ROOT, env=plan.env, hide=("Dashboard sign-in link",)
        )
        children.append(api)
        wait_until_ready(f"{plan.api_url}/health", api, "API")

        web = Child("web", plan.web_command(npm), cwd=WEB, env=plan.env)
        children.append(web)
        wait_until_ready(plan.dashboard_url, web, "dashboard")

        if plan.demo:
            from demo import open_listener, serve_banner  # scripts/demo.py

            demo_listener = open_listener(plan.demo_port)
            threading.Thread(target=serve_banner, args=(demo_listener,), daemon=True).start()

        url, project_id = asyncio.run(sign_in_link(plan, plan.demo))
        say(banner(plan, url, project_id))

        while not any(child.exited for child in children):
            time.sleep(0.5)
        crashed = next(child for child in children if child.exited)
        raise LaunchError(f"the [{crashed.name}] process stopped unexpectedly")
    except KeyboardInterrupt:
        say("\nstopping…")
        return 0
    except LaunchError as exc:
        say(f"traceforge: {exc}")
        return 1
    finally:
        for sig in STOP_SIGNALS:  # don't let a second Ctrl+C abort the cleanup
            signal.signal(sig, signal.SIG_IGN)
        if demo_listener is not None:
            demo_listener.close()
        # Dashboard first, then the API with SIGINT so it shuts down gracefully
        # (cancelling running scans and removing its token file).
        for child in reversed(children):
            child.stop(signal.SIGINT if child.name == "api" else signal.SIGTERM)


if __name__ == "__main__":
    raise SystemExit(run())
