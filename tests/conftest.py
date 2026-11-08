from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import shutil
import socket
import sys
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from traceforge.api import create_app
from traceforge.config import Settings

BASE_URL = "http://127.0.0.1:8000"
DASHBOARD_ORIGIN = "http://127.0.0.1:5173"

# Deterministic DNS for scope tests; nothing ever touches the network.
FAKE_DNS = {
    "app.example.com": ["93.184.216.34"],
    "www.example.com": ["93.184.216.35", "2606:2800:220:1::1"],
    "intranet.example.com": ["10.20.0.5"],
    "staging.example.com": ["203.0.113.50"],
    "rebind.example.com": ["127.0.0.1"],
}


def fake_resolver(hostname: str) -> list:
    if hostname not in FAKE_DNS:
        raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")
    return [ipaddress.ip_address(a) for a in FAKE_DNS[hostname]]


@pytest.fixture(autouse=True)
def _isolate_environment(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Keep tests from reading the developer's TRACEFORGE_* vars or real directories."""
    names = [n for n in os.environ if n.startswith("TRACEFORGE_")]
    names += ["TRACEFORGE_HOST", "TRACEFORGE_PORT", "TRACEFORGE_DB_PATH", "XDG_RUNTIME_DIR"]
    for var in set(names):
        # setenv first so monkeypatch records the original state even when the
        # variable is unset; anything a test writes to os.environ is then undone.
        monkeypatch.setenv(var, "")
        monkeypatch.delenv(var)
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))


def _real_nmap_binaries() -> set[str]:
    found = {
        os.path.realpath(p) for p in ("/usr/lib/nmap/nmap", "/usr/bin/nmap") if os.path.exists(p)
    }
    if which := shutil.which("nmap"):
        found.add(os.path.realpath(which))
    return found


REAL_NMAP = _real_nmap_binaries()


def _is_loopback_target(value: str) -> bool:
    try:
        return ipaddress.ip_network(value, strict=False).network_address.is_loopback and (
            ipaddress.ip_network(value, strict=False).num_addresses == 1
        )
    except ValueError:
        return False


@pytest.fixture(autouse=True)
def _never_scan_real_hosts(monkeypatch: pytest.MonkeyPatch, request: pytest.FixtureRequest):
    """Safety net: no test may execute the real nmap against anything but loopback.

    Unit tests use the fake nmap below. Only tests marked ``integration`` may run
    the real binary, and only against single loopback addresses.
    """
    original = asyncio.create_subprocess_exec

    async def guarded(program, *args, **kwargs):
        if os.path.realpath(str(program)) in REAL_NMAP or Path(str(program)).name == "nmap":
            if request.node.get_closest_marker("integration") is None:
                pytest.fail(f"unit test tried to execute real nmap: {[program, *args]}")
            argv = [str(a) for a in args]
            targets = argv[argv.index("--") + 1 :] if "--" in argv else []
            if not targets or not all(_is_loopback_target(t) for t in targets):
                pytest.fail(f"integration test may only scan loopback, got {targets}")
        return await original(program, *args, **kwargs)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", guarded)


@dataclass
class FakeNmap:
    """Handle on the fake nmap executable (see tests/fake_nmap.py)."""

    path: Path

    def set_scenario(self, mode: str = "ok", **extra: object) -> None:
        (self.path.parent / "scenario.json").write_text(json.dumps({"mode": mode, **extra}))

    def queue_xml(self, *documents: str) -> None:
        """Make the next runs print these XML documents, one per run."""
        queue = [{"mode": "xml", "xml": doc} for doc in documents]
        (self.path.parent / "scenario.json").write_text(json.dumps(queue))

    @property
    def pids(self) -> list[int]:
        log = self.path.parent / "pids.txt"
        return [int(line) for line in log.read_text().split()] if log.exists() else []

    @property
    def environment(self) -> dict[str, str]:
        return json.loads((self.path.parent / "env.json").read_text())

    @property
    def calls(self) -> list[list[str]]:
        log = self.path.parent / "calls.jsonl"
        return [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []


@pytest.fixture
def fake_nmap(tmp_path: Path) -> FakeNmap:
    directory = tmp_path / "fake-bin"
    directory.mkdir()
    path = directory / "fake-nmap"
    source = (Path(__file__).parent / "fake_nmap.py").read_text()
    path.write_text(f"#!{sys.executable}\n{source}")
    path.chmod(0o700)
    return FakeNmap(path)


@pytest.fixture
def settings(tmp_path: Path, fake_nmap: FakeNmap) -> Settings:
    return Settings(
        db_path=tmp_path / "traceforge.db",
        token_file=tmp_path / "run" / "api.token",
        nmap_path=fake_nmap.path,
    )


@pytest.fixture
def app(settings: Settings) -> FastAPI:
    return create_app(settings, resolver=fake_resolver)


@pytest.fixture
def client(app: FastAPI) -> Iterator[TestClient]:
    # The context manager runs the lifespan: database init + token file.
    with TestClient(app, base_url=BASE_URL) as test_client:
        yield test_client


@pytest.fixture
def auth(app: FastAPI) -> dict[str, str]:
    return {"Authorization": f"Bearer {app.state.api_token}"}


def browser_headers(
    origin: str | None = DASHBOARD_ORIGIN, fetch_site: str | None = "same-origin"
) -> dict[str, str]:
    headers = {}
    if origin is not None:
        headers["Origin"] = origin
    if fetch_site is not None:
        headers["Sec-Fetch-Site"] = fetch_site
    return headers


def sign_in(client: TestClient, app: FastAPI) -> str:
    """Open a dashboard session; returns the CSRF token. Cookie stays in the client."""
    code, _ = app.state.sessions.issue_login_code()
    response = client.post("/api/v1/auth/session", json={"code": code}, headers=browser_headers())
    assert response.status_code == 200, response.text
    return response.json()["csrf_token"]


# --- inventory / comparison fixtures -------------------------------------------------


@pytest.fixture
def db(tmp_path: Path):
    from traceforge.db import Database

    database = Database(tmp_path / "t.db")
    database.initialize()
    return database


@pytest.fixture
def evidence_dir(tmp_path: Path) -> Path:
    path = tmp_path / "evidence"
    path.mkdir()
    return path


@pytest.fixture
def project(db) -> int:
    from traceforge.db.repositories import ProjectRepository

    return ProjectRepository(db).create("acme", "SOW-1")["id"]
