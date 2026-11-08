from __future__ import annotations

import ipaddress
import os
import socket
from collections.abc import Iterator
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


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(db_path=tmp_path / "traceforge.db", token_file=tmp_path / "run" / "api.token")


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
