"""API authentication: bearer token (TUI/CLI) and cookie sessions (dashboard)."""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from tests.conftest import BASE_URL, browser_headers, sign_in
from traceforge.security.auth import CSRF_HEADER, SESSION_COOKIE
from traceforge.security.sessions import SessionStore
from traceforge.security.tokens import read_token_file

PROTECTED = [
    ("GET", "/api/v1/projects"),
    ("POST", "/api/v1/projects"),
    ("GET", "/api/v1/projects/1/scope"),
    ("POST", "/api/v1/projects/1/scope/check"),
    ("POST", "/api/v1/projects/1/scans"),
    ("GET", "/api/v1/auth/session"),
    ("POST", "/api/v1/auth/login-codes"),
]


# --------------------------------------------------------------------------- unauthorized


@pytest.mark.parametrize(("method", "path"), PROTECTED)
def test_requests_without_credentials_are_rejected(
    client: TestClient, method: str, path: str
) -> None:
    response = client.request(method, path, json={})
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"


@pytest.mark.parametrize(
    "authorization",
    [
        "Bearer wrong-token",
        "Bearer ",
        "Basic dXNlcjpwYXNz",
        "bearer",
        "Bearer \u00e9\u00e9\u00e9".encode("latin-1"),  # non-ASCII must not crash compare
    ],
)
def test_invalid_bearer_tokens_are_rejected(client: TestClient, authorization: str | bytes) -> None:
    response = client.get("/api/v1/projects", headers={"Authorization": authorization})
    assert response.status_code == 401


def test_bearer_token_grants_access(client: TestClient, auth: dict) -> None:
    assert client.get("/api/v1/projects", headers=auth).status_code == 200
    assert client.get("/api/v1/auth/session", headers=auth).json()["method"] == "token"


def test_health_stays_public(client: TestClient) -> None:
    assert client.get("/health").status_code == 200


def test_token_is_unique_per_server_instance(settings) -> None:
    from traceforge.api import create_app

    assert create_app(settings).state.api_token != create_app(settings).state.api_token


# --------------------------------------------------------------------------- token file


def test_token_file_is_owner_only_and_removed_on_shutdown(app: FastAPI, settings) -> None:
    path = settings.token_path
    with TestClient(app, base_url=BASE_URL):
        assert read_token_file(path) == app.state.api_token
        assert path.stat().st_mode & 0o777 == 0o600
        assert path.parent.stat().st_mode & 0o777 == 0o700
    assert not path.exists()


# --------------------------------------------------------------------------- sessions


def test_login_code_exchange_sets_hardened_cookie(client: TestClient, app: FastAPI) -> None:
    code, _ = app.state.sessions.issue_login_code()
    response = client.post("/api/v1/auth/session", json={"code": code}, headers=browser_headers())

    assert response.status_code == 200
    body = response.json()
    assert body["method"] == "session" and body["csrf_token"]
    cookie = response.headers["set-cookie"]
    assert cookie.startswith(f"{SESSION_COOKIE}=")
    assert "HttpOnly" in cookie
    assert "SameSite=strict" in cookie
    assert "Path=/api" in cookie
    assert "Max-Age" not in cookie and "expires" not in cookie.lower()
    # The session id is never exposed to scripts in the response body.
    assert client.cookies[SESSION_COOKIE] not in response.text


def test_login_code_is_single_use(client: TestClient, app: FastAPI) -> None:
    code, _ = app.state.sessions.issue_login_code()
    first = client.post("/api/v1/auth/session", json={"code": code})
    second = client.post("/api/v1/auth/session", json={"code": code})
    assert first.status_code == 200
    assert second.status_code == 401


def test_unknown_login_code_is_rejected(client: TestClient) -> None:
    response = client.post("/api/v1/auth/session", json={"code": "guess"})
    assert response.status_code == 401
    assert SESSION_COOKIE not in client.cookies


def test_session_cookie_allows_reads(client: TestClient, app: FastAPI) -> None:
    sign_in(client, app)
    response = client.get("/api/v1/projects", headers=browser_headers())
    assert response.status_code == 200


def test_session_writes_require_csrf_token(client: TestClient, app: FastAPI) -> None:
    csrf = sign_in(client, app)
    body = {"name": "acme", "authorization_ref": "SOW-1"}

    missing = client.post("/api/v1/projects", json=body, headers=browser_headers())
    wrong = client.post(
        "/api/v1/projects", json=body, headers={**browser_headers(), CSRF_HEADER: "nope"}
    )
    ok = client.post(
        "/api/v1/projects", json=body, headers={**browser_headers(), CSRF_HEADER: csrf}
    )

    assert missing.status_code == 403
    assert missing.json()["detail"] == "Missing or invalid CSRF token"
    assert wrong.status_code == 403
    assert ok.status_code == 201


def test_csrf_token_of_another_session_is_rejected(client: TestClient, app: FastAPI) -> None:
    other_csrf = sign_in(client, app)
    sign_in(client, app)  # replaces the cookie with a second session
    response = client.post(
        "/api/v1/projects",
        json={"name": "x", "authorization_ref": "y"},
        headers={**browser_headers(), CSRF_HEADER: other_csrf},
    )
    assert response.status_code == 403


def test_forged_session_cookie_is_rejected(client: TestClient) -> None:
    client.cookies.set(SESSION_COOKIE, "forged", domain="127.0.0.1", path="/api")
    assert client.get("/api/v1/projects").status_code == 401


def test_sessions_cannot_mint_login_codes(client: TestClient, app: FastAPI) -> None:
    csrf = sign_in(client, app)
    response = client.post(
        "/api/v1/auth/login-codes", headers={**browser_headers(), CSRF_HEADER: csrf}
    )
    assert response.status_code == 403


def test_token_can_mint_dashboard_link(client: TestClient, auth: dict) -> None:
    response = client.post("/api/v1/auth/login-codes", headers=auth)
    assert response.status_code == 201
    body = response.json()
    assert body["url"] == f"http://127.0.0.1:5173/#code={body['code']}"
    # The fresh code works exactly once.
    assert client.post("/api/v1/auth/session", json={"code": body["code"]}).status_code == 200


def test_sign_out_revokes_session(client: TestClient, app: FastAPI) -> None:
    csrf = sign_in(client, app)
    session_id = client.cookies[SESSION_COOKIE]

    response = client.delete(
        "/api/v1/auth/session", headers={**browser_headers(), CSRF_HEADER: csrf}
    )
    assert response.status_code == 204

    client.cookies.set(SESSION_COOKIE, session_id, domain="127.0.0.1", path="/api")
    assert client.get("/api/v1/projects").status_code == 401


def test_expired_session_and_code_are_rejected(client: TestClient, app: FastAPI) -> None:
    now = [1_000_000.0]
    app.state.sessions = SessionStore(session_ttl=60, login_code_ttl=30, clock=lambda: now[0])

    stale_code, _ = app.state.sessions.issue_login_code()
    now[0] += 31
    assert client.post("/api/v1/auth/session", json={"code": stale_code}).status_code == 401

    sign_in(client, app)
    assert client.get("/api/v1/projects").status_code == 200
    now[0] += 61
    assert client.get("/api/v1/projects").status_code == 401


def test_pending_login_codes_are_bounded() -> None:
    store = SessionStore(session_ttl=60, login_code_ttl=60)
    codes = [store.issue_login_code()[0] for _ in range(40)]
    assert store.redeem_login_code(codes[0]) is None  # evicted
    assert store.redeem_login_code(codes[-1]) is not None
