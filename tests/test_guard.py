"""Trusted Host, CORS, Origin and fetch-metadata enforcement (DNS rebinding / CSRF)."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from tests.conftest import DASHBOARD_ORIGIN, browser_headers
from traceforge.security.guard import parse_host_header

# --------------------------------------------------------------------------- Host


@pytest.mark.parametrize(
    "host",
    [
        "evil.example",  # DNS rebinding: attacker domain resolved to 127.0.0.1
        "evil.example:8000",
        "127.0.0.1.nip.io:8000",
        "localhost.evil.example:8000",
        "sub.localhost:8000",
        "localhost.:8000",
        "0.0.0.0:8000",
        "192.168.1.10:8000",
        "[::ffff:127.0.0.1]:8000",
        "127.0.0.1:5173",  # right host, wrong port
        "127.0.0.1",  # implies port 80
        "127.0.0.1:",
        "127.0.0.1:abc",
        "::1:8000",  # unbracketed IPv6
        "[::1",
        "",
    ],
)
def test_untrusted_host_is_rejected(client: TestClient, auth: dict, host: str) -> None:
    for path in ("/health", "/api/v1/projects"):
        response = client.get(path, headers={"Host": host, **auth})
        assert response.status_code == 400, (host, path)
        assert response.json() == {"detail": "Invalid Host header"}


@pytest.mark.parametrize(
    "host", ["127.0.0.1:8000", "localhost:8000", "LOCALHOST:8000", "[::1]:8000"]
)
def test_loopback_host_is_accepted(client: TestClient, host: str) -> None:
    assert client.get("/health", headers={"Host": host}).status_code == 200


def test_rejected_host_never_reaches_authentication_or_routes(
    client: TestClient, auth: dict
) -> None:
    response = client.post(
        "/api/v1/projects",
        json={"name": "x", "authorization_ref": "y"},
        headers={"Host": "attacker.test:8000", **auth},
    )
    assert response.status_code == 400
    assert client.get("/api/v1/projects", headers=auth).json() == []


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("127.0.0.1:8000", ("127.0.0.1", 8000)),
        ("LocalHost", ("localhost", None)),
        ("[::1]:8000", ("::1", 8000)),
        ("[::1]", ("::1", None)),
        ("a b:80", None),
        ("[::1]x", None),
        ("host:0", None),
        ("host:65536", None),
    ],
)
def test_parse_host_header(value: str, expected: tuple | None) -> None:
    assert parse_host_header(value) == expected


# --------------------------------------------------------------------------- Origin / CORS


@pytest.mark.parametrize(
    "origin",
    [
        "https://evil.example",
        "http://evil.example:5173",
        "null",  # sandboxed iframes, file:// pages
        "http://127.0.0.1:3000",  # another local web app
        "http://127.0.0.1:8000",  # the API's own origin (e.g. a compromised docs page)
        "http://127.0.0.1:5173.evil.example",
        "https://127.0.0.1:5173",  # scheme matters
    ],
)
def test_foreign_origin_is_rejected(client: TestClient, auth: dict, origin: str) -> None:
    for method, path in (("GET", "/health"), ("POST", "/api/v1/projects")):
        response = client.request(
            method,
            path,
            json={"name": "x", "authorization_ref": "y"},
            headers={**auth, **browser_headers(origin, fetch_site=None)},
        )
        assert response.status_code == 403, (origin, method)
        assert response.json() == {"detail": "Origin not allowed"}
        assert not any(h.startswith("access-control-") for h in response.headers)


@pytest.mark.parametrize("origin", [DASHBOARD_ORIGIN, "http://localhost:5173"])
def test_dashboard_origin_is_accepted(client: TestClient, origin: str) -> None:
    assert client.get("/health", headers=browser_headers(origin)).status_code == 200


@pytest.mark.parametrize("origin", ["https://evil.example", DASHBOARD_ORIGIN])
def test_cors_preflight_is_always_refused(client: TestClient, origin: str) -> None:
    response = client.options(
        "/api/v1/projects",
        headers={
            "Origin": origin,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "authorization, content-type",
        },
    )
    assert response.status_code == 403
    assert not any(h.startswith("access-control-") for h in response.headers)


def test_no_cors_headers_even_for_allowed_origin(client: TestClient) -> None:
    response = client.get("/health", headers=browser_headers())
    assert response.status_code == 200
    assert not any(h.startswith("access-control-") for h in response.headers)


@pytest.mark.parametrize("site", ["cross-site", "same-site"])
def test_cross_site_fetch_metadata_is_rejected(client: TestClient, site: str) -> None:
    # same-site matters on localhost: every port of 127.0.0.1 is the same "site".
    response = client.get("/health", headers=browser_headers(origin=None, fetch_site=site))
    assert response.status_code == 403
    assert response.json() == {"detail": "Cross-site requests are not permitted"}


@pytest.mark.parametrize("site", ["same-origin", "none"])
def test_same_origin_fetch_metadata_is_accepted(client: TestClient, site: str) -> None:
    response = client.get("/health", headers=browser_headers(origin=None, fetch_site=site))
    assert response.status_code == 200


# --------------------------------------------------------------------------- headers


def test_security_headers_on_success_and_rejection(client: TestClient) -> None:
    ok = client.get("/health")
    rejected = client.get("/health", headers={"Host": "evil.example:8000"})
    for response in (ok, rejected):
        assert response.headers["x-content-type-options"] == "nosniff"
        assert response.headers["x-frame-options"] == "DENY"
        assert response.headers["cache-control"] == "no-store"
        assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
        assert response.headers["cross-origin-resource-policy"] == "same-origin"


def test_docs_disabled_by_default(client: TestClient) -> None:
    assert client.get("/docs").status_code == 404
    assert client.get("/openapi.json").status_code == 404
