from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from traceforge import __version__
from traceforge.api.deps import get_database


def test_health_ok(client: TestClient) -> None:
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "version": __version__, "database": "ok"}


def test_health_degraded_when_database_unavailable(app: FastAPI, client: TestClient) -> None:
    class BrokenDatabase:
        def ping(self) -> bool:
            return False

    app.dependency_overrides[get_database] = BrokenDatabase
    try:
        response = client.get("/health")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 503
    assert response.json()["status"] == "degraded"
    assert response.json()["database"] == "error"


def test_health_is_documented_in_openapi_when_docs_enabled(settings) -> None:
    from tests.conftest import BASE_URL
    from traceforge.api import create_app

    app = create_app(settings.model_copy(update={"enable_docs": True}))
    with TestClient(app, base_url=BASE_URL) as client:
        schema = client.get("/openapi.json").json()
        docs = client.get("/docs")

    # Swagger UI needs CDN scripts, so the docs page alone is exempt from the API CSP.
    assert docs.status_code == 200
    assert "content-security-policy" not in docs.headers

    assert "/health" in schema["paths"]
    assert schema["info"]["version"] == __version__
