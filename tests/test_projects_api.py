"""Projects, scope and scan launches through the HTTP API."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from tests.conftest import BASE_URL, browser_headers, fake_resolver, sign_in
from traceforge.api import create_app
from traceforge.security.auth import CSRF_HEADER


def create_project(client: TestClient, auth: dict, *rules: tuple[str, str]) -> int:
    response = client.post(
        "/api/v1/projects", json={"name": "acme", "authorization_ref": "SOW-42"}, headers=auth
    )
    assert response.status_code == 201, response.text
    pid = response.json()["id"]
    for kind, value in rules:
        r = client.post(
            f"/api/v1/projects/{pid}/scope", json={"kind": kind, "value": value}, headers=auth
        )
        assert r.status_code == 201, r.text
    return pid


def test_project_lifecycle(client: TestClient, auth: dict) -> None:
    pid = create_project(client, auth, ("include", "10.0.0.0/24"), ("exclude", "10.0.0.1"))

    project = client.get(f"/api/v1/projects/{pid}", headers=auth).json()
    assert project["scope_rule_count"] == 2
    rules = client.get(f"/api/v1/projects/{pid}/scope", headers=auth).json()
    assert [(r["kind"], r["value"]) for r in rules] == [
        ("include", "10.0.0.0/24"),
        ("exclude", "10.0.0.1/32"),
    ]
    rule_id = rules[1]["id"]
    assert client.delete(f"/api/v1/projects/{pid}/scope/{rule_id}", headers=auth).status_code == 204
    assert client.get(f"/api/v1/projects/{pid}", headers=auth).json()["scope_rule_count"] == 1


def test_project_requires_authorization_reference(client: TestClient, auth: dict) -> None:
    for body in ({"name": "x"}, {"name": "x", "authorization_ref": ""}):
        assert client.post("/api/v1/projects", json=body, headers=auth).status_code == 422


def test_authorization_window_must_be_ordered_and_timezone_aware(
    client: TestClient, auth: dict
) -> None:
    base = {"name": "x", "authorization_ref": "y"}
    reversed_window = {
        **base,
        "authorized_from": "2026-12-01T00:00:00Z",
        "authorized_until": "2026-11-01T00:00:00Z",
    }
    naive = {**base, "authorized_from": "2026-12-01T00:00:00"}
    for body in (reversed_window, naive):
        assert client.post("/api/v1/projects", json=body, headers=auth).status_code == 422


def test_duplicate_project_and_rule_conflict(client: TestClient, auth: dict) -> None:
    pid = create_project(client, auth, ("include", "10.0.0.0/24"))
    dup = client.post(
        "/api/v1/projects", json={"name": "acme", "authorization_ref": "x"}, headers=auth
    )
    assert dup.status_code == 409
    rule = client.post(
        f"/api/v1/projects/{pid}/scope",
        json={"kind": "include", "value": "10.0.0.0/24"},
        headers=auth,
    )
    assert rule.status_code == 409


def test_invalid_and_overbroad_scope_rules_are_rejected(client: TestClient, auth: dict) -> None:
    pid = create_project(client, auth)
    for value in ("0.0.0.0/0", "*.com", "-iL /etc/passwd", "not a host"):
        response = client.post(
            f"/api/v1/projects/{pid}/scope", json={"kind": "include", "value": value}, headers=auth
        )
        assert response.status_code == 422, value


def test_unknown_project_is_404(client: TestClient, auth: dict) -> None:
    assert client.get("/api/v1/projects/999", headers=auth).status_code == 404
    response = client.post(
        "/api/v1/projects/999/scans", json={"tool": "x", "targets": ["10.0.0.1"]}, headers=auth
    )
    assert response.status_code == 404


def test_scope_check_reports_each_target(client: TestClient, auth: dict) -> None:
    pid = create_project(client, auth, ("include", "10.0.0.0/24"), ("include", "*.example.com"))
    response = client.post(
        f"/api/v1/projects/{pid}/scope/check",
        json={"targets": ["10.0.0.7", "10.0.1.7", "app.example.com", "rebind.example.com"]},
        headers=auth,
    )
    assert response.status_code == 200
    body = response.json()
    assert body["allowed"] is False
    assert [d["allowed"] for d in body["decisions"]] == [True, False, True, False]


def test_out_of_scope_launch_is_forbidden_and_audited(client: TestClient, auth: dict, app) -> None:
    pid = create_project(client, auth, ("include", "10.0.0.0/24"))

    response = client.post(
        f"/api/v1/projects/{pid}/scans",
        json={"tool": "nmap", "targets": ["10.0.0.5", "8.8.8.8"]},
        headers=auth,
    )

    assert response.status_code == 403
    detail = response.json()["detail"]
    assert "nothing was launched" in detail["message"]
    assert [d["allowed"] for d in detail["decisions"]] == [True, False]
    audit = app.state.executor.audit.list_all(pid)
    assert audit[-1]["action"] == "launch.denied"


def test_in_scope_launch_without_tool_adapters_is_501(client: TestClient, auth: dict) -> None:
    pid = create_project(client, auth, ("include", "10.0.0.0/24"))
    response = client.post(
        f"/api/v1/projects/{pid}/scans",
        json={"tool": "nmap", "targets": ["10.0.0.5"]},
        headers=auth,
    )
    assert response.status_code == 501
    assert "available: none" in response.json()["detail"]


def test_launch_through_api_reaches_registered_tool(settings) -> None:
    from tests.test_executor import RecordingRunner, RecordingTool
    from traceforge.execution.tools import ToolRegistry

    tool, runner = RecordingTool(), RecordingRunner()
    app = create_app(settings, tools=ToolRegistry([tool]), runner=runner, resolver=fake_resolver)
    with TestClient(app, base_url=BASE_URL) as client:
        auth = {"Authorization": f"Bearer {app.state.api_token}"}
        pid = create_project(client, auth, ("include", "10.0.0.0/24"))

        denied = client.post(
            f"/api/v1/projects/{pid}/scans",
            json={"tool": "probe", "targets": ["10.0.1.1"]},
            headers=auth,
        )
        ok = client.post(
            f"/api/v1/projects/{pid}/scans",
            json={"tool": "probe", "targets": ["10.0.0.9"]},
            headers=auth,
        )

    assert denied.status_code == 403
    assert ok.status_code == 202
    assert runner.calls == [(ok.json()["scan_id"], ["probe", "--", "10.0.0.9"])]


def test_dashboard_session_can_manage_scope_with_csrf(client: TestClient, app: FastAPI) -> None:
    csrf = sign_in(client, app)
    headers = {**browser_headers(), CSRF_HEADER: csrf}
    pid = client.post(
        "/api/v1/projects", json={"name": "web", "authorization_ref": "T-1"}, headers=headers
    ).json()["id"]
    response = client.post(
        f"/api/v1/projects/{pid}/scope",
        json={"kind": "include", "value": "10.0.0.0/24"},
        headers=headers,
    )
    assert response.status_code == 201
    assert app.state.executor.audit.list_all(pid)[-1]["actor"] == "dashboard"


def test_scope_changes_are_audited(client: TestClient, auth: dict, app) -> None:
    pid = create_project(client, auth, ("include", "10.0.0.0/24"))
    actions = [e["action"] for e in app.state.executor.audit.list_all(pid)]
    assert actions == ["project.created", "scope.added"]
