"""Scan endpoints end to end over HTTP, using the fake nmap binary."""

from __future__ import annotations

import ipaddress
import time
from collections.abc import Callable

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from tests.conftest import BASE_URL, FakeNmap, browser_headers, sign_in
from tests.test_projects_api import create_project
from traceforge.api import create_app
from traceforge.security.auth import CSRF_HEADER


def wait_for_status(client: TestClient, auth: dict, scan_id: int, *wanted: str) -> dict:
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        scan = client.get(f"/api/v1/scans/{scan_id}", headers=auth).json()
        if scan["status"] in wanted:
            return scan
        time.sleep(0.05)
    pytest.fail(f"scan {scan_id} never reached {wanted}; last: {scan}")


def launch(client: TestClient, auth: dict, pid: int, targets: list[str], **body) -> dict:
    body.setdefault("options", {"ports": "22,80"})
    response = client.post(
        f"/api/v1/projects/{pid}/scans", json={"targets": targets, **body}, headers=auth
    )
    return {"status_code": response.status_code, **response.json()}


def test_scan_lifecycle_over_http(client: TestClient, auth: dict, fake_nmap: FakeNmap) -> None:
    pid = create_project(client, auth, ("include", "10.0.0.0/24"))

    launched = launch(client, auth, pid, ["10.0.0.5"])
    assert launched["status_code"] == 202
    assert launched["status"] == "queued"
    assert launched["scan_addresses"] == ["10.0.0.5"]

    scan = wait_for_status(client, auth, launched["scan_id"], "completed", "failed")
    assert scan["status"] == "completed", scan["error"]
    assert scan["tool"] == "nmap"
    assert scan["targets"] == ["10.0.0.5"]
    assert scan["options"]["ports"] == "22,80"
    assert scan["command"][0] == str(fake_nmap.path)
    assert scan["command"][1:] == fake_nmap.calls[0]
    assert scan["actor"] == "cli"
    assert scan["open_ports"] == 2 and scan["hosts_up"] == 1
    assert len(scan["evidence"]["sha256"]) == 64

    results = client.get(f"/api/v1/scans/{scan['id']}/results", headers=auth).json()
    assert results["scan"]["id"] == scan["id"]
    (host,) = results["hosts"]
    assert host["address"] == "10.0.0.5" and host["state"] == "up"
    assert [(p["port"], p["service_name"], p["service_product"]) for p in host["ports"]] == [
        (22, "ssh", "OpenSSH"),
        (80, "http", "nginx"),
    ]

    history = client.get("/api/v1/scans", headers=auth).json()
    assert [s["id"] for s in history] == [scan["id"]]
    assert client.get(f"/api/v1/scans?project_id={pid + 1}", headers=auth).json() == []
    assert len(client.get("/api/v1/scans?status=completed", headers=auth).json()) == 1
    assert client.get("/api/v1/scans?status=bogus", headers=auth).status_code == 422


def test_scan_history_is_newest_first_and_paginated(client, auth) -> None:
    pid = create_project(client, auth, ("include", "10.0.0.0/24"))
    ids = [launch(client, auth, pid, [f"10.0.0.{i}"])["scan_id"] for i in (1, 2, 3)]
    for scan_id in ids:
        wait_for_status(client, auth, scan_id, "completed")
    page = client.get("/api/v1/scans?limit=2", headers=auth).json()
    assert [s["id"] for s in page] == ids[::-1][:2]
    rest = client.get("/api/v1/scans?limit=2&offset=2", headers=auth).json()
    assert [s["id"] for s in rest] == [ids[0]]


def test_evidence_download_is_verified(client, auth, settings) -> None:
    pid = create_project(client, auth, ("include", "10.0.0.0/24"))
    scan_id = launch(client, auth, pid, ["10.0.0.5"])["scan_id"]
    scan = wait_for_status(client, auth, scan_id, "completed")

    response = client.get(f"/api/v1/scans/{scan_id}/evidence", headers=auth)
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/xml")
    assert "attachment" in response.headers["content-disposition"]
    assert "sandbox" in response.headers["content-security-policy"]
    assert response.content.startswith(b"<?xml")

    path = settings.evidence_path / scan["evidence"]["file"]
    path.write_bytes(path.read_bytes() + b"<!-- tampered -->")
    tampered = client.get(f"/api/v1/scans/{scan_id}/evidence", headers=auth)
    assert tampered.status_code == 409
    assert "SHA-256" in tampered.json()["detail"]


def test_cancel_running_scan(client, auth, fake_nmap: FakeNmap) -> None:
    fake_nmap.set_scenario("sleep")
    pid = create_project(client, auth, ("include", "10.0.0.0/24"))
    scan_id = launch(client, auth, pid, ["10.0.0.5"])["scan_id"]
    wait_for_status(client, auth, scan_id, "running")

    response = client.post(f"/api/v1/scans/{scan_id}/cancel", headers=auth)

    assert response.status_code == 200
    assert response.json()["status"] == "cancelled"
    assert response.json()["error"] == "cancelled by cli"
    again = client.post(f"/api/v1/scans/{scan_id}/cancel", headers=auth)
    assert again.status_code == 409


def test_failed_scan_reports_error(client, auth, fake_nmap: FakeNmap) -> None:
    fake_nmap.set_scenario("fail")
    pid = create_project(client, auth, ("include", "10.0.0.0/24"))
    scan_id = launch(client, auth, pid, ["10.0.0.5"])["scan_id"]
    scan = wait_for_status(client, auth, scan_id, "failed")
    assert "QUITTING" in scan["error"]
    assert client.get(f"/api/v1/scans/{scan_id}/results", headers=auth).json()["hosts"] == []


def test_unknown_scan_is_404(client, auth) -> None:
    for method, path in (
        ("GET", "/api/v1/scans/999"),
        ("GET", "/api/v1/scans/999/results"),
        ("GET", "/api/v1/scans/999/evidence"),
        ("POST", "/api/v1/scans/999/cancel"),
    ):
        assert client.request(method, path, headers=auth).status_code == 404, path


@pytest.mark.parametrize(
    "method, path",
    [
        ("GET", "/api/v1/scans"),
        ("GET", "/api/v1/scans/1"),
        ("GET", "/api/v1/scans/1/results"),
        ("GET", "/api/v1/scans/1/evidence"),
        ("POST", "/api/v1/scans/1/cancel"),
    ],
)
def test_scan_endpoints_require_authentication(client, method, path) -> None:
    assert client.request(method, path).status_code == 401
    assert (
        client.request(method, path, headers={"Authorization": "Bearer wrong"}).status_code == 401
    )


# --------------------------------------------------------------------------- scope


@pytest.mark.parametrize(
    "targets",
    [
        ["8.8.8.8"],
        ["10.0.0.5", "8.8.8.8"],
        ["10.0.0.0/23"],
        ["10.0.0.13"],  # excluded
        ["rebind.example.com"],  # in-scope name pointing at 127.0.0.1
        ["intranet.example.com"],  # in-scope name pointing at private 10.20.0.5
    ],
)
def test_out_of_scope_targets_never_execute(client, auth, fake_nmap, targets) -> None:
    pid = create_project(
        client,
        auth,
        ("include", "10.0.0.0/24"),
        ("exclude", "10.0.0.13"),
        ("include", "*.example.com"),
    )
    response = launch(client, auth, pid, targets)
    assert response["status_code"] == 403
    assert client.get("/api/v1/scans", headers=auth).json() == []
    time.sleep(0.1)
    assert fake_nmap.calls == []


@pytest.mark.parametrize(
    "body, message",
    [
        ({"options": {"ports": "22 -oN /tmp/x"}}, "ports"),
        ({"options": {"script": "default"}}, "Extra inputs"),
        ({"options": {"timing": 1}}, "timing"),
        ({"timeout_seconds": 10**6}, None),
        ({"targets": ["-iL/etc/passwd"]}, "may not start with '-'"),
    ],
)
def test_invalid_requests_are_rejected_without_executing(
    client, auth, fake_nmap, body, message
) -> None:
    pid = create_project(client, auth, ("include", "10.0.0.0/24"))
    targets = body.pop("targets", ["10.0.0.5"])
    response = launch(client, auth, pid, targets, **body)
    assert response["status_code"] == 422
    if message:
        assert message in str(response["detail"])
    assert fake_nmap.calls == []


def test_timeout_above_server_maximum_is_rejected(settings, fake_nmap) -> None:
    app = create_app(
        settings.model_copy(update={"scan_max_timeout_seconds": 60}),
        resolver=lambda _: [],
    )
    with TestClient(app, base_url=BASE_URL) as client:
        auth = {"Authorization": f"Bearer {app.state.api_token}"}
        pid = create_project(client, auth, ("include", "10.0.0.0/24"))
        response = launch(client, auth, pid, ["10.0.0.5"], timeout_seconds=61)
    assert response["status_code"] == 422
    assert "between 10 and 60" in response["detail"]


def test_queue_full_returns_429(settings, fake_nmap: FakeNmap) -> None:
    fake_nmap.set_scenario("sleep")
    app = create_app(
        settings.model_copy(update={"scan_max_concurrent": 1, "scan_max_queued": 0}),
        resolver=lambda _: [],
    )
    with TestClient(app, base_url=BASE_URL) as client:
        auth = {"Authorization": f"Bearer {app.state.api_token}"}
        pid = create_project(client, auth, ("include", "10.0.0.0/24"))
        assert launch(client, auth, pid, ["10.0.0.5"])["status_code"] == 202
        assert launch(client, auth, pid, ["10.0.0.6"])["status_code"] == 429
    # Leaving the context shut the server down: the running scan was cancelled.
    scans = app.state.executor.scans.list_all()
    assert [s["status"] for s in scans] == ["failed", "cancelled"]


def rebinding_resolver(answers: list[str]) -> Callable[[str], list]:
    """Returns a different address on every lookup, like a rebinding DNS server."""
    calls = iter(answers)

    def resolve(hostname: str) -> list:
        return [ipaddress.ip_address(next(calls))]

    return resolve


def test_dns_rebinding_cannot_redirect_the_scan(settings, fake_nmap: FakeNmap) -> None:
    # First answer is in scope; any later lookup would point at the operator's machine.
    resolver = rebinding_resolver(["93.184.216.34"] + ["127.0.0.1"] * 10)
    app = create_app(settings, resolver=resolver)
    with TestClient(app, base_url=BASE_URL) as client:
        auth = {"Authorization": f"Bearer {app.state.api_token}"}
        pid = create_project(client, auth, ("include", "*.example.com"))
        launched = launch(client, auth, pid, ["app.example.com"])
        assert launched["status_code"] == 202
        scan = wait_for_status(client, auth, launched["scan_id"], "completed")

    (argv,) = fake_nmap.calls
    assert "-n" in argv  # nmap never resolves names itself
    assert argv[argv.index("--") + 1 :] == ["93.184.216.34"]
    assert "app.example.com" not in argv
    assert scan["scan_addresses"] == ["93.184.216.34"]


def test_scope_check_reports_resolved_addresses(client, auth) -> None:
    pid = create_project(client, auth, ("include", "*.example.com"))
    body = client.post(
        f"/api/v1/projects/{pid}/scope/check",
        json={"targets": ["www.example.com"]},
        headers=auth,
    ).json()
    assert body["decisions"][0]["addresses"] == ["93.184.216.35", "2606:2800:220:1::1"]


# --------------------------------------------------------------------------- dashboard


def test_dashboard_can_launch_and_cancel_with_csrf(
    client: TestClient, app: FastAPI, fake_nmap: FakeNmap
) -> None:
    fake_nmap.set_scenario("sleep")
    csrf = sign_in(client, app)
    headers = {**browser_headers(), CSRF_HEADER: csrf}
    pid = client.post(
        "/api/v1/projects", json={"name": "web", "authorization_ref": "T-1"}, headers=headers
    ).json()["id"]
    client.post(
        f"/api/v1/projects/{pid}/scope",
        json={"kind": "include", "value": "10.0.0.0/24"},
        headers=headers,
    )
    body = {"targets": ["10.0.0.5"], "options": {"ports": "22"}}

    no_csrf = client.post(f"/api/v1/projects/{pid}/scans", json=body, headers=browser_headers())
    assert no_csrf.status_code == 403
    assert fake_nmap.calls == []

    launched = client.post(f"/api/v1/projects/{pid}/scans", json=body, headers=headers)
    assert launched.status_code == 202
    scan_id = launched.json()["scan_id"]
    wait_for_status(client, browser_headers(), scan_id, "running")
    assert (
        client.post(f"/api/v1/scans/{scan_id}/cancel", headers=browser_headers()).status_code == 403
    )
    cancelled = client.post(f"/api/v1/scans/{scan_id}/cancel", headers=headers)
    assert cancelled.json()["status"] == "cancelled"
    assert cancelled.json()["actor"] == "dashboard"
    actions = [e["action"] for e in app.state.executor.audit.list_all(pid)]
    assert "scan.cancel_requested" in actions


def test_cross_origin_scan_launch_is_refused(client, auth, fake_nmap) -> None:
    pid = create_project(client, auth, ("include", "10.0.0.0/24"))
    response = client.post(
        f"/api/v1/projects/{pid}/scans",
        json={"targets": ["10.0.0.5"]},
        headers={**auth, **browser_headers(origin="https://evil.example", fetch_site="cross-site")},
    )
    assert response.status_code == 403
    assert fake_nmap.calls == []


def test_nmap_is_registered_by_default(app: FastAPI) -> None:
    assert app.state.executor.tools.names == ["nmap"]
