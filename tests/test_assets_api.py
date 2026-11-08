"""Asset, comparison and evidence-verification endpoints, end to end over HTTP."""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from tests.conftest import FakeNmap, browser_headers, sign_in
from tests.nmapxml import Host, Port, nmap_xml
from tests.test_projects_api import create_project
from tests.test_scans_api import launch, wait_for_status


def run_scans(client, auth, fake_nmap: FakeNmap, pid: int, *documents: str) -> list[int]:
    """Run one scan per XML document through the real job pipeline."""
    fake_nmap.queue_xml(*documents)
    ids = []
    for _ in documents:
        scan_id = launch(client, auth, pid, ["10.0.0.0/28"])["scan_id"]
        wait_for_status(client, auth, scan_id, "completed", "failed")
        ids.append(scan_id)
    return ids


BEFORE = nmap_xml(
    Host(
        "10.0.0.5",
        [
            Port(22, service="ssh", product="OpenSSH", version="9.6p1"),
            Port(8080, service="http", product="Jetty", version="9.4"),
        ],
    ),
    services="22,8080",
)
AFTER = nmap_xml(
    Host(
        "10.0.0.5",
        [Port(22, service="ssh", product="OpenSSH", version="9.7p1"), Port(8080, state="closed")],
    ),
    services="22,8080",
    offset=120,
)


@pytest.fixture
def scanned(client: TestClient, auth: dict, fake_nmap: FakeNmap) -> tuple[int, list[int]]:
    pid = create_project(client, auth, ("include", "10.0.0.0/24"))
    return pid, run_scans(client, auth, fake_nmap, pid, BEFORE, AFTER)


def test_asset_inventory_over_http(client, auth, scanned) -> None:
    pid, (first, second) = scanned

    (asset,) = client.get(f"/api/v1/assets?project_id={pid}", headers=auth).json()
    assert asset["address"] == "10.0.0.5"
    assert asset["project_name"] == "acme"
    assert asset["open_ports"] == 1
    assert asset["last_scan_id"] == second
    assert asset["services"] == [
        {"protocol": "tcp", "port": 22, "service_name": "ssh", "identification": "detected"}
    ]

    detail = client.get(f"/api/v1/assets/{asset['uid']}", headers=auth).json()
    ports = {p["port"]: p for p in detail["ports"]}
    assert ports[8080]["state"] == "closed" and ports[8080]["state_scan_id"] == second
    assert ports[22]["service_version"] == "9.7p1"
    assert [o["scan_id"] for o in detail["observations"]] == [second, first]
    prov = detail["observations"][0]["provenance"]
    assert prov["requested_targets"] == ["10.0.0.0/28"]
    assert prov["scanned_address"] == "10.0.0.5"
    assert prov["configuration"]["ports_scanned"] == {"tcp": "22,8080"}
    assert len(prov["evidence"]["sha256"]) == 64

    stats = client.get(f"/api/v1/assets/stats?project_id={pid}", headers=auth).json()
    assert stats == {
        "assets": 1,
        "unconfirmed": 0,
        "assets_with_open_ports": 1,
        "open_ports": 1,
        "detected_services": 1,
    }
    assert client.get("/api/v1/assets?q=jetty", headers=auth).json() == []  # closed now
    assert len(client.get("/api/v1/assets?q=openssh", headers=auth).json()) == 1

    scan = client.get(f"/api/v1/scans/{second}", headers=auth).json()
    assert scan["ports_scanned"] == {"tcp": "22,8080"}
    results = client.get(f"/api/v1/scans/{second}/results", headers=auth).json()
    assert results["hosts"][0]["asset_uid"] == asset["uid"]


def test_scan_comparison_over_http(client, auth, scanned) -> None:
    pid, (first, second) = scanned
    response = client.get(
        f"/api/v1/projects/{pid}/scans/compare?baseline={first}&comparison={second}", headers=auth
    )
    assert response.status_code == 200
    body = response.json()
    assert [(c["category"], c["kind"], c["port"]) for c in body["changes"]] == [
        ("removed", "port_closed", 8080),
        ("changed", "version_changed", 22),
    ]
    assert body["summary"]["unchanged_open_ports"] == 0
    assert body["baseline"]["ports_scanned"] == {"tcp": "22,8080"}
    assert body["comparison"]["host_discovery"] is True


def test_comparison_rules_over_http(client, auth, fake_nmap, scanned) -> None:
    pid, (first, second) = scanned
    url = f"/api/v1/projects/{pid}/scans/compare"

    other = client.post(
        "/api/v1/projects", json={"name": "other", "authorization_ref": "B"}, headers=auth
    ).json()["id"]
    assert client.get(f"{url}?baseline={first}&comparison={first}", headers=auth).status_code == 422

    fake_nmap.set_scenario("fail")
    failed = launch(client, auth, pid, ["10.0.0.5"])["scan_id"]
    wait_for_status(client, auth, failed, "failed")
    conflict = client.get(f"{url}?baseline={first}&comparison={failed}", headers=auth)
    assert conflict.status_code == 409 and "failed" in conflict.json()["detail"]

    # The other project's URL never reveals this project's scans.
    for scan_pair in ((first, second), (first, 999)):
        response = client.get(
            f"/api/v1/projects/{other}/scans/compare?baseline={scan_pair[0]}"
            f"&comparison={scan_pair[1]}",
            headers=auth,
        )
        assert response.status_code == 404
    assert (
        client.get(
            "/api/v1/projects/999/scans/compare?baseline=1&comparison=2", headers=auth
        ).status_code
        == 404
    )
    assert client.get(f"{url}?baseline=x&comparison=1", headers=auth).status_code == 422


def test_asset_endpoint_validation(client, auth, scanned) -> None:
    assert client.get("/api/v1/assets/ast_0000000000000000", headers=auth).status_code == 404
    for bad in ("1", "ast_XYZ", "ast_0000000000000000;drop", "..%2F..%2Fetc"):
        assert client.get(f"/api/v1/assets/{bad}", headers=auth).status_code in (404, 422)
    assert client.get("/api/v1/assets?project_id=999", headers=auth).status_code == 404
    assert client.get("/api/v1/assets?q=" + "x" * 201, headers=auth).status_code == 422
    # SQL metacharacters are just text.
    assert client.get("/api/v1/assets?q=' OR 1=1 --", headers=auth).json() == []


def test_cross_project_isolation_over_http(client, auth, fake_nmap) -> None:
    first = create_project(client, auth, ("include", "10.0.0.0/24"))
    second = client.post(
        "/api/v1/projects", json={"name": "other", "authorization_ref": "B"}, headers=auth
    ).json()["id"]
    client.post(
        f"/api/v1/projects/{second}/scope",
        json={"kind": "include", "value": "10.0.0.0/24"},
        headers=auth,
    )
    run_scans(client, auth, fake_nmap, first, BEFORE)
    run_scans(client, auth, fake_nmap, second, AFTER)

    a = client.get(f"/api/v1/assets?project_id={first}", headers=auth).json()
    b = client.get(f"/api/v1/assets?project_id={second}", headers=auth).json()
    assert len(a) == len(b) == 1 and a[0]["uid"] != b[0]["uid"]
    for asset, pid in ((a[0], first), (b[0], second)):
        detail = client.get(f"/api/v1/assets/{asset['uid']}", headers=auth).json()
        assert {o["provenance"]["project_id"] for o in detail["observations"]} == {pid}
    assert len(client.get("/api/v1/assets", headers=auth).json()) == 2


def test_evidence_verification(client, auth, settings, scanned) -> None:
    _, (first, _) = scanned
    ok = client.get(f"/api/v1/scans/{first}/evidence/verify", headers=auth).json()
    assert ok["verified"] is True and ok["actual_sha256"] == ok["recorded_sha256"]

    path = settings.evidence_path / ok["file"]
    path.write_bytes(path.read_bytes() + b" ")
    bad = client.get(f"/api/v1/scans/{first}/evidence/verify", headers=auth).json()
    assert bad["verified"] is False and "does NOT match" in bad["detail"]
    path.unlink()
    gone = client.get(f"/api/v1/scans/{first}/evidence/verify", headers=auth).json()
    assert gone["verified"] is False and gone["actual_sha256"] is None


@pytest.mark.parametrize(
    "path",
    [
        "/api/v1/assets",
        "/api/v1/assets/stats",
        "/api/v1/assets/ast_0000000000000000",
        "/api/v1/projects/1/scans/compare?baseline=1&comparison=2",
        "/api/v1/scans/1/evidence/verify",
    ],
)
def test_new_endpoints_require_authentication(client, path) -> None:
    assert client.get(path).status_code == 401
    assert client.get(path, headers={"Authorization": "Bearer nope"}).status_code == 401


def test_dashboard_session_can_read_assets(client: TestClient, app: FastAPI, scanned) -> None:
    sign_in(client, app)
    response = client.get("/api/v1/assets", headers=browser_headers())
    assert response.status_code == 200 and len(response.json()) == 1
    cross = client.get(
        "/api/v1/assets",
        headers=browser_headers(origin="https://evil.example", fetch_site="cross-site"),
    )
    assert cross.status_code == 403
