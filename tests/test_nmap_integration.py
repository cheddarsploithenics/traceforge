"""Integration: the real nmap binary against a listener this test starts on 127.0.0.1.

Safety: the project's only authorized scope is ``127.0.0.1/32``; the targets
are literal loopback addresses (no DNS); and the autouse guard in conftest.py
fails the test if real nmap is ever pointed at anything but loopback.
Skipped when nmap is not installed.
"""

from __future__ import annotations

import shutil
import socket
import threading
import time
from collections.abc import Iterator
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

import pytest
from fastapi.testclient import TestClient

from tests.conftest import BASE_URL
from tests.test_projects_api import create_project
from tests.test_scans_api import launch, wait_for_status
from traceforge.api import create_app
from traceforge.config import Settings

NMAP = shutil.which("nmap")
pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(NMAP is None, reason="nmap is not installed"),
]
BANNER = b"SSH-2.0-OpenSSH_9.6p1 Debian-3\r\n"


@pytest.fixture
def banner_server() -> Iterator[int]:
    """A tiny TCP service on an ephemeral loopback port that sends an SSH banner."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(16)
    server.settimeout(0.2)
    stop = threading.Event()

    def serve() -> None:
        while not stop.is_set():
            try:
                conn, _ = server.accept()
            except OSError:
                continue
            with conn:
                try:
                    conn.sendall(BANNER)
                    time.sleep(0.3)
                except OSError:
                    pass

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield server.getsockname()[1]
    finally:
        stop.set()
        thread.join(timeout=2)
        server.close()


@pytest.fixture
def real_client(tmp_path) -> Iterator[tuple[TestClient, dict]]:
    settings = Settings(
        db_path=tmp_path / "traceforge.db",
        token_file=tmp_path / "run" / "api.token",
        nmap_path=NMAP,
    )

    def no_dns(hostname: str) -> list:
        raise OSError("DNS is disabled in integration tests")

    app = create_app(settings, resolver=no_dns)
    with TestClient(app, base_url=BASE_URL) as client:
        yield client, {"Authorization": f"Bearer {app.state.api_token}"}


def test_real_nmap_finds_local_service(real_client, banner_server: int) -> None:
    client, auth = real_client
    pid = create_project(client, auth, ("include", "127.0.0.1/32"))

    launched = launch(
        client,
        auth,
        pid,
        ["127.0.0.1"],
        options={"ports": str(banner_server), "timing": 4, "skip_host_discovery": True},
        timeout_seconds=120,
    )
    assert launched["status_code"] == 202, launched
    scan = wait_for_status(client, auth, launched["scan_id"], "completed", "failed")

    assert scan["status"] == "completed", scan["error"]
    assert scan["exit_code"] == 0
    assert scan["tool_version"]
    results = client.get(f"/api/v1/scans/{scan['id']}/results", headers=auth).json()
    (host,) = results["hosts"]
    assert host["address"] == "127.0.0.1"
    (port,) = host["ports"]
    assert (port["port"], port["state"]) == (banner_server, "open")
    assert port["service_name"] == "ssh"
    assert port["service_product"] == "OpenSSH"

    evidence = client.get(f"/api/v1/scans/{scan['id']}/evidence", headers=auth)
    assert b'scanner="nmap"' in evidence.content
    assert b'type="connect"' in evidence.content  # TCP connect scan, no raw packets


def test_real_nmap_closed_port(real_client, banner_server: int) -> None:
    client, auth = real_client
    pid = create_project(client, auth, ("include", "127.0.0.1/32"))
    # The port right after ours is almost certainly closed; either way it's loopback.
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    closed_port = probe.getsockname()[1]
    probe.close()

    launched = launch(
        client,
        auth,
        pid,
        ["127.0.0.1"],
        options={"ports": str(closed_port), "service_detection": False, "timing": 4},
    )
    scan = wait_for_status(client, auth, launched["scan_id"], "completed", "failed")
    assert scan["status"] == "completed", scan["error"]
    assert scan["open_ports"] == 0


def test_real_nmap_refuses_out_of_scope_loopback(real_client) -> None:
    client, auth = real_client
    pid = create_project(client, auth, ("include", "127.0.0.1/32"))
    response = launch(client, auth, pid, ["127.0.0.2"])
    assert response["status_code"] == 403
    assert client.get("/api/v1/scans", headers=auth).json() == []


def test_real_nmap_can_be_cancelled(real_client, banner_server: int) -> None:
    client, auth = real_client
    pid = create_project(client, auth, ("include", "127.0.0.1/32"))
    # Version detection with a slow timing template keeps nmap busy for a while.
    launched = launch(
        client,
        auth,
        pid,
        ["127.0.0.1"],
        options={"ports": "1-65535", "timing": 2, "skip_host_discovery": True},
    )
    wait_for_status(client, auth, launched["scan_id"], "running")
    response = client.post(f"/api/v1/scans/{launched['scan_id']}/cancel", headers=auth)
    assert response.json()["status"] == "cancelled"


@pytest.mark.parametrize("target", ["10.0.0.1", "8.8.8.8", "127.0.0.0/8", "scanme.nmap.org"])
async def test_guard_refuses_non_loopback_even_for_integration_tests(target: str) -> None:
    import asyncio

    with pytest.raises(pytest.fail.Exception, match="may only scan loopback"):
        await asyncio.create_subprocess_exec(NMAP, "-sT", "-n", "--", target)


@pytest.fixture
def http_server() -> Iterator[ThreadingHTTPServer]:
    """A temporary HTTP server on an ephemeral 127.0.0.1 port (stop it to close the port)."""

    class Quiet(SimpleHTTPRequestHandler):
        def log_message(self, *args: object) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Quiet)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_inventory_and_comparison_against_a_real_http_service(real_client, http_server) -> None:
    """Open → confirmed closed → not checked, with real Nmap, on 127.0.0.1 only."""
    client, auth = real_client
    pid = create_project(client, auth, ("include", "127.0.0.1/32"))
    port = http_server.server_address[1]
    options = {"timing": 4, "skip_host_discovery": True}

    def scan(ports: str) -> dict:
        launched = launch(
            client,
            auth,
            pid,
            ["127.0.0.1"],
            options={**options, "ports": ports},
            timeout_seconds=120,
        )
        result = wait_for_status(client, auth, launched["scan_id"], "completed", "failed")
        assert result["status"] == "completed", result["error"]
        return result

    first = scan(str(port))
    http_server.shutdown()
    http_server.server_close()  # the port is now closed
    second = scan(str(port))
    other = socket.socket()
    other.bind(("127.0.0.1", 0))
    unrelated = other.getsockname()[1]
    other.close()
    third = scan(str(unrelated))  # never checks the HTTP port

    url = f"/api/v1/projects/{pid}/scans/compare"
    closed = client.get(f"{url}?baseline={first['id']}&comparison={second['id']}", headers=auth)
    assert [(c["category"], c["kind"], c["port"]) for c in closed.json()["changes"]] == [
        ("removed", "port_closed", port)
    ]
    unchecked = client.get(
        f"{url}?baseline={first['id']}&comparison={third['id']}", headers=auth
    ).json()
    assert [(c["category"], c["kind"], c["port"]) for c in unchecked["changes"]] == [
        ("inconclusive", "port_not_checked", port)
    ]
    assert unchecked["summary"]["removed"] == 0

    (asset,) = client.get(f"/api/v1/assets?project_id={pid}", headers=auth).json()
    detail = client.get(f"/api/v1/assets/{asset['uid']}", headers=auth).json()
    http = next(p for p in detail["ports"] if p["port"] == port)
    assert http["state"] == "closed"  # from the second scan; the third did not look
    assert http["state_scan_id"] == second["id"]
    assert http["last_open_at"] is not None
    assert http["service_name"] == "http" and http["identification"] == "detected"
    assert [o["scan_id"] for o in detail["observations"]] == [
        third["id"],
        second["id"],
        first["id"],
    ]
    for observation in detail["observations"]:
        prov = observation["provenance"]
        assert prov["tool"] == "nmap" and prov["tool_version"]
        assert prov["requested_targets"] == ["127.0.0.1"]
        verify = client.get(f"/api/v1/scans/{prov['scan_id']}/evidence/verify", headers=auth)
        assert verify.json()["verified"] is True
