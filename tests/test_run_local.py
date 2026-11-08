"""scripts/run_local.py: the one-terminal launcher's planning and preflight checks.

Starting the real servers is covered manually (see README); these tests check
the logic that decides what runs where and what the user is told.
"""

from __future__ import annotations

import importlib.util
import socket
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "run_local.py"
spec = importlib.util.spec_from_file_location("traceforge_run_local", SCRIPT)
assert spec and spec.loader
launcher = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = launcher  # dataclasses look their module up while executing
spec.loader.exec_module(launcher)


def plan_for(*argv: str):
    return launcher.make_plan(launcher.parse_args(list(argv)), base_env={"PATH": "/usr/bin"})


def test_dev_plan_wires_api_and_dashboard_together() -> None:
    plan = plan_for()
    assert plan.api_command()[-4:] == ["traceforge", "serve", "--port", "8000"]
    assert plan.web_command("npm") == ["npm", "run", "dev"]
    assert plan.env["TRACEFORGE_API_URL"] == "http://127.0.0.1:8000"
    assert plan.env["TRACEFORGE_DASHBOARD_URL"] == "http://127.0.0.1:5173"
    assert plan.env["PATH"] == "/usr/bin"  # the rest of the environment is kept


def test_prod_plan_uses_hardened_preview_and_custom_port() -> None:
    plan = plan_for("--prod", "--api-port", "8123")
    assert plan.web_command("npm") == ["npm", "run", "preview"]
    assert plan.env["TRACEFORGE_PORT"] == "8123"
    assert plan.env["TRACEFORGE_API_URL"] == "http://127.0.0.1:8123"
    assert plan.env["TRACEFORGE_DASHBOARD_URL"] == "http://127.0.0.1:4173"
    settings = plan.settings()
    assert settings.base_url == "http://127.0.0.1:8123"
    assert settings.token_path.name == "api-8123.token"


def test_port_in_use() -> None:
    with socket.socket() as server:
        server.bind(("127.0.0.1", 0))
        server.listen()
        port = server.getsockname()[1]
        assert launcher.port_in_use(port)
    assert not launcher.port_in_use(port)


@pytest.fixture
def web_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    (tmp_path / "node_modules").mkdir()
    monkeypatch.setattr(launcher, "WEB", tmp_path)
    monkeypatch.setattr(launcher.shutil, "which", lambda name: f"/usr/bin/{name}")
    return tmp_path


def test_preflight_names_busy_ports(web_dir: Path) -> None:
    with socket.socket() as server:
        server.bind(("127.0.0.1", 0))
        server.listen()
        port = server.getsockname()[1]
        with pytest.raises(launcher.LaunchError, match=rf"127.0.0.1:{port} \(API"):
            launcher.preflight(plan_for("--api-port", str(port)))


def test_preflight_explains_missing_dependencies(web_dir: Path, monkeypatch) -> None:
    (web_dir / "node_modules").rmdir()
    with pytest.raises(launcher.LaunchError, match="make install"):
        launcher.preflight(plan_for("--api-port", "1"))
    monkeypatch.setattr(launcher.shutil, "which", lambda name: None)
    with pytest.raises(launcher.LaunchError, match="npm was not found"):
        launcher.preflight(plan_for())


def test_banner() -> None:
    url = "http://127.0.0.1:5173/#code=abc"
    plain = launcher.banner(plan_for(), url, None)
    assert url in plain and "make link" in plain and "Demo" not in plain

    demo = launcher.banner(plan_for("--demo", "--api-port", "8001"), url, 3)
    assert 'project #3 "Local lab"' in demo
    assert "ports 2222,2223" in demo
    assert "dashboard-link --api-url http://127.0.0.1:8001" in demo
