from __future__ import annotations

import pytest

from traceforge import __version__
from traceforge.cli import main


def test_version_command(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["version"]) == 0
    assert capsys.readouterr().out.strip() == f"traceforge {__version__}"


def test_serve_refuses_public_bind(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["serve", "--host", "0.0.0.0"]) == 2
    assert "non-loopback" in capsys.readouterr().err


def test_serve_reports_unusable_database_path(tmp_path, capsys: pytest.CaptureFixture[str]) -> None:
    blocker = tmp_path / "not-a-directory"
    blocker.write_text("")

    assert main(["serve", "--db", str(blocker / "traceforge.db")]) == 1
    err = capsys.readouterr().err
    assert "cannot initialise database" in err
    assert "Traceback" not in err


def test_serve_passes_validated_settings_to_uvicorn(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import uvicorn

    calls: list[dict] = []
    monkeypatch.setattr(uvicorn, "run", lambda app, **kwargs: calls.append(kwargs))

    assert main(["serve", "--port", "8123", "--db", str(tmp_path / "t.db")]) == 0
    assert calls == [{"host": "127.0.0.1", "port": 8123, "proxy_headers": False}]


def test_serve_reload_keeps_loopback_and_exports_settings(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import os

    import uvicorn

    calls: list[tuple[object, dict]] = []
    monkeypatch.setattr(uvicorn, "run", lambda app, **kwargs: calls.append((app, kwargs)))
    db = tmp_path / "t.db"

    assert main(["serve", "--reload", "--port", "8124", "--db", str(db)]) == 0

    app, kwargs = calls[0]
    assert app == "traceforge.api.app:create_app"
    assert kwargs["factory"] is True and kwargs["reload"] is True
    assert kwargs["host"] == "127.0.0.1"
    assert os.environ["TRACEFORGE_PORT"] == "8124"
    assert os.environ["TRACEFORGE_DB_PATH"] == str(db)


def test_serve_reload_refuses_public_bind(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["serve", "--reload", "--host", "0.0.0.0"]) == 2
    assert "non-loopback" in capsys.readouterr().err


def test_environment_is_clean_between_tests() -> None:
    # Runs after the reload test above; its exported variables must not leak.
    import os

    assert "TRACEFORGE_PORT" not in os.environ
    assert "TRACEFORGE_DB_PATH" not in os.environ


def _wire_cli_to_app(monkeypatch: pytest.MonkeyPatch, app) -> None:
    """Point CLI client commands at an in-process app instead of a live server."""
    import httpx

    from tests.conftest import BASE_URL
    from traceforge import cli
    from traceforge.client import TraceForgeClient

    app.state.database.initialize()
    monkeypatch.setattr(
        cli,
        "_make_client",
        lambda settings: TraceForgeClient(
            BASE_URL,
            token_provider=lambda: app.state.api_token,
            transport=httpx.ASGITransport(app=app),
        ),
    )


def test_cli_project_and_scope_workflow(
    app, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _wire_cli_to_app(monkeypatch, app)

    assert main(["project", "create", "acme", "--authorization-ref", "SOW-42"]) == 0
    assert main(["scope", "add", "1", "include", "10.0.0.0/24"]) == 0
    assert main(["scope", "add", "1", "exclude", "10.0.0.13", "--note", "prod db"]) == 0
    capsys.readouterr()

    assert main(["scope", "check", "1", "10.0.0.5"]) == 0
    assert "ALLOW  10.0.0.5" in capsys.readouterr().out
    assert main(["scope", "check", "1", "10.0.0.13", "8.8.8.8"]) == 1
    out = capsys.readouterr().out
    assert "DENY   10.0.0.13" in out and "DENY   8.8.8.8" in out

    assert main(["scope", "add", "1", "include", "0.0.0.0/0"]) == 1
    assert "too broad" in capsys.readouterr().err

    assert main(["project", "list"]) == 0
    assert "#1  acme  [SOW-42]  2 rule(s)" in capsys.readouterr().out


def test_cli_dashboard_link(
    app, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _wire_cli_to_app(monkeypatch, app)
    assert main(["dashboard-link"]) == 0
    assert "http://127.0.0.1:5173/#code=" in capsys.readouterr().out


def test_cli_client_without_server_token(capsys: pytest.CaptureFixture[str], tmp_path) -> None:
    assert main(["project", "list", "--api-url", "http://127.0.0.1:9"]) == 1
    assert "no API token found" in capsys.readouterr().err


def test_cli_refuses_remote_api_url(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["project", "list", "--api-url", "http://203.0.113.9:8000"]) == 2
    assert "loopback" in capsys.readouterr().err


def test_serve_refuses_token_dir_owned_by_someone_else(
    tmp_path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import os

    real_uid = os.getuid()
    monkeypatch.setattr(os, "getuid", lambda: real_uid + 1)
    assert main(["serve", "--db", str(tmp_path / "t.db")]) == 1
    assert "unsafe token directory" in capsys.readouterr().err


def test_cli_scan_workflow(
    app, fake_nmap, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _wire_cli_to_app(monkeypatch, app)
    assert main(["project", "create", "acme", "--authorization-ref", "SOW-42"]) == 0
    assert main(["scope", "add", "1", "include", "10.0.0.0/24"]) == 0
    capsys.readouterr()

    assert main(["scan", "run", "1", "10.0.0.5", "-p", "22,80", "--timing", "4", "--wait"]) == 0
    out = capsys.readouterr().out
    assert "Queued scan #1 of 10.0.0.5" in out
    assert "COMPLETED" in out
    assert "22/tcp" in out and "OpenSSH 9.6p1" in out
    argv = fake_nmap.calls[0]
    assert argv[argv.index("-p") + 1] == "22,80" and "-T4" in argv

    assert main(["scan", "list"]) == 0
    assert "#1    completed" in capsys.readouterr().out
    assert main(["scan", "show", "1"]) == 0
    assert "evidence: scan-1-nmap-" in capsys.readouterr().out

    assert main(["scan", "run", "1", "10.0.0.6", "8.8.8.8"]) == 1
    err = capsys.readouterr().err
    assert "nothing was launched" in err
    assert "ALLOW  10.0.0.6" in err and "DENY   8.8.8.8" in err
    assert len(fake_nmap.calls) == 1

    assert main(["scan", "cancel", "1"]) == 1
    assert "already completed" in capsys.readouterr().err


def test_cli_scan_options_are_validated(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit):
        main(["scan", "run", "1", "10.0.0.5", "--timing", "1"])
    with pytest.raises(SystemExit):
        main(["scan", "run", "1", "10.0.0.5", "-p", "22", "--top-ports", "10"])


def test_cli_assets_and_scan_compare(
    app, settings, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from tests.test_tui import seed_inventory

    _wire_cli_to_app(monkeypatch, app)
    first, second = seed_inventory(app, settings)

    assert main(["asset", "list", "--project", "1"]) == 0
    out = capsys.readouterr().out
    assert "10.0.0.5" in out and "[acme]" in out and "1 open: 22/ssh" in out
    uid = out.split()[0]
    assert uid.startswith("ast_")

    assert main(["asset", "show", uid]) == 0
    out = capsys.readouterr().out
    assert "22/tcp" in out and "detected" in out and "OpenSSH 9.7p1" in out
    assert "8080/tcp" in out and "closed" in out and "port-label" in out
    assert f"scan #{second}" in out and "requested 10.0.0.0/24 → 10.0.0.5" in out

    assert main(["scan", "compare", str(first), str(second)]) == 0
    out = capsys.readouterr().out
    assert "0 added · 1 removed · 1 changed · 0 inconclusive" in out
    assert "REMOVED" in out and "port_closed" in out and "was open, now confirmed closed" in out

    assert main(["scan", "compare", str(first), str(first)]) == 1
    assert "two different scans" in capsys.readouterr().err
    assert main(["asset", "show", "ast_0000000000000000"]) == 1
    assert "404" in capsys.readouterr().err
