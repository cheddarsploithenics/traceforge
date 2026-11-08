from __future__ import annotations

import pytest
from pydantic import ValidationError

from traceforge.config import Settings, is_loopback_host


@pytest.mark.parametrize("host", ["127.0.0.1", "127.0.0.53", "::1", "localhost", "LOCALHOST"])
def test_loopback_hosts_accepted(host: str) -> None:
    assert is_loopback_host(host)
    assert Settings(host=host).host == host


@pytest.mark.parametrize("host", ["0.0.0.0", "::", "192.168.1.10", "example.com", ""])
def test_non_loopback_hosts_rejected(host: str) -> None:
    assert not is_loopback_host(host)
    with pytest.raises(ValidationError, match="non-loopback"):
        Settings(host=host)


def test_env_cannot_bypass_loopback(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TRACEFORGE_HOST", "0.0.0.0")
    with pytest.raises(ValidationError):
        Settings()


def test_defaults_bind_to_localhost() -> None:
    settings = Settings()
    assert settings.host == "127.0.0.1"
    assert settings.port == 8000
    assert settings.base_url == "http://127.0.0.1:8000"


def test_base_url_brackets_ipv6_and_honours_override() -> None:
    assert Settings(host="::1", port=9000).base_url == "http://[::1]:9000"
    assert Settings(api_url="http://127.0.0.1:1234/").base_url == "http://127.0.0.1:1234"


def test_default_db_path_uses_xdg_data_home(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    assert Settings().db_path == tmp_path / "traceforge" / "traceforge.db"


@pytest.mark.parametrize(
    "origin",
    [
        "https://evil.example",
        "http://192.168.1.5:5173",
        "http://127.0.0.1:5173/path",
        "http://user@127.0.0.1:5173",
        "127.0.0.1:5173",
        "null",
    ],
)
def test_allowed_origins_must_be_bare_loopback_origins(origin: str) -> None:
    with pytest.raises(ValidationError):
        Settings(allowed_origins=[origin])


def test_allowed_origins_are_normalised() -> None:
    settings = Settings(allowed_origins=["HTTP://LOCALHOST:3000/", "http://[::1]:3000"])
    assert settings.allowed_origins == ["http://localhost:3000", "http://[::1]:3000"]


@pytest.mark.parametrize("field", ["api_url", "dashboard_url"])
@pytest.mark.parametrize(
    "url", ["http://example.com:8000", "http://10.0.0.5:8000", "ftp://127.0.0.1"]
)
def test_client_urls_must_stay_on_loopback(field: str, url: str) -> None:
    # The CLI/TUI send the API token to api_url; it must never leave the machine.
    with pytest.raises(ValidationError):
        Settings(**{field: url})


def test_allowed_origins_from_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TRACEFORGE_ALLOWED_ORIGINS", '["http://127.0.0.1:3000"]')
    assert Settings().allowed_origins == ["http://127.0.0.1:3000"]
    monkeypatch.setenv("TRACEFORGE_ALLOWED_ORIGINS", '["https://evil.example"]')
    with pytest.raises(ValidationError):
        Settings()
