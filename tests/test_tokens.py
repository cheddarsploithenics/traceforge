from __future__ import annotations

import os
from pathlib import Path

import pytest

from traceforge.config import Settings, default_token_dir
from traceforge.security.tokens import (
    InsecureTokenFileError,
    read_token_file,
    remove_token_file,
    write_token_file,
)


def test_write_and_read_round_trip(tmp_path: Path) -> None:
    path = tmp_path / "dir" / "api.token"
    write_token_file(path, "s3cret")
    assert read_token_file(path) == "s3cret"
    assert path.stat().st_mode & 0o777 == 0o600


def test_missing_file_reads_as_none(tmp_path: Path) -> None:
    assert read_token_file(tmp_path / "nope") is None


def test_group_readable_token_file_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "api.token"
    write_token_file(path, "s3cret")
    os.chmod(path, 0o640)
    with pytest.raises(InsecureTokenFileError, match="other users"):
        read_token_file(path)


def test_symlinked_token_file_is_refused(tmp_path: Path) -> None:
    real = tmp_path / "real"
    write_token_file(real, "s3cret")
    link = tmp_path / "link"
    link.symlink_to(real)
    with pytest.raises(OSError):
        read_token_file(link)


def test_loose_token_directory_is_tightened(tmp_path: Path) -> None:
    directory = tmp_path / "run"
    directory.mkdir(mode=0o777)
    os.chmod(directory, 0o777)
    write_token_file(directory / "api.token", "x")
    assert directory.stat().st_mode & 0o777 == 0o700


def test_remove_only_deletes_own_token(tmp_path: Path) -> None:
    path = tmp_path / "api.token"
    write_token_file(path, "newer-server")
    remove_token_file(path, "older-server")
    assert path.exists()
    remove_token_file(path, "newer-server")
    assert not path.exists()


def test_world_writable_runtime_dir_is_not_trusted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # WSLg ships XDG_RUNTIME_DIR=/mnt/wslg/runtime-dir with mode 0777.
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    os.chmod(runtime, 0o777)
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(runtime))
    assert default_token_dir() == tmp_path / "xdg" / "traceforge" / "run"

    os.chmod(runtime, 0o700)
    assert default_token_dir() == runtime / "traceforge"


def test_token_path_is_per_port() -> None:
    assert Settings(port=8000).token_path.name == "api-8000.token"
    assert Settings(api_url="http://127.0.0.1:9001").token_path.name == "api-9001.token"
