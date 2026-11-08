"""Generation and private on-disk storage of the per-server API token.

The token authenticates local, non-browser clients (the TUI and CLI). It is
regenerated every time the server starts and written to a file readable only
by the current OS user, so the operating system's user boundary is what
protects it.
"""

from __future__ import annotations

import os
import secrets
import stat
from pathlib import Path

TOKEN_BYTES = 32


class InsecureTokenFileError(RuntimeError):
    """The token file or its directory has unsafe ownership or permissions."""


def generate_secret(nbytes: int = TOKEN_BYTES) -> str:
    return secrets.token_urlsafe(nbytes)


def ensure_private_dir(path: Path) -> None:
    """Create ``path`` as a 0700 directory owned by the current user."""
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    st = path.lstat()
    if not stat.S_ISDIR(st.st_mode):
        raise InsecureTokenFileError(f"{path} is not a directory")
    if st.st_uid != os.getuid():
        raise InsecureTokenFileError(f"{path} is owned by another user")
    if st.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        os.chmod(path, 0o700)


def write_token_file(path: Path, token: str) -> None:
    """Atomically write ``token`` to ``path`` with mode 0600."""
    ensure_private_dir(path.parent)
    tmp = path.with_name(f".{path.name}.{secrets.token_hex(4)}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="ascii") as handle:
            handle.write(token + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


def read_token_file(path: Path) -> str | None:
    """Return the token stored at ``path``, or None if there is no file.

    Refuses files that are not owned by this user or that other users could
    read, since such a token cannot be trusted to be the server's.
    """
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return None
    with os.fdopen(fd, encoding="ascii") as handle:
        st = os.fstat(handle.fileno())
        if st.st_uid != os.getuid():
            raise InsecureTokenFileError(f"{path} is owned by another user")
        if st.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
            raise InsecureTokenFileError(f"{path} is accessible to other users (expected 0600)")
        token = handle.read().strip()
    return token or None


def remove_token_file(path: Path, token: str) -> None:
    """Delete the token file if it still holds *our* token."""
    try:
        if read_token_file(path) == token:
            path.unlink()
    except (OSError, InsecureTokenFileError):
        pass
