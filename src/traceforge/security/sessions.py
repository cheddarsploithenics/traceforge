"""In-memory store for dashboard sign-in codes and browser sessions.

Flow:
1. A trusted local channel (server startup output, or ``traceforge
   dashboard-link`` using the API token) obtains a single-use login code.
2. The dashboard exchanges that code for a session. The session id is only
   ever stored in an ``HttpOnly`` cookie, so page scripts cannot read it.
3. Each session carries a CSRF token that the dashboard keeps in memory and
   must echo in a header on state-changing requests.

Only SHA-256 digests of codes and session ids are kept, and everything is
discarded when the server stops.
"""

from __future__ import annotations

import hashlib
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass

from traceforge.security.tokens import generate_secret

MAX_PENDING_LOGIN_CODES = 16


def _digest(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8", "surrogateescape")).hexdigest()


@dataclass(frozen=True)
class Session:
    csrf_token: str
    created_at: float
    expires_at: float


class SessionStore:
    def __init__(
        self,
        *,
        session_ttl: float,
        login_code_ttl: float,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._session_ttl = session_ttl
        self._login_code_ttl = login_code_ttl
        self._clock = clock
        self._codes: dict[str, float] = {}  # digest -> expiry
        self._sessions: dict[str, Session] = {}  # digest -> session
        self._lock = threading.Lock()

    def _prune(self, now: float) -> None:
        self._codes = {k: exp for k, exp in self._codes.items() if exp > now}
        self._sessions = {k: s for k, s in self._sessions.items() if s.expires_at > now}

    def issue_login_code(self) -> tuple[str, float]:
        """Return a new single-use login code and its expiry timestamp."""
        code = generate_secret()
        with self._lock:
            now = self._clock()
            self._prune(now)
            if len(self._codes) >= MAX_PENDING_LOGIN_CODES:
                oldest = min(self._codes, key=self._codes.__getitem__)
                del self._codes[oldest]
            expires_at = now + self._login_code_ttl
            self._codes[_digest(code)] = expires_at
        return code, expires_at

    def redeem_login_code(self, code: str) -> tuple[str, Session] | None:
        """Consume ``code`` and open a session. Returns (session_id, session)."""
        with self._lock:
            now = self._clock()
            self._prune(now)
            if self._codes.pop(_digest(code), None) is None:
                return None
            session_id = generate_secret()
            session = Session(
                csrf_token=generate_secret(),
                created_at=now,
                expires_at=now + self._session_ttl,
            )
            self._sessions[_digest(session_id)] = session
        return session_id, session

    def get(self, session_id: str) -> Session | None:
        with self._lock:
            session = self._sessions.get(_digest(session_id))
            if session is None:
                return None
            if session.expires_at <= self._clock():
                del self._sessions[_digest(session_id)]
                return None
            return session

    def revoke(self, session_id: str) -> None:
        with self._lock:
            self._sessions.pop(_digest(session_id), None)
