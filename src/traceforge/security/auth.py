"""Authentication dependencies for API routes.

Two credential types are accepted:

* ``Authorization: Bearer <api token>`` — for the TUI and CLI, which read the
  token from the owner-only token file.
* The ``traceforge_session`` cookie — for the web dashboard. State-changing
  requests must also send the session's CSRF token in ``X-TraceForge-CSRF``.
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass
from typing import Annotated, Literal

from fastapi import Depends, HTTPException, Request, status

from traceforge.security.sessions import Session, SessionStore

SESSION_COOKIE = "traceforge_session"
CSRF_HEADER = "X-TraceForge-CSRF"
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


@dataclass(frozen=True)
class Principal:
    method: Literal["token", "session"]
    session: Session | None = None
    session_id: str | None = None

    @property
    def actor(self) -> str:
        return "cli" if self.method == "token" else "dashboard"


def _unauthorized(detail: str = "Authentication required") -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers={"WWW-Authenticate": "Bearer"},
    )


def _equal(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8", "surrogateescape"), b.encode("utf-8"))


def require_principal(request: Request) -> Principal:
    authorization = request.headers.get("authorization")
    if authorization is not None:
        scheme, _, credential = authorization.partition(" ")
        if scheme.lower() != "bearer" or not _equal(
            credential.strip(), request.app.state.api_token
        ):
            raise _unauthorized("Invalid API token")
        return Principal(method="token")

    session_id = request.cookies.get(SESSION_COOKIE)
    if session_id:
        store: SessionStore = request.app.state.sessions
        session = store.get(session_id)
        if session is None:
            raise _unauthorized("Session expired or invalid")
        if request.method not in SAFE_METHODS:
            supplied = request.headers.get(CSRF_HEADER, "")
            if not supplied or not _equal(supplied, session.csrf_token):
                raise HTTPException(status.HTTP_403_FORBIDDEN, "Missing or invalid CSRF token")
        return Principal(method="session", session=session, session_id=session_id)

    raise _unauthorized()


def require_token_principal(
    principal: Annotated[Principal, Depends(require_principal)],
) -> Principal:
    """Only the API token (i.e. a local process of the owning user) may pass."""
    if principal.method != "token":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "This action requires the API token")
    return principal


AuthenticatedPrincipal = Annotated[Principal, Depends(require_principal)]
TokenPrincipal = Annotated[Principal, Depends(require_token_principal)]
