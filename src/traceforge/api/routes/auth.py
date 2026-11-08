"""Session management for the dashboard and login-code issuance."""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, HTTPException, Request, Response, status

from traceforge.api.deps import get_app_settings
from traceforge.schemas import LoginCode, LoginRequest, SessionInfo
from traceforge.security.auth import SESSION_COOKIE, AuthenticatedPrincipal, TokenPrincipal
from traceforge.security.sessions import SessionStore

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


def _ts(value: float) -> datetime:
    return datetime.fromtimestamp(value, UTC)


@router.post("/session", response_model=SessionInfo, summary="Exchange a login code")
def create_session(body: LoginRequest, request: Request, response: Response) -> SessionInfo:
    store: SessionStore = request.app.state.sessions
    redeemed = store.redeem_login_code(body.code)
    if redeemed is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired login code")
    session_id, session = redeemed
    response.set_cookie(
        SESSION_COOKIE,
        session_id,
        httponly=True,
        samesite="strict",
        path="/api",
        # No Max-Age: a browser-session cookie. Expiry is enforced server-side.
        # Not "Secure": the API is plain HTTP on loopback only.
    )
    return SessionInfo(
        method="session", csrf_token=session.csrf_token, expires_at=_ts(session.expires_at)
    )


@router.get("/session", response_model=SessionInfo, summary="Describe the current credential")
def read_session(principal: AuthenticatedPrincipal) -> SessionInfo:
    if principal.session is None:
        return SessionInfo(method="token")
    return SessionInfo(
        method="session",
        csrf_token=principal.session.csrf_token,
        expires_at=_ts(principal.session.expires_at),
    )


@router.delete("/session", status_code=status.HTTP_204_NO_CONTENT, summary="Sign out")
def delete_session(principal: AuthenticatedPrincipal, request: Request) -> Response:
    if principal.session_id is not None:
        request.app.state.sessions.revoke(principal.session_id)
    response = Response(status_code=status.HTTP_204_NO_CONTENT)
    response.delete_cookie(SESSION_COOKIE, path="/api", httponly=True, samesite="strict")
    return response


@router.post(
    "/login-codes",
    response_model=LoginCode,
    status_code=status.HTTP_201_CREATED,
    summary="Mint a single-use dashboard sign-in link (API token only)",
)
def create_login_code(_: TokenPrincipal, request: Request) -> LoginCode:
    store: SessionStore = request.app.state.sessions
    code, expires_at = store.issue_login_code()
    settings = get_app_settings(request)
    return LoginCode(
        code=code, url=f"{settings.dashboard_url}/#code={code}", expires_at=_ts(expires_at)
    )
