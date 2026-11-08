"""ASGI middleware that admits only requests that are provably local.

It runs before routing and authentication and enforces:

* **Trusted Host** — the ``Host`` header must name a loopback host *and* the
  port the API listens on. A DNS-rebinding page (``evil.example`` resolving
  to 127.0.0.1) always sends its own hostname, so it is rejected here.
* **No CORS** — the dashboard reaches the API same-origin through the Vite
  proxy, so the API never needs cross-origin access. Preflight requests are
  refused and no ``Access-Control-*`` header is ever emitted, which means a
  browser will never expose an API response to another origin.
* **Origin allowlist** — any request carrying an ``Origin`` header must come
  from a configured dashboard origin. ``Origin: null`` is refused.
* **Fetch metadata** — ``Sec-Fetch-Site: cross-site``/``same-site`` requests
  are refused. Note that other ports on 127.0.0.1 count as *same-site*, which
  is why SameSite cookies alone are not enough on localhost.
* **Defensive response headers** on every response.
"""

from __future__ import annotations

from collections.abc import Iterable

from starlette.datastructures import Headers, MutableHeaders
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send
from starlette.websockets import WebSocketClose

ALLOWED_FETCH_SITES = frozenset({"same-origin", "none"})
LOOPBACK_NAMES = frozenset({"127.0.0.1", "localhost", "::1"})

SECURITY_HEADERS = {
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "no-referrer",
    "cross-origin-resource-policy": "same-origin",
    "cache-control": "no-store",
}
API_CSP = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'; sandbox"


def parse_host_header(value: str) -> tuple[str, int | None] | None:
    """Split a Host header into (hostname, port). Returns None if malformed."""
    if not value or any(c.isspace() for c in value):
        return None
    if value.startswith("["):
        end = value.find("]")
        if end == -1:
            return None
        host, rest = value[1:end], value[end + 1 :]
        if rest and not rest.startswith(":"):
            return None
        port_text = rest[1:] if rest else None
    else:
        if value.count(":") > 1:
            return None  # bare IPv6 without brackets
        host, sep, port_text = value.partition(":")
        port_text = port_text if sep else None
    if not host:
        return None
    if port_text is None:
        return host.lower(), None
    if not port_text.isdigit() or not 0 < int(port_text) < 65536:
        return None
    return host.lower(), int(port_text)


class LocalRequestGuard:
    def __init__(
        self,
        app: ASGIApp,
        *,
        port: int,
        allowed_origins: Iterable[str],
        extra_hosts: Iterable[str] = (),
        csp_exempt_paths: Iterable[str] = (),
    ) -> None:
        self.app = app
        self.port = port
        self.allowed_hosts = LOOPBACK_NAMES | {h.lower() for h in extra_hosts}
        self.allowed_origins = frozenset(allowed_origins)
        self.csp_exempt_paths = tuple(csp_exempt_paths)

    def check(self, scope: Scope) -> tuple[int, str] | None:
        """Return (status, reason) if the request must be rejected."""
        headers = Headers(scope=scope)

        parsed = parse_host_header(headers.get("host", ""))
        if parsed is None:
            return 400, "Invalid Host header"
        hostname, port = parsed
        if hostname not in self.allowed_hosts or (port or 80) != self.port:
            return 400, "Invalid Host header"

        if (
            scope["type"] == "http"
            and scope["method"] == "OPTIONS"
            and "access-control-request-method" in headers
        ):
            return 403, "Cross-origin requests are not permitted"

        origin = headers.get("origin")
        if origin is not None and origin.lower() not in self.allowed_origins:
            return 403, "Origin not allowed"

        fetch_site = headers.get("sec-fetch-site")
        if fetch_site is not None and fetch_site.lower() not in ALLOWED_FETCH_SITES:
            return 403, "Cross-site requests are not permitted"
        return None

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return

        rejection = self.check(scope)
        if rejection is not None:
            if scope["type"] == "websocket":
                await WebSocketClose(code=1008)(scope, receive, send)
                return
            status, reason = rejection
            response = JSONResponse({"detail": reason}, status_code=status)
            await response(scope, receive, self._with_security_headers(scope, send))
            return

        if scope["type"] == "http":
            send = self._with_security_headers(scope, send)
        await self.app(scope, receive, send)

    def _with_security_headers(self, scope: Scope, send: Send) -> Send:
        exempt = self.csp_exempt_paths and scope["path"].startswith(self.csp_exempt_paths)
        add_csp = not exempt

        async def wrapped(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                for name, value in SECURITY_HEADERS.items():
                    headers[name] = value
                if add_csp:
                    headers["content-security-policy"] = API_CSP
                for name in [k for k in headers if k.startswith("access-control-")]:
                    del headers[name]
            await send(message)

        return wrapped
