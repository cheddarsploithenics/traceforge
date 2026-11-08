# TraceForge

Open-source, evidence-driven penetration testing orchestration platform for Kali Linux.

> **Status: v0.1 (pre-alpha).** A hardened local API, a web dashboard, a terminal interface,
> and project-level authorized scope enforcement. **No scanning tools are wired up yet:**
> the execution layer exists, but no tool adapters are registered.

> **Legal notice:** TraceForge is intended for authorised security testing only. Only run it
> against systems you own or have explicit written permission to test.

## Architecture

```
 ┌──────────────────────┐        ┌──────────────────────┐
 │  Web dashboard       │        │  Terminal UI         │
 │  React + TypeScript  │        │  Textual             │
 │  (web/)              │        │  (traceforge.tui)    │
 └──────────┬───────────┘        └──────────┬───────────┘
            │ HTTP (fetch)                   │ HTTP (httpx)
            └───────────────┬────────────────┘
                            ▼
              ┌───────────────────────────┐
              │  TraceForge API (FastAPI) │  bound to 127.0.0.1 only
              │  1. request guard         │  Host / Origin / no CORS
              │  2. authentication        │  token (TUI, CLI) | session (web)
              │  3. executor              │  scope check before any tool
              └─────────────┬─────────────┘
                            ▼
              ┌───────────────────────────┐
              │  SQLite                   │  projects, scope, audit log,
              │  traceforge.db            │  scan history
              └───────────────────────────┘
```

Both interfaces are thin clients of the same HTTP API, so business logic lives in one place.
Response models are defined once in [`src/traceforge/schemas.py`](src/traceforge/schemas.py) and
mirrored in [`web/src/api/client.ts`](web/src/api/client.ts).

## Security model

TraceForge controls offensive tooling, so the local API is treated as a security boundary.
The full analysis is in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md). In short:

- **Localhost only.** The API, the dashboard servers, and every URL a client sends
  credentials to must be loopback addresses. This is enforced in configuration validation,
  so flags and environment variables can't bypass it.
- **Trusted Host header.** Requests whose `Host` isn't a loopback name plus the API's port
  are rejected before routing. This defeats DNS rebinding.
- **No CORS, strict Origin.** The dashboard is same-origin through the Vite proxy, so the
  API never sends CORS headers and refuses all preflights. Requests from foreign origins or
  with `Sec-Fetch-Site: cross-site/same-site` get `403`.
- **Authentication on every `/api` route.**
  - **TUI and CLI:** a random bearer token, regenerated on every server start and stored in
    an owner-only (`0600`) file.
  - **Dashboard:** a single-use sign-in link that is exchanged for an `HttpOnly`,
    `SameSite=Strict` session cookie, plus a per-session CSRF token held only in memory.
    Nothing is stored in `localStorage`.
- **Authorized scope before execution.** Every tool launch goes through one executor that
  enforces the project's scope. Scope is deny-by-default, exclusions win, the authorization
  window is checked, and hostnames are resolved and checked. The result is recorded in an
  audit log *before* a tool is even looked up.

## Requirements

- Kali Linux (or any recent Linux)
- Python 3.11+
- Node.js 22.22+ or 24.15+ (24 LTS recommended) and npm, only for the web dashboard

## Installation

```bash
git clone <your-fork-url> traceforge
cd traceforge

# Backend + terminal UI
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"

# Web dashboard
cd web && npm ci && cd ..
```

Or simply `make install`. Activate the virtualenv (`source .venv/bin/activate`) to put the
`traceforge` command on your `PATH`; the examples below assume it is active.

## Running

Start the API first; the dashboard and the TUI both depend on it.

### 1. API server

```bash
traceforge serve                 # http://127.0.0.1:8000
traceforge serve --port 8080     # different port
```

On startup the server:

- writes a fresh API token to an owner-only file (shown in the log), which the TUI and CLI
  read automatically;
- prints a **single-use dashboard sign-in link** that expires after 5 minutes.

Health check: <http://127.0.0.1:8000/health>. Interactive API docs are off by default
(`TRACEFORGE_ENABLE_DOCS=true` turns them on at <http://127.0.0.1:8000/docs>).

For auto-reload during backend development:

```bash
traceforge serve --reload
```

Use this rather than invoking `uvicorn` directly: the `traceforge` command is what enforces
the loopback-only bind address.

### 2. Web dashboard

```bash
cd web
npm run dev                          # development: http://127.0.0.1:5173
npm run build && npm run preview     # hardened build with strict CSP: http://127.0.0.1:4173
```

Open the sign-in link printed by `traceforge serve`, or get a new one at any time:

```bash
traceforge dashboard-link
```

The Vite server proxies `/health` and `/api/` to the API, so the browser only ever talks to
one origin. If the API runs on a different port:

```bash
TRACEFORGE_API_URL=http://127.0.0.1:8080 npm run dev
```

The sign-in link points to `TRACEFORGE_DASHBOARD_URL` (default `http://127.0.0.1:5173`). If
you use the preview server, set `TRACEFORGE_DASHBOARD_URL=http://127.0.0.1:4173` before
starting the API.

### 3. Terminal UI

In a second terminal:

```bash
traceforge tui
traceforge tui --api-url http://127.0.0.1:8080
```

Keys: `r` refresh, `q` quit. The status refreshes automatically every 10 seconds.

### 4. Projects and authorized scope (CLI)

Nothing can be launched against a target unless a project explicitly authorizes it:

```bash
traceforge project create "ACME external" --authorization-ref SOW-2026-042 \
    --authorized-from 2026-11-09T08:00:00Z --authorized-until 2026-11-20T18:00:00Z
traceforge scope add 1 include 203.0.113.0/24
traceforge scope add 1 include "*.acme.example"
traceforge scope add 1 exclude 203.0.113.13 --note "production DB, excluded by client"
traceforge scope list 1
traceforge scope check 1 203.0.113.5 203.0.113.13 www.acme.example   # exit 1 if any is denied
traceforge project list
```

Scope rules accept IPv4/IPv6 addresses, CIDR networks, hostnames and `*.domain`
wildcards. Over-broad includes (`0.0.0.0/0`, anything wider than IPv4 `/8` or IPv6 `/32`, or
`*.com`) are rejected.

### Make shortcuts

```
make api     # API server
make web     # dashboard dev server
make tui     # terminal UI
make link    # dashboard sign-in link
make preview # hardened dashboard build on :4173
make test    # all tests
make help    # everything else
```

## Configuration

All settings can be set with environment variables; CLI flags take precedence.

| Variable              | Default                                   | Purpose                              |
| --------------------- | ----------------------------------------- | ------------------------------------ |
| `TRACEFORGE_HOST`     | `127.0.0.1`                               | Bind address (loopback only)         |
| `TRACEFORGE_PORT`     | `8000`                                    | API port                             |
| `TRACEFORGE_DB_PATH`  | `$XDG_DATA_HOME/traceforge/traceforge.db` | SQLite database file                 |
| `TRACEFORGE_API_URL`  | derived from host/port                    | API URL used by the TUI, CLI and dev proxy (loopback only) |
| `TRACEFORGE_DASHBOARD_URL` | `http://127.0.0.1:5173`              | Base of dashboard sign-in links (loopback only) |
| `TRACEFORGE_ALLOWED_ORIGINS` | dev + preview origins on `127.0.0.1`/`localhost` | JSON list of browser origins allowed to call the API (loopback only) |
| `TRACEFORGE_TOKEN_FILE` | `<token dir>/api-<port>.token`          | API token location |
| `TRACEFORGE_SESSION_TTL_SECONDS` | `28800` (8 h)                  | Dashboard session lifetime |
| `TRACEFORGE_LOGIN_CODE_TTL_SECONDS` | `300`                       | Sign-in link lifetime |
| `TRACEFORGE_ENABLE_DOCS` | `false`                                | Serve `/docs` and `/openapi.json` |

`XDG_DATA_HOME` defaults to `~/.local/share`. The database and its parent directory are
created on first start.

The token directory is `$XDG_RUNTIME_DIR/traceforge` only when that runtime directory is
private to you (mode `0700`, owned by you). Otherwise it is `$XDG_DATA_HOME/traceforge/run`.
WSLg, for example, provides a world-writable runtime directory, which is deliberately not used.

## Testing

```bash
make test
```

which runs:

```bash
.venv/bin/pytest                     # API, security, scope, executor, client, TUI, CLI
.venv/bin/ruff check . && .venv/bin/ruff format --check .
cd web && npm run typecheck && npm test
```

The same checks run in GitHub Actions ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)).

## Project layout

```
.
├── src/traceforge/
│   ├── api/              FastAPI app factory, dependencies and routes
│   │   └── routes/       health, auth, projects (scope + scan launch)
│   ├── security/         request guard, token file, sessions, auth dependencies
│   ├── execution/        scope policy, executor choke point, tool adapter registry
│   ├── db/               SQLite connection, migrations, repositories
│   ├── tui/              Textual app, widgets and stylesheet
│   ├── cli.py            `traceforge serve | tui | dashboard-link | project | scope`
│   ├── client.py         async API client used by the TUI and CLI
│   ├── config.py         settings and loopback enforcement
│   └── schemas.py        response models shared across interfaces
├── docs/THREAT_MODEL.md  threat model and security requirements for tool adapters
├── tests/                pytest suite
├── web/                  React + TypeScript dashboard (Vite, Vitest)
├── Makefile
└── pyproject.toml
```

## Roadmap

- First tool adapter (Nmap), meeting the adapter requirements in the threat model
- Scan history and audit log views in the dashboard and TUI
- Scope management in the dashboard
- Serving the built dashboard directly from the API

## Contributing

Issues and pull requests are welcome. Please run `make lint test` before submitting.

## License

Apache License 2.0. See [LICENSE](LICENSE).
