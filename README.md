# TraceForge

Open-source, evidence-driven penetration testing orchestration platform for Kali Linux.

> **Status: v0.3 (pre-alpha).** A hardened local API, a web dashboard, a terminal interface,
> project-level authorized scope enforcement, **Nmap TCP connect scanning** with hash-verified
> evidence, and new in v0.3: a **persistent asset inventory** with full provenance and a
> **scan comparison engine** that separates confirmed changes from things a scan simply
> did not observe.

> **Legal notice:** TraceForge is intended for authorised security testing only. Only run it
> against systems you own or have explicit written permission to test.

## Quick start

One command, one terminal. It installs dependencies on first use, starts the API and the
dashboard, and prints a sign-in link:

```bash
git clone <your-fork-url> traceforge && cd traceforge
make demo
```

Open the printed `http://127.0.0.1:5173/#code=…` link, go to **Scans → New scan**, and scan
`127.0.0.1` on ports `2222,2223`. The host then appears under **Assets**; scan again and use
**Scans → Compare scans** to see what changed. `make demo` adds a "Local lab" project whose only authorized
scope is `127.0.0.1/32`, plus a fake SSH service on `127.0.0.1:2222` to find, so nothing leaves
your machine. Press **Ctrl+C** to stop everything.

Use `make run` for the same without the demo project and service. Requirements are listed
[below](#requirements): Python 3.11+, Node.js 22.22+/24, and Nmap.

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
              │  3. executor              │  scope check + DNS pinning
              │  4. scan job manager      │  queue, concurrency, timeouts
              └──────┬──────────────┬─────┘
                     ▼              ▼
   ┌───────────────────────┐  ┌──────────────────────────┐
   │  SQLite traceforge.db │  │  nmap -sT [-sV] -n       │  argv only, no shell,
   │  projects, scope,     │  │  --unprivileged -oX - -- │  minimal environment
   │  scans, assets, ports │  │  <pinned IPs>            │
   │  services, audit log  │  └────────────┬─────────────┘
   └───────────────────────┘               ▼
                               evidence/scan-N-nmap-*.xml   0600, SHA-256 in SQLite
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
- **DNS pinning.** A hostname is resolved once, during the scope check. Nmap is given the
  exact addresses that were checked (never the name) and runs with `-n`, so a DNS change or
  rebinding attack between the check and the scan cannot redirect it.
- **Constrained tool execution.** Nmap runs from an argument vector (never a shell) built
  only from an allowlisted options model: there is no way to pass raw flags. It always uses
  TCP connect scanning (`-sT --unprivileged`, no raw packets), targets follow `--`, and the
  process gets a minimal environment so server secrets are never inherited or logged.

## Requirements

- Kali Linux (or any recent Linux)
- Python 3.11+
- Nmap (`sudo apt install nmap`; preinstalled on Kali). Root is not needed: scans use TCP connect.
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

### One terminal (recommended)

```bash
make run        # API + dashboard (dev server); prints a sign-in link
make run-prod   # same, but builds the dashboard and serves it with the strict CSP (port 4173)
make demo       # make run + a loopback-only demo project and target
```

These run `scripts/run_local.py`, which:

1. checks that the ports (8000, 5173 or 4173, and 2222 for the demo) are free and that the
   dependencies are installed, and says what to do if not;
2. starts the API, waits for `/health`, then starts the dashboard and waits for it;
3. prints one single-use sign-in link (`make link` prints another);
4. streams both logs with `[api]` / `[web]` prefixes;
5. on **Ctrl+C** stops the dashboard, then the API, which cancels running scans and removes its
   token file.

Use another API port with `.venv/bin/python scripts/run_local.py --api-port 8001` (add `--demo`
or `--prod` as needed). The security model is unchanged: everything binds to `127.0.0.1`, and
the dashboard still reaches the API same-origin through the Vite proxy.

For the terminal UI, run `make tui` in a second terminal while `make run` is running.

### Running the pieces separately

Useful when working on one part. Start the API first; the dashboard and the TUI both depend on
it.

#### 1. API server

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

#### 2. Web dashboard

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

#### 3. Terminal UI

In a second terminal:

```bash
traceforge tui
traceforge tui --api-url http://127.0.0.1:8080
```

Keys: `o` overview, `s` scans, `a` assets, `d` compare (`c` compares the highlighted scan
with the previous one), `r` refresh, `q` quit. Everything refreshes automatically every
10 seconds.

### Projects and authorized scope (CLI)

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

### Scanning

Scans are Nmap TCP connect scans (`-sT`) with optional service/version detection (`-sV`).
They are queued and run in the background by the API server; at most
`TRACEFORGE_SCAN_MAX_CONCURRENT` run at once and the rest wait as `queued`.

```bash
traceforge scan run 1 10.0.0.5 10.0.0.0/28 app.acme.example -p 22,80,443 --wait
traceforge scan run 1 10.0.0.5 --top-ports 100 --timing 4 --no-version
traceforge scan run 1 10.0.0.5 -Pn --timeout 600     # treat as online; kill after 10 min
traceforge scan list [--project 1] [--status running]
traceforge scan show 3                              # status, command, evidence, ports
traceforge scan cancel 3                            # terminates the nmap process
```

Every target must be inside the project's scope, or the whole request is refused and nothing
runs. Options are limited to: ports (`-p`) **or** top ports, service detection on/off, timing
`-T2`…`-T4`, and `-Pn`. Stealth/evasion templates (`-T0`/`-T1`), SYN and other raw-packet
scans, NSE scripts and free-form arguments are not available.

Scan states are `queued → running → completed | failed | cancelled`. A failed scan records why
(non-zero exit with Nmap's error output, timeout, unparseable output, …). Scans still active
when the server stops are cancelled; any found active at startup are marked failed.

- **Dashboard:** a console with four views in the sidebar (Assets is described below).
  - **Overview:** headline counts, recent scans, platform status and projects.
  - **Scans:** history with status filters, project filter and search. Select a scan to open its
    detail panel (summary, ports and services, the exact command, evidence hash, evidence
    download, **Cancel scan**). **New scan** opens the launch form, and scope denials are explained
    target by target. The view refreshes while scans are active.
  - **Projects:** authorization references, testing windows, and each project's scope rules
    (read-only; scope is changed from the CLI).
- **Terminal UI:** press `s` for the Scans tab (scan history; highlighting a scan shows its
  results), `a` for Assets, `d` for Compare (`c` on a scan compares it with the previous
  completed scan of its project), `o` to return to the overview.
- **API:** `POST /api/v1/projects/{id}/scans`, `GET /api/v1/scans`, `GET /api/v1/scans/{id}`,
  `GET /api/v1/scans/{id}/results`, `POST /api/v1/scans/{id}/cancel`, and
  `GET /api/v1/scans/{id}/evidence` (raw XML, verified against its SHA-256 before download).

#### Trying it locally

The quickest way is `make demo` (see [Quick start](#quick-start)). It is safe to re-run: it
reuses the "Local lab" project and prints a fresh link. Then from another terminal you can
also use the CLI against it:

```bash
.venv/bin/traceforge scan run 1 127.0.0.1 -p 2222,2223 --wait
.venv/bin/traceforge scan run 1 127.0.0.2     # refused: outside scope, nothing runs
```

The same thing by hand, scanning only a throwaway listener on your own loopback interface:

```bash
# Terminal 1
traceforge serve

# Terminal 2: a fake SSH service on 127.0.0.1:2222 (Ctrl+C to stop)
python3 -c 'import socket,time
s=socket.create_server(("127.0.0.1",2222))
while True:
    c,_=s.accept()
    try: c.sendall(b"SSH-2.0-OpenSSH_9.6p1 Debian-3\r\n"); time.sleep(0.3)
    except OSError: pass
    c.close()'

# Terminal 3
traceforge project create "Local lab" --authorization-ref LAB-001
traceforge scope add 1 include 127.0.0.1/32
traceforge scan run 1 127.0.0.1 -p 2222,2223 --wait
traceforge scan run 1 127.0.0.2          # refused: outside scope, nothing runs
traceforge tui                           # press s to browse the results
```

### Asset inventory

Every completed scan updates the project's **assets** — one per host per project, however
often it is scanned, each with a stable identifier (`ast_…`). An asset shows:

- address and hostnames, first and last time it **responded**;
- every port ever seen open, with its **current** state (from the latest scan that actually
  checked that port), the service name and version, and the scans those came from;
- how each service was identified: **detected** (Nmap probed it, `-sV`) or **port label**
  (only the conventional name for that port number — not evidence of what runs there);
- the full **observation history**: for each scan, the tool and version, when it was
  observed, the target the operator asked for and the address actually scanned (after DNS
  pinning), the scan configuration, and the evidence file with its SHA-256.

Evidence is referenced, not copied: one XML file per scan, re-verifiable at any time
(`GET /api/v1/scans/{id}/evidence/verify`, or **Verify hash** in the dashboard).

Rules that keep the inventory honest:

- Only **completed** scans count. Failed and cancelled scans never change an asset.
- A port's state only changes when a scan **checked that port**. If scan 1 saw 8080 open and
  scan 2 only scanned 22, 8080 stays "open, last checked in scan 1".
- With `-Pn`, Nmap reports every target as up even if nothing answered. Such hosts are kept
  but marked *never answered* and hidden by default; a host counts as present only if some
  port answered (open, or closed — a TCP reset is an answer).
- An open port is an observation, not a vulnerability. TraceForge does not score or classify
  findings.

```bash
traceforge asset list [--project 1] [--search ssh] [--all]
traceforge asset show ast_9d0ac403fa30fb3a
```

API: `GET /api/v1/assets` (`project_id`, `q`, `include_unconfirmed`), `GET /api/v1/assets/stats`,
`GET /api/v1/assets/{uid}`.

### Comparing scans

Compare two **completed** scans of the same project (dashboard: **Scans → Compare scans**, or
**Compare with #N** in a scan's panel; TUI: `c` on a scan; CLI below). Every difference is in
exactly one category:

| Category | Meaning |
| --- | --- |
| **Added** | Confirmed by both scans: a port is now open that the baseline checked and found closed or filtered; a host now responds that the baseline targeted without an answer. |
| **Removed** | Confirmed by both scans: an open port is now **closed** (a TCP reset), or a host that responded no longer does although the comparison scan targeted it. |
| **Changed** | Both scans **detected** the service by probing and it differs: another service, or another version. |
| **Inconclusive** | One side did not observe it, or the observation is ambiguous: the port was not scanned, the host timed out or was not targeted, coverage is unknown, the port is now *filtered* (no answer is not "closed"), or a port label was replaced by a real detection. |

So if scan A saw 8080 open and scan B never checked 8080, the result is **inconclusive — not
checked**, never "closed". Each result shows both scans' coverage (ports scanned, `-Pn`, `-sV`)
side by side, plus notes such as "the baseline scan is newer". Comparisons are calculated on
demand from the stored observations, so they always follow the same rules as the inventory.

```bash
traceforge scan compare 4 7        # baseline #4 → comparison #7
```

API: `GET /api/v1/projects/{project_id}/scans/compare?baseline=4&comparison=7`. A scan from
another project is reported as not found; failed or cancelled scans are refused (`409`).

#### Evidence and storage

Nmap's XML output is streamed to `<evidence dir>/scan-<id>-nmap-<random>.xml` (file `0600`,
directory `0700`). TraceForge creates the file itself (`-oX -`), so Nmap never writes to a
path a client could influence. The database stores the file name, its SHA-256 and size, plus
the scan's targets, the pinned addresses actually scanned, options, the exact argv, timestamps,
exit code and error. Parsed results go into `assets` (hosts per project, across scans),
`scan_hosts` and `scan_ports` (port state and service name, product, version, extra info,
CPEs). Service banners are controlled by the scanned host, so control characters are
stripped at parse time and every interface renders them as plain text.

Since v0.3 the database also records what each scan *covered* (the ports Nmap probed, from
`<scaninfo>`), ports Nmap reported in bulk (`<extraports>`), and per-host timestamps and
timeouts. The `assets` and `asset_ports` tables are derived from those observations and
recomputed in the same transaction whenever a scan completes.

#### Upgrading from v0.2

Nothing to do: the first `v0.3` start applies an additive migration (new columns and one new
table; no data is removed) and then re-reads the XML evidence of earlier scans to recover
their coverage. Each evidence file is used **only if its SHA-256 still matches** the hash
recorded at scan time; scans whose evidence is missing or altered keep "coverage unknown",
which comparisons treat conservatively. Recorded hashes are never modified. The server log
reports how many scans were updated.

### Running in a VM

TraceForge works the same inside a Linux VM, with one thing to know: it only listens on
`127.0.0.1` **inside the VM**, by design. Opening `http://<vm-ip>:5173` from your host's
browser will not work, and there is deliberately no setting to expose it on the network.

Either use a browser inside the VM, or forward the dashboard port over SSH from your host:

```bash
# on the host (the VM needs an SSH server: sudo apt install openssh-server)
ssh -L 5173:127.0.0.1:5173 user@<vm-ip>
```

Keep that SSH session open, run `make run` (or `make demo`) in the VM, and open the sign-in
link (`http://127.0.0.1:5173/#code=…`) in your host's browser. Only port 5173 needs
forwarding: the dashboard proxies API calls to the server inside the VM. If 5173 is already
used on the host, the local port must still be 5173, because the dashboard's origin is part of
the security checks.

Fresh VM setup, for reference:

```bash
sudo apt install -y git python3-venv nmap     # nmap is preinstalled on Kali
# plus Node.js 22.22+ or 24 (nodejs.org or nvm; distribution packages are often too old)
git clone <your-fork-url> traceforge && cd traceforge
make install
```

### Make shortcuts

```
make run     # API + dashboard in one terminal, with a sign-in link
make run-prod  # same, hardened production build
make demo    # make run + loopback-only demo project and target
make api     # API server only
make web     # dashboard dev server only
make tui     # terminal UI
make link    # dashboard sign-in link
make preview # hardened dashboard build on :4173
make test    # all tests
make test-integration  # real-Nmap tests against a 127.0.0.1 listener only
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
| `TRACEFORGE_NMAP_PATH` | `nmap` on `PATH`                         | Absolute path to the Nmap binary |
| `TRACEFORGE_EVIDENCE_DIR` | `<db dir>/evidence`                   | Raw tool output (owner-only) |
| `TRACEFORGE_SCAN_MAX_CONCURRENT` | `2`                            | Scans running at once |
| `TRACEFORGE_SCAN_MAX_QUEUED` | `20`                               | Scans waiting for a slot (beyond that: HTTP 429) |
| `TRACEFORGE_SCAN_DEFAULT_TIMEOUT_SECONDS` | `1800`                | Per-scan time limit when none is given |
| `TRACEFORGE_SCAN_MAX_TIMEOUT_SECONDS` | `14400`                   | Largest time limit a client may request |
| `TRACEFORGE_SCAN_MAX_ADDRESSES` | `4096`                          | Most addresses one scan may cover (CIDRs expanded) |
| `TRACEFORGE_SCAN_MAX_OUTPUT_BYTES` | `67108864`                   | Abort a scan whose XML output exceeds this |

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
.venv/bin/pytest                     # API, security, scope, executor, jobs, nmap, client, TUI, CLI
.venv/bin/ruff check . && .venv/bin/ruff format --check .
cd web && npm run typecheck && npm test && npm run build
```

Tests never scan external hosts:

- **Unit tests** run a fake `nmap` (`tests/fake_nmap.py`) that prints canned XML and records
  its argv, PID and environment, so the real job manager, subprocess handling, timeouts,
  cancellation and parsing are exercised without any network traffic.
- **Integration tests** (`tests/test_nmap_integration.py`, marker `integration`) run the real
  Nmap against listeners the test starts on `127.0.0.1` — a fake SSH service and a temporary
  HTTP server that is stopped mid-test to verify "open → confirmed closed → not checked" across
  the inventory and comparison engine — in a project whose only scope is `127.0.0.1/32`. They
  are skipped when Nmap is not installed.
- **Inventory and comparison tests** (`tests/test_inventory.py`, `tests/test_compare.py`,
  `tests/test_assets_api.py`) build realistic Nmap XML (`tests/nmapxml.py`) for every case:
  repeated scans, coverage gaps, bulk-reported ports, `-Pn`, timeouts, failed scans,
  cross-project isolation, and the upgrade of a genuine v0.2 database.
- An autouse guard in `tests/conftest.py` fails any test that tries to execute the real Nmap
  binary unless it is an integration test *and* every target is a single loopback address.

```bash
.venv/bin/pytest -m integration       # only the real-Nmap loopback tests
.venv/bin/pytest -m "not integration" # everything else
```

The same checks run in GitHub Actions ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)).

## Project layout

```
.
├── src/traceforge/
│   ├── api/              FastAPI app factory, dependencies and routes
│   │   └── routes/       health, auth, projects (scope, scan launch, compare), scans, assets
│   ├── security/         request guard, token file, sessions, auth dependencies
│   ├── execution/        scope policy, executor choke point, tool adapter contract,
│   │                     nmap adapter + XML parser, background scan job manager
│   ├── inventory/        observation model, asset derivation + v0.2 backfill, comparisons
│   ├── db/               SQLite connection, migrations, repositories
│   ├── tui/              Textual app, widgets and stylesheet
│   ├── cli.py            `traceforge serve | tui | dashboard-link | project | scope | scan`
│   ├── client.py         async API client used by the TUI and CLI
│   ├── config.py         settings and loopback enforcement
│   └── schemas.py        response models shared across interfaces
├── docs/THREAT_MODEL.md  threat model and security requirements for tool adapters
├── scripts/              run_local.py (one-terminal launcher), demo.py (loopback demo)
├── tests/                pytest suite
├── web/                  React + TypeScript dashboard (Vite, Vitest)
├── Makefile
└── pyproject.toml
```

## Limitations (v0.3)

- **TCP only, connect scan only.** No UDP, SYN, OS detection or NSE scripts. Connect scans are
  slower and more visible in target logs than SYN scans; that is deliberate.
- **One address family per scan.** Nmap scans IPv4 *or* IPv6 in a single run. Mixed explicit
  targets are refused; for a hostname, the IPv4 addresses are scanned when the scan has no
  explicit IPv6 targets (start a separate scan for its IPv6 addresses).
- **Hostname rules authorize the name's public addresses.** If `*.acme.example` is in scope
  and a name resolves to a public address not covered by any network rule, it is scanned
  (non-public addresses always need an explicit network rule, and exclusions always win).
  If a domain might point at third-party infrastructure (CDNs, SaaS), scope by IP/CIDR instead
  or add exclusions.
- **Scope is checked at launch.** Removing a scope rule or reaching the end of the authorized
  window does not stop a scan that is already running; cancel it.
- **Jobs live in the API process.** There is no persistent queue: stopping the server cancels
  active scans, and on the next start any scan left active is marked failed.
- **No progress reporting.** Status is queued/running until Nmap exits.
- **Comparisons see only what Nmap reports.** Coverage comes from Nmap's own `<scaninfo>`;
  bulk-reported ports are interpreted only when Nmap says which ports they are (or there is a
  single bulk group). Otherwise the result is inconclusive, by design.
- **"Removed" for hosts means "no longer responding"**, not "decommissioned": host discovery
  can be blocked by a firewall, and under `-Pn` a host with every port filtered is
  indistinguishable from an absent one.
- **One asset per address per project.** Re-used addresses (DHCP, cloud) look like one asset;
  hostnames are recorded but not used as identity.
- **v0.2 scans without verifiable evidence** have unknown coverage: only ports they listed
  individually take part in comparisons and state changes.
- **No finding management.** TraceForge records observations; it does not rate risk, open
  tickets, or mark ports as vulnerabilities.
- **Evidence files are not deleted** with their scans; manage the evidence directory yourself.

## Roadmap

- Scope management and the audit log in the dashboard and TUI
- Scheduled rescans of a project's scope, with a change feed built on the comparison engine
- Findings: operator-confirmed notes and severity, linked to the observations that support them
- Further adapters (HTTP probing, TLS inspection), each meeting the threat model's §8
- Report export (Markdown/HTML) with provenance and evidence hashes

## Contributing

Issues and pull requests are welcome. Please run `make lint test` before submitting.

## License

Apache License 2.0. See [LICENSE](LICENSE).
