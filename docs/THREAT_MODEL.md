# TraceForge threat model

Status: applies to TraceForge 0.3 (local API hardening, the Nmap adapter, and the asset
inventory and scan comparison engine).
Review this document whenever a new interface, endpoint or tool adapter is added.

## 1. System overview

```
 Operator's browser                                     Operator's terminal
 ┌───────────────────────────────┐                      ┌─────────────────────┐
 │ any web page (untrusted)      │                      │ TUI / CLI           │
 │ TraceForge dashboard          │                      │ (traceforge tui …)  │
 │   http://127.0.0.1:5173       │                      └──────────┬──────────┘
 └──────────────┬────────────────┘                                 │ Bearer token
                │ same-origin fetch + HttpOnly cookie              │ (read from 0600 file)
                ▼                                                  │
 ┌───────────────────────────────┐   proxy (Host rewritten,        │
 │ Vite dev/preview server       │   Origin forwarded)             │
 │ 127.0.0.1:5173 / :4173        ├──────────────┐                  │
 └───────────────────────────────┘              ▼                  ▼
                                 ┌────────────────────────────────────────────┐
                                 │ TraceForge API (FastAPI) — 127.0.0.1:8000  │
                                 │  1. LocalRequestGuard  (Host/Origin/CORS)  │
                                 │  2. Authentication     (token | session)   │
                                 │  3. Executor           (scope → tool)      │
                                 └───────┬──────────────────────┬─────────────┘
                                         ▼                      ▼
                         SQLite (projects, scope,      scan job manager → nmap
                         audit log, scans, results)    → pinned, authorized IPs only
```

Both interfaces are clients of the same API; there is no second code path to
the database or to tool execution.

## 2. Assumptions

* TraceForge runs on a single-operator workstation (typically Kali Linux).
* The **operating-system user account is the trust boundary**. Anything
  running as the operator's user is trusted to the same degree as the operator.
* The operator's browser also visits untrusted websites while TraceForge runs.
* The machine may be on a hostile network (client sites, conferences, labs).

## 3. Assets

| Asset | Why it matters |
| --- | --- |
| Authority to launch tools | Highest value: a misuse turns the operator's machine into an attack platform against third parties. |
| Scope definitions and authorization data | Define what is legal to test. Tampering could cause out-of-scope (unlawful) testing. |
| Audit log | Evidence that scope was enforced; needed to defend the engagement afterwards. |
| Engagement data (projects, scan results, assets, raw evidence) | Confidential client information. |
| Integrity of conclusions (asset state, scan comparisons) | Operators act on "port closed" or "host gone"; a wrong conclusion can hide exposure or misreport remediation to a client. |
| API token, session cookies, sign-in codes | Grant all of the above. |

## 4. Threat actors

| ID | Actor | Capability |
| --- | --- | --- |
| A1 | Remote network attacker | Can send packets to the machine's non-loopback interfaces. |
| A2 | Malicious website in the operator's browser | Runs JavaScript; can make cross-origin requests, submit forms, embed frames, and use DNS rebinding to point its own hostname at 127.0.0.1. |
| A3 | Another local OS user | Can connect to loopback ports, read world-readable files, write to world-writable directories. |
| A4 | Malicious process running as the operator | Same privileges as the operator. **Out of scope** — see §7. |
| A5 | Operator error | Typos in targets, overly broad scope, testing after the authorized window. |
| A6 | Hostile or misconfigured DNS for an in-scope domain | Can make an in-scope hostname resolve to arbitrary addresses. |
| A7 | Compromised third-party script | e.g. a CDN serving Swagger UI. |
| A8 | Hostile scanned host | Controls every byte its services return: banners, version strings, hostnames in responses. Reaches TraceForge through Nmap's output. |

## 5. Threats and mitigations

### 5.1 Network exposure (A1)

| Threat | Mitigation | Verified by |
| --- | --- | --- |
| API reachable from the network | Bind address validated to loopback in `Settings`; CLI flags, env vars and `--reload` all pass through that validation. | `test_config.py`, `test_cli.py` |
| Dashboard reachable from the network | Vite `server.host` / `preview.host` = `127.0.0.1`. | manual: `ss -ltn` |
| Credentials sent to a remote host | `api_url` and `dashboard_url` must be loopback; the TUI/CLI refuse to send the token anywhere else. Vite refuses a non-loopback `TRACEFORGE_API_URL`. | `test_config.py`, `test_cli.py` |

### 5.2 Malicious websites (A2)

| Threat | Mitigation | Verified by |
| --- | --- | --- |
| **DNS rebinding**: `evil.example` re-resolves to 127.0.0.1 so the attacker's page becomes "same-origin" with the API | `LocalRequestGuard` accepts only `Host` = loopback name **and** the API's port; anything else gets `400` before routing or auth. Vite's own host check (`allowedHosts: []`, never `true`) protects ports 5173/4173. | `test_guard.py::test_untrusted_host_is_rejected` |
| **Cross-origin reads** of API data | No CORS: the dashboard is same-origin through the Vite proxy, so the API never emits `Access-Control-*` headers and refuses every preflight. Vite's dev-server CORS is disabled (`cors: false`). | `test_guard.py::test_cors_preflight_is_always_refused`, `…no_cors_headers…` |
| **CSRF** (forms, `fetch(no-cors)`, image tags) | Layered: (1) any `Origin` outside the dashboard allowlist → `403`, including `null` and the API's own origin; (2) `Sec-Fetch-Site: cross-site` **and `same-site`** → `403`; (3) cookie-authenticated writes need the per-session `X-TraceForge-CSRF` token, which a cross-origin page can neither read nor send; (4) `SameSite=Strict` cookie. | `test_guard.py`, `test_auth.py::test_session_writes_require_csrf_token` |
| Why `SameSite` alone is insufficient | Browsers treat every port of `127.0.0.1` as the **same site**, so a page on `127.0.0.1:3000` would still get `SameSite=Strict` cookies. Origin and fetch-metadata checks close that gap. | `test_guard.py` (`http://127.0.0.1:3000`, `same-site`) |
| Clickjacking | `X-Frame-Options: DENY` and `frame-ancestors 'none'` on the API and both Vite servers. | `test_guard.py::test_security_headers…` |
| Session theft through XSS | Session id is `HttpOnly`; CSRF token and nothing else lives in JS memory; nothing in `localStorage`/`sessionStorage`. Strict CSP on the preview server. React escapes all rendered data. | `App.test.tsx` (“never persists credentials…”) |
| Sign-in code leakage via `Referer`/logs | Code travels in the URL **fragment**, which browsers never send to servers; the dashboard scrubs it from the address bar and history immediately; `Referrer-Policy: no-referrer`. Codes are single-use and expire after 5 minutes. | `test_auth.py`, `App.test.tsx` |

### 5.3 Other local users (A3)

| Threat | Mitigation | Verified by |
| --- | --- | --- |
| Calling the API over loopback | Every `/api` route requires the bearer token or a session. Only `/health` (status + version) is public. | `test_auth.py::test_requests_without_credentials_are_rejected` |
| Reading the API token | Token file is created `0600` (via `O_EXCL`, `O_NOFOLLOW`, atomic rename) inside a `0700` directory owned by the operator. Readers refuse files that are group/world-accessible or owned by someone else. | `test_tokens.py` |
| Pre-planting the token directory | The server refuses a token directory owned by another user. `XDG_RUNTIME_DIR` is used only if it is private: **WSLg provides a world-writable `/mnt/wslg/runtime-dir`**, which is ignored. | `test_tokens.py`, `test_cli.py::test_serve_refuses_token_dir…` |
| Guessing tokens / codes | 256-bit random values (`secrets.token_urlsafe(32)`), compared in constant time; only SHA-256 digests of codes and session ids are kept in memory. | `test_auth.py` |
| Replaying an old token | A new token is generated on every server start; the old file is replaced. | `test_auth.py::test_token_is_unique_per_server_instance` |

### 5.4 Operator error and out-of-scope testing (A5, A6)

All tool launches pass through a single choke point, `Executor.launch`
(`src/traceforge/execution/executor.py`):

1. the project must exist and have a written-authorization reference
   (`authorization_ref`), and the current time must be inside its optional
   `authorized_from`/`authorized_until` window;
2. every target is parsed strictly; values starting with `-` (option
   injection), whitespace, shell metacharacters, URLs, ports, zone ids and
   non-ASCII are rejected;
3. scope is evaluated **before the tool is looked up**. It is deny-by-default;
   exclusions always win; a CIDR target must fit entirely inside one include
   and must not overlap any exclude; one denied target blocks the whole
   launch;
4. hostnames must match a hostname rule *and* resolve; any resolved address in
   an excluded range is a denial, and addresses that are not publicly routable
   (RFC 1918, loopback, link-local, …) must be covered by an explicit network
   rule. This stops an in-scope domain from steering a tool at internal
   infrastructure (A6). Resolution failure denies (fail closed);
5. the decision is written to the audit log (`launch.denied` or
   `launch.authorized`);
6. tool adapters receive an `AuthorizedTargets` object, which can only be
   constructed by `ScopePolicy.authorize()`, and must return an argv list (no
   shell).

Further guard rails: include rules broader than IPv4 `/8` or IPv6 `/32`,
multicast/unspecified ranges, and wildcards covering a whole TLD (`*.com`) are
refused. IPv4-mapped IPv6 targets (`::ffff:10.0.0.1`) are normalised so IPv4
exclusions cannot be bypassed.

Verified by `test_scope.py`, `test_executor.py`, `test_projects_api.py`.

### 5.5 Tool execution: the Nmap adapter (A5, A6, A8)

`src/traceforge/execution/nmap.py` (adapter) and `src/traceforge/execution/jobs.py`
(job manager).

| Threat | Mitigation | Verified by |
| --- | --- | --- |
| Shell or option injection through targets or options | `asyncio.create_subprocess_exec` with an argv list; no shell anywhere in the package (static AST check). Clients choose only fields of `NmapScanOptions` (`extra="forbid"`): port spec matched by a strict regex and range-checked, enums for timing. Targets are re-serialised from parsed objects and follow `--`. | `test_nmap.py` (options, exact argv, `test_no_shell_execution_anywhere_in_the_package`), `test_scans_api.py::test_invalid_requests_are_rejected_without_executing` |
| **DNS rebinding / TOCTOU between scope check and scan** (A6) | Hostnames are resolved once, inside `ScopePolicy.authorize`; `AuthorizedTargets` carries those addresses and the adapter passes **only them** to Nmap, which runs with `-n` (no DNS). A hostname without pinned addresses is refused. | `test_scans_api.py::test_dns_rebinding_cannot_redirect_the_scan`, `test_nmap.py::test_hostnames_are_pinned_to_checked_addresses` |
| Stealthy, evasive or privileged scanning | Always `-sT --unprivileged` (overrides the `--privileged` that Kali's `nmap` wrapper adds); `-T0`/`-T1`/`-T5`, decoys, fragmentation, NSE and raw flags are not expressible. | `test_nmap.py::test_optional_flags`, integration test asserts `type="connect"` |
| Oversized scans | Addresses covered (CIDRs expanded) capped by `TRACEFORGE_SCAN_MAX_ADDRESSES`; per-scan timeout with a server maximum; XML output capped. | `test_nmap.py`, `test_jobs.py` |
| Runaway or orphaned processes | Each scan runs in its own session; timeout, cancellation and shutdown send SIGTERM to the process group, then SIGKILL after a grace period. Signals are only sent while the leader is unreaped, so a recycled PID is never signalled. | `test_jobs.py` (timeout, cancel, ignore-SIGTERM, shutdown: process is gone) |
| Resource exhaustion through many requests | Concurrency semaphore plus a bounded queue; excess launches get `429`. | `test_jobs.py::test_queue_limit`, `test_scans_api.py::test_queue_full_returns_429` |
| Secrets leaking into tool processes, logs or evidence | Tools get a minimal environment (`PATH`, `HOME`, locale): no `TRACEFORGE_*`, tokens, cloud credentials or proxies. The API token is never on the command line. Stored errors are a sanitised, length-capped tail of stderr. | `test_jobs.py::test_tool_runs_with_a_minimal_environment` |
| Tool writing to attacker-chosen paths | `-oX -`: XML goes to stdout and TraceForge creates the evidence file itself (`O_EXCL | O_NOFOLLOW`, `0600`, in a `0700` directory it owns). The working directory is the evidence directory. | `test_jobs.py::test_completed_scan_stores_results_and_evidence` |
| Evidence tampering | SHA-256 and size recorded at write time; the download endpoint refuses a file whose hash no longer matches. | `test_scans_api.py::test_evidence_download_is_verified` |
| Malicious XML (A8) | Entity declarations refused before parsing (no entity expansion); stdlib parser never fetches external entities; size cap. | `test_nmap.py::test_rejects_malformed_or_unsafe_xml` |
| Target-controlled text attacking the UIs (A8) | Parser replaces non-printable characters (terminal escapes, bidi overrides) and caps field length. The TUI renders table cells as `rich.text.Text` (Textual parses plain `str` cells as markup, including `@click` actions) and escapes other text; React escapes everything; evidence downloads are `attachment` with the API's `default-src 'none'; sandbox` CSP. | `test_nmap.py::test_target_controlled_text_is_sanitised`, `test_tui.py::test_tui_scan_results_render_banners_literally`, `Scans.test.tsx` ("inert text") |
| Unauthenticated or cross-site scan control | All scan routes use the existing authentication; launch and cancel are POSTs, so dashboard sessions need the CSRF token and an allowed `Origin`. | `test_scans_api.py` (auth, CSRF, cross-origin) |
| A test suite scanning real hosts | Unit tests use a fake `nmap`; an autouse guard fails any test that executes the real binary unless it is marked `integration` and every target is a single loopback address. | `test_nmap.py::test_unit_tests_cannot_execute_real_nmap`, `test_nmap_integration.py::test_guard_refuses_non_loopback…` |

Every scan is audited: `launch.authorized` (actor, targets, pinned addresses, options),
`scan.started`, and `scan.completed | failed | cancelled` (exit code, reason, evidence hash),
plus `scan.cancel_requested` with the requesting actor.

### 5.6 Asset inventory and scan comparison (A5, A8)

`src/traceforge/inventory/` (model, store, compare) and `api/routes/assets.py`.

| Threat | Mitigation | Verified by |
| --- | --- | --- |
| **Misleading conclusions**: a port reported closed (or a host gone) because a scan never looked | One interpretation model for inventory and comparisons: a port's state is known only if it was listed, or covered by `<scaninfo>` *and* placed by an unambiguous `<extraports>` group; otherwise "not observed" with the reason. Filtered ≠ closed. Comparisons label everything one side did not observe as *inconclusive*. | `test_compare.py` (`…never_reported_closed`, `…filtered_is_not_closed`, `…ambiguous_bulk_groups…`, `…unknown_coverage…`), mutation-checked |
| `-Pn` making absent hosts look present | Hosts with reason `user-set` count as responsive only if a port answered (open or closed); otherwise the asset is *unconfirmed* and hidden by default. | `test_inventory.py::test_down_hosts_and_unanswered_pn_hosts…`, `test_compare.py::test_pn_without_any_answer` |
| Failed, cancelled or interrupted scans producing "changes" | Asset state is derived only from **completed** scans; comparisons refuse other statuses (`409`). Results and the `completed` status are committed in **one transaction**, so a crash cannot leave half-ingested results. | `test_inventory.py::test_failed_or_cancelled…`, `…results_and_completion_are_atomic`, `test_compare.py::test_incomplete_scans…` |
| Order-dependent or drifting derived data | Asset state is recomputed from all observations (never patched) in the ingesting transaction. | `test_inventory.py::test_ingestion_order_does_not_matter` |
| Cross-project leakage | Comparisons are project-scoped (`/projects/{id}/scans/compare`); a scan of another project is reported as not found (no existence oracle). Observation queries join scans *and* assets on the same project. Assets are per project: the same IP in two engagements is two assets. | `test_compare.py::test_scans_from_another_project…`, `test_assets_api.py::test_cross_project_isolation…` |
| Tampered evidence feeding the inventory during the v0.2 upgrade | Backfill re-parses an evidence file only if its SHA-256 matches the recorded hash (opened with `O_NOFOLLOW`, name must be a plain file name); otherwise coverage stays unknown. Recorded hashes are never rewritten. | `test_inventory.py::test_v02_database_is_upgraded…` |
| Malicious XML (A8), now also from evidence files | Same hardened parser as scanning (entity declarations refused, size cap). Port specs from `<scaninfo>`/`<extrareasons>` are parsed strictly (regex, range-checked); malformed → "unknown", never "covered". | `test_nmap.py`, `PortSet` |
| SQL injection via search/filters | Parameterised queries only; `LIKE` wildcards in user input are escaped; asset ids must match `^ast_[0-9a-f]{16}$`; search length capped. | `test_inventory.py::test_search`, `test_assets_api.py::test_asset_endpoint_validation` |
| Target-controlled text in new views (A8) | Same as §5.5: sanitised at parse time; TUI cells are literal `Text`; React escapes. | `Assets.test.tsx` ("inertly"), `test_tui.py` |
| Over-reading an observation as a vulnerability | No severity or vulnerability classification exists; the UI states that an open port is an observation, and distinguishes *detected* services from *port labels*. | `test_inventory.py::test_asset_created_from_nmap_xml` |

All new endpoints are read-only `GET`s behind the existing authentication; scope enforcement
is unchanged (assets come only from scans that passed it).

### 5.7 Third-party code (A7)

* `/docs` and `/openapi.json` are **disabled by default**. Swagger UI loads
  scripts from a CDN that would run on the API's origin. If enabled
  (`TRACEFORGE_ENABLE_DOCS=true`), the API's own origin is still *not* an
  allowed origin, so script on the docs page cannot make credentialed writes.
* Dependencies are pinned through `package-lock.json`; CI runs `npm ci`.

## 6. Authentication design

| Client | Credential | Lifetime | Storage |
| --- | --- | --- | --- |
| TUI, CLI | `Authorization: Bearer <api token>` | Until the server stops | `0600` file `<token dir>/api-<port>.token`, removed on shutdown |
| Dashboard | single-use sign-in code → `traceforge_session` cookie | Code: 5 min, one use. Session: 8 h (server-enforced), browser-session cookie | Code in URL fragment (scrubbed); cookie `HttpOnly; SameSite=Strict; Path=/api`; CSRF token in JS memory only |

Sign-in codes are issued only to holders of the API token (`traceforge
dashboard-link`) or printed by the server at startup, so the operator's
terminal is the trust anchor for the browser. Browser sessions cannot mint new
codes.

## 7. Residual risks and limitations

* **Same-user processes are trusted (A4).** Anything running as the operator
  can read the token file and the SQLite database, or attach to the server
  process. TraceForge does not defend against a compromised user account.
* **Cookies are not port-isolated.** The session cookie for `127.0.0.1` is
  sent to *every* port on `127.0.0.1` under `/api`. A local service run by
  another user on, say, `127.0.0.1:9000` would receive it if the operator's
  browser requested `http://127.0.0.1:9000/api/...`. Mitigations: short
  lifetime, server-side revocation on sign-out, and the session is useless
  for writes without the CSRF token and an allowed `Origin`. Not eliminated.
* **The sign-in link is printed to the server's terminal** (and any log it is
  redirected to). It is single-use and expires in 5 minutes.
* **The Vite dev server is a development tool** with no CSP (React Fast
  Refresh needs inline scripts) and a history of path-traversal advisories.
  Keep it updated; prefer `npm run build && npm run preview` for real
  engagements.
* **No TLS on loopback.** Only root on the same machine could observe the
  traffic, and root is already fully trusted.
* **Sessions live in memory**; restarting the server signs the dashboard out.
  Single-process deployment only.
* **Scope is checked at launch time.** Scope or window changes do not affect a
  tool that is already running; the operator must cancel it. (The DNS TOCTOU
  window is closed for Nmap by pinning; see §5.5.)
* **Hostname rules authorize the name's public addresses.** An in-scope domain
  that resolves to a public address outside every network rule is scanned.
  Non-public addresses need an explicit network rule and exclusions always
  win, but a domain pointing at third-party infrastructure (CDN, SaaS) would
  be scanned. Operators who need address-exact scope should use IP/CIDR rules.
* **Scan jobs are in-process.** A clean shutdown cancels and kills every
  scan. If the API process is killed abruptly (SIGKILL, crash), a running Nmap
  is not signalled: it runs in its own session, so it continues until its next
  write to the now-closed stdout pipe fails (SIGPIPE) or it finishes. Its
  targets were already authorized; the scan is marked failed on the next start.
* **Evidence files are protected by file permissions only** and are not
  deleted with their scans. A same-user process could replace an evidence
  file; verification detects this but cannot restore the original.
* **Comparisons trust Nmap's own coverage report.** If Nmap mis-reports what it
  scanned, conclusions follow it. Bulk-reported ports are only interpreted
  when unambiguous.
* **Asset identity is the IP address per project.** Address re-use (DHCP,
  cloud) merges distinct machines into one asset history.
* **Audit log integrity relies on file permissions.** It is append-only by
  convention, not tamper-evident.
* **`/health` is unauthenticated** and reveals the version string to local
  users.

## 8. Requirements for tool adapters

The Nmap adapter (§5.5) meets all of these. Any future adapter is not
mergeable unless it:

1. accepts only `AuthorizedTargets` and builds an **argv list** (never
   `shell=True`), placing targets after `--` where the tool supports it;
2. disables or constrains any feature that discovers and follows new targets
   (DNS brute force, redirects, `--traceroute` hops, script-driven pivots), or
   re-checks such targets through `ScopePolicy`;
3. passes **resolved, scope-checked addresses** to the tool instead of
   hostnames where possible, to remove the DNS TOCTOU window;
4. never accepts free-form extra arguments from clients without an allowlist
   (e.g. `-iL`, `-oN`, `--script` can read/write arbitrary files);
5. runs the tool with a timeout and without elevated privileges unless the
   operator explicitly opts in;
6. records start/finish/exit status in the audit log.

## 9. Verifying the controls

```bash
.venv/bin/pytest tests/test_guard.py tests/test_auth.py tests/test_tokens.py \
                 tests/test_scope.py tests/test_executor.py tests/test_projects_api.py \
                 tests/test_nmap.py tests/test_jobs.py tests/test_scans_api.py \
                 tests/test_inventory.py tests/test_compare.py tests/test_assets_api.py \
                 tests/test_nmap_integration.py
cd web && npm test
```
