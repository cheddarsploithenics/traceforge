/**
 * Typed client for the TraceForge API.
 * Mirrors the Pydantic models in src/traceforge/schemas.py.
 *
 * Security model (see docs/THREAT_MODEL.md):
 * - Requests always go to the page's own origin; Vite proxies them to the API.
 * - Authentication is an HttpOnly session cookie that scripts cannot read.
 * - The per-session CSRF token is held only in this module's memory. Nothing
 *   is ever written to localStorage, sessionStorage or script-readable cookies.
 */

export interface HealthResponse {
  status: "ok" | "degraded";
  version: string;
  database: "ok" | "error";
}

export interface SessionInfo {
  method: "token" | "session";
  csrf_token: string | null;
  expires_at: string | null;
}

export interface Project {
  id: number;
  name: string;
  authorization_ref: string;
  authorized_from: string | null;
  authorized_until: string | null;
  created_at: string;
  scope_rule_count: number;
}

export interface ScopeRule {
  id: number;
  project_id: number;
  kind: "include" | "exclude";
  value: string;
  note: string | null;
  created_at: string;
}

export interface ScopeDecision {
  target: string;
  allowed: boolean;
  reason: string;
  addresses?: string[];
}

export type ScanStatus = "queued" | "running" | "completed" | "failed" | "cancelled";
export const ACTIVE_STATUSES: ReadonlySet<ScanStatus> = new Set(["queued", "running"]);

/** Mirrors NmapScanOptions: the only options a client can choose. */
export interface NmapScanOptions {
  service_detection?: boolean;
  ports?: string;
  top_ports?: number;
  timing?: 2 | 3 | 4;
  skip_host_discovery?: boolean;
}

export interface ScanLaunch {
  targets: string[];
  tool?: string;
  options?: NmapScanOptions;
  timeout_seconds?: number;
}

export interface ScanLaunchResult {
  scan_id: number;
  tool: string;
  targets: string[];
  scan_addresses: string[];
  status: ScanStatus;
}

export interface EvidenceRef {
  file: string;
  sha256: string;
  size_bytes: number;
}

export interface Scan {
  id: number;
  project_id: number | null;
  tool: string | null;
  name: string;
  status: ScanStatus;
  targets: string[];
  scan_addresses: string[];
  options: Record<string, unknown>;
  command: string[];
  actor: string | null;
  timeout_seconds: number | null;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  exit_code: number | null;
  error: string | null;
  tool_version: string | null;
  evidence: EvidenceRef | null;
  hosts_up: number;
  open_ports: number;
  ports_scanned?: Record<string, string> | null;
}

export interface ScanPort {
  protocol: string;
  port: number;
  state: string;
  reason: string | null;
  service_name: string | null;
  service_product: string | null;
  service_version: string | null;
  service_extrainfo: string | null;
  service_tunnel: string | null;
  service_method: string | null;
  service_confidence: number | null;
  cpe: string[];
}

export interface ScanHost {
  asset_id: number;
  address: string;
  addr_type: string;
  state: string;
  reason: string | null;
  hostnames: string[];
  ports: ScanPort[];
}

export interface ScanResults {
  scan: Scan;
  hosts: ScanHost[];
}

// --- asset inventory & comparisons (v0.3) ------------------------------------

/** "detected": Nmap probed and identified the service; "port-label": only the
 * conventional name for that port number. */
export type Identification = "detected" | "port-label";

export interface ServiceRef {
  protocol: string;
  port: number;
  service_name: string | null;
  identification: Identification | null;
}

export interface AssetSummary {
  uid: string;
  project_id: number;
  project_name: string;
  address: string;
  addr_type: string;
  hostnames: string[];
  first_seen: string;
  last_seen: string;
  confirmed: boolean;
  open_ports: number;
  last_scan_id: number | null;
  services: ServiceRef[];
}

export interface AssetPort {
  protocol: string;
  port: number;
  state: string;
  state_scan_id: number | null;
  first_seen: string;
  last_seen: string;
  last_open_at: string | null;
  service_name: string | null;
  service_product: string | null;
  service_version: string | null;
  service_extrainfo: string | null;
  service_method: string | null;
  identification: Identification | null;
  service_confidence: number | null;
  cpe: string[];
  service_scan_id: number | null;
}

export interface ScanConfiguration {
  options: Record<string, unknown>;
  command: string[];
  timeout_seconds: number | null;
  ports_scanned: Record<string, string> | null;
  host_discovery: boolean;
  service_detection: boolean;
}

export interface Provenance {
  project_id: number;
  scan_id: number;
  tool: string | null;
  tool_version: string | null;
  observed_at: string;
  requested_targets: string[];
  scanned_address: string;
  configuration: ScanConfiguration;
  evidence: EvidenceRef | null;
}

export interface ObservedPort {
  protocol: string;
  port: number;
  state: string;
  reason: string | null;
  service_name: string | null;
  service_product: string | null;
  service_version: string | null;
  service_extrainfo: string | null;
  service_method: string | null;
  identification: Identification | null;
  cpe: string[];
}

export interface AssetObservation {
  scan_id: number;
  observed_at: string;
  state: string;
  reason: string | null;
  responsive: boolean;
  timed_out: boolean;
  hostnames: string[];
  ports: ObservedPort[];
  provenance: Provenance;
}

export interface AssetDetail extends AssetSummary {
  ports: AssetPort[];
  observations: AssetObservation[];
}

export interface AssetStats {
  assets: number;
  unconfirmed: number;
  assets_with_open_ports: number;
  open_ports: number;
  detected_services: number;
}

export type ChangeCategory = "added" | "removed" | "changed" | "inconclusive";

export interface ComparisonSide {
  scan_id: number;
  status: ScanStatus;
  created_at: string;
  finished_at: string | null;
  tool: string | null;
  tool_version: string | null;
  targets: string[];
  scan_addresses: string[];
  ports_scanned: Record<string, string> | null;
  host_discovery: boolean;
  service_detection: boolean;
  hosts_responsive: number;
  evidence: EvidenceRef | null;
}

export interface ComparisonChange {
  category: ChangeCategory;
  kind: string;
  address: string;
  asset_uid: string | null;
  hostnames: string[];
  protocol: string | null;
  port: number | null;
  before: Record<string, unknown> | null;
  after: Record<string, unknown> | null;
  detail: string;
}

export interface ScanComparison {
  project_id: number;
  baseline: ComparisonSide;
  comparison: ComparisonSide;
  summary: Record<ChangeCategory, number> & { unchanged_open_ports: number };
  changes: ComparisonChange[];
  notes: string[];
}

export interface EvidenceVerification {
  scan_id: number;
  file: string;
  recorded_sha256: string;
  actual_sha256: string | null;
  size_bytes: number | null;
  verified: boolean;
  detail: string;
}

export const CSRF_HEADER = "X-TraceForge-CSRF";
const UNSAFE_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number | null = null,
    /** Per-target scope decisions when a launch was refused (HTTP 403). */
    readonly decisions: ScopeDecision[] = [],
  ) {
    super(message);
    this.name = "ApiError";
  }
}

export class UnauthorizedError extends ApiError {
  constructor(message: string) {
    super(message, 401);
    this.name = "UnauthorizedError";
  }
}

let csrfToken: string | null = null;
const signInAttempts = new Map<string, Promise<SessionInfo>>();

/** Test helper: forget in-memory credentials. */
export function resetClientState(): void {
  csrfToken = null;
  signInAttempts.clear();
}

function isAbort(err: unknown): boolean {
  return err instanceof DOMException && err.name === "AbortError";
}

async function send(
  path: string,
  { method = "GET", body, signal }: { method?: string; body?: unknown; signal?: AbortSignal } = {},
): Promise<Response> {
  const headers: Record<string, string> = { Accept: "application/json" };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (UNSAFE_METHODS.has(method) && csrfToken) headers[CSRF_HEADER] = csrfToken;
  try {
    return await fetch(path, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      credentials: "same-origin",
      cache: "no-store",
      redirect: "error",
      signal,
    });
  } catch (err) {
    if (isAbort(err)) throw err;
    throw new ApiError("Cannot reach the TraceForge API");
  }
}

interface ErrorInfo {
  message: string;
  decisions: ScopeDecision[];
}

function describe(detail: unknown, status: number): ErrorInfo {
  if (typeof detail === "string") return { message: detail, decisions: [] };
  // FastAPI validation errors: [{loc: [...], msg: "..."}]
  if (Array.isArray(detail)) {
    const parts = detail.map((item: { loc?: unknown[]; msg?: string }) => {
      const field = (item.loc ?? []).filter((p) => p !== "body").join(".");
      return field ? `${field}: ${item.msg}` : String(item.msg);
    });
    return { message: parts.join("; ") || `HTTP ${status}`, decisions: [] };
  }
  // Scope denial: {message, decisions}
  if (detail && typeof detail === "object" && "message" in detail) {
    const { message, decisions } = detail as { message: unknown; decisions?: ScopeDecision[] };
    return { message: String(message), decisions: Array.isArray(decisions) ? decisions : [] };
  }
  return { message: `HTTP ${status}`, decisions: [] };
}

async function errorInfo(response: Response): Promise<ErrorInfo> {
  try {
    const data = (await response.json()) as { detail?: unknown };
    return describe(data.detail, response.status);
  } catch {
    return { message: `HTTP ${response.status}`, decisions: [] };
  }
}

async function request<T>(
  path: string,
  init: { method?: string; body?: unknown; signal?: AbortSignal } = {},
): Promise<T> {
  const response = await send(path, init);
  if (response.status === 401) {
    csrfToken = null;
    throw new UnauthorizedError((await errorInfo(response)).message);
  }
  if (!response.ok) {
    const info = await errorInfo(response);
    throw new ApiError(info.message, response.status, info.decisions);
  }
  return (response.status === 204 ? undefined : await response.json()) as T;
}

export async function fetchHealth(signal?: AbortSignal): Promise<HealthResponse> {
  const response = await send("/health", { signal });
  // 503 is a valid "degraded" health report, not a transport failure.
  if (!response.ok && response.status !== 503) {
    throw new ApiError(`Unexpected HTTP ${response.status} from /health`, response.status);
  }
  return (await response.json()) as HealthResponse;
}

function remember(session: SessionInfo): SessionInfo {
  csrfToken = session.csrf_token;
  return session;
}

/** Exchange a single-use code for a session. Deduplicated so a code is spent once. */
export function signIn(code: string): Promise<SessionInfo> {
  let attempt = signInAttempts.get(code);
  if (!attempt) {
    attempt = request<SessionInfo>("/api/v1/auth/session", {
      method: "POST",
      body: { code },
    }).then(remember);
    signInAttempts.set(code, attempt);
  }
  return attempt;
}

export async function getSession(signal?: AbortSignal): Promise<SessionInfo> {
  return remember(await request<SessionInfo>("/api/v1/auth/session", { signal }));
}

export async function signOut(): Promise<void> {
  try {
    await request<void>("/api/v1/auth/session", { method: "DELETE" });
  } finally {
    csrfToken = null;
  }
}

export function listProjects(signal?: AbortSignal): Promise<Project[]> {
  return request<Project[]>("/api/v1/projects", { signal });
}

export function listScope(projectId: number, signal?: AbortSignal): Promise<ScopeRule[]> {
  return request<ScopeRule[]>(`/api/v1/projects/${projectId}/scope`, { signal });
}

export function evidenceUrl(scanId: number): string {
  return `/api/v1/scans/${scanId}/evidence`;
}

export function launchScan(projectId: number, body: ScanLaunch): Promise<ScanLaunchResult> {
  return request<ScanLaunchResult>(`/api/v1/projects/${projectId}/scans`, {
    method: "POST",
    body: { tool: "nmap", ...body },
  });
}

export function listScans(
  { projectId, limit = 50 }: { projectId?: number; limit?: number } = {},
  signal?: AbortSignal,
): Promise<Scan[]> {
  const params = new URLSearchParams({ limit: String(limit) });
  if (projectId !== undefined) params.set("project_id", String(projectId));
  return request<Scan[]>(`/api/v1/scans?${params.toString()}`, { signal });
}

export function getScanResults(scanId: number, signal?: AbortSignal): Promise<ScanResults> {
  return request<ScanResults>(`/api/v1/scans/${scanId}/results`, { signal });
}

export function cancelScan(scanId: number): Promise<Scan> {
  return request<Scan>(`/api/v1/scans/${scanId}/cancel`, { method: "POST" });
}

export function listAssets(
  {
    projectId,
    query,
    includeUnconfirmed = false,
    limit = 500,
  }: { projectId?: number; query?: string; includeUnconfirmed?: boolean; limit?: number } = {},
  signal?: AbortSignal,
): Promise<AssetSummary[]> {
  // Fixed parameter order keeps URLs stable (and easy to match in tests).
  const params = new URLSearchParams({ limit: String(limit) });
  if (projectId !== undefined) params.set("project_id", String(projectId));
  if (query) params.set("q", query);
  if (includeUnconfirmed) params.set("include_unconfirmed", "true");
  return request<AssetSummary[]>(`/api/v1/assets?${params.toString()}`, { signal });
}

export function getAsset(uid: string, signal?: AbortSignal): Promise<AssetDetail> {
  return request<AssetDetail>(`/api/v1/assets/${encodeURIComponent(uid)}`, { signal });
}

export function getAssetStats(signal?: AbortSignal): Promise<AssetStats> {
  return request<AssetStats>("/api/v1/assets/stats", { signal });
}

export function compareScans(
  projectId: number,
  baseline: number,
  comparison: number,
  signal?: AbortSignal,
): Promise<ScanComparison> {
  const params = new URLSearchParams({ baseline: String(baseline), comparison: String(comparison) });
  return request<ScanComparison>(
    `/api/v1/projects/${projectId}/scans/compare?${params.toString()}`,
    { signal },
  );
}

export function verifyEvidence(scanId: number): Promise<EvidenceVerification> {
  return request<EvidenceVerification>(`/api/v1/scans/${scanId}/evidence/verify`);
}

/** Split free-form target input (newlines, commas, spaces) into a list. */
export function parseTargets(text: string): string[] {
  return Array.from(new Set(text.split(/[\s,]+/).filter(Boolean)));
}

/**
 * Read a sign-in code from the URL fragment (`#code=…`) and remove it from the
 * address bar and history. Fragments are never sent to servers or in Referer.
 */
export function takeLoginCodeFromUrl(): string | null {
  const params = new URLSearchParams(window.location.hash.slice(1));
  const code = params.get("code");
  if (code !== null) {
    window.history.replaceState(null, "", window.location.pathname + window.location.search);
  }
  return code || null;
}
