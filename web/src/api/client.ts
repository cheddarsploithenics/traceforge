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

export const CSRF_HEADER = "X-TraceForge-CSRF";
const UNSAFE_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number | null = null,
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

async function errorDetail(response: Response): Promise<string> {
  try {
    const data = (await response.json()) as { detail?: unknown };
    if (typeof data.detail === "string") return data.detail;
  } catch {
    // fall through
  }
  return `HTTP ${response.status}`;
}

async function request<T>(
  path: string,
  init: { method?: string; body?: unknown; signal?: AbortSignal } = {},
): Promise<T> {
  const response = await send(path, init);
  if (response.status === 401) {
    csrfToken = null;
    throw new UnauthorizedError(await errorDetail(response));
  }
  if (!response.ok) throw new ApiError(await errorDetail(response), response.status);
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
