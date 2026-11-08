import { vi } from "vitest";

export interface RecordedCall {
  method: string;
  path: string;
  headers: Record<string, string>;
  body: unknown;
  credentials: RequestCredentials | undefined;
}

type Handler = (call: RecordedCall) => Response | Promise<Response>;

export const json = (body: unknown, status = 200) =>
  new Response(status === 204 ? null : JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });

/** Route fetch() calls by "METHOD /path" and record every request. */
export function mockApi(routes: Record<string, Handler>) {
  const calls: RecordedCall[] = [];
  vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init = {}) => {
    const call: RecordedCall = {
      method: init.method ?? "GET",
      path: String(input),
      headers: { ...(init.headers as Record<string, string>) },
      body: typeof init.body === "string" ? JSON.parse(init.body) : undefined,
      credentials: init.credentials,
    };
    calls.push(call);
    const handler = routes[`${call.method} ${call.path}`];
    return handler ? handler(call) : json({ detail: `unmocked ${call.method} ${call.path}` }, 404);
  });
  return calls;
}

export const HEALTHY = { status: "ok", version: "0.2.0", database: "ok" };

/** Scan list request issued by the overview and scans pages. */
export const SCANS_LIST = "GET /api/v1/scans?limit=200";
export const SESSION = {
  method: "session",
  csrf_token: "csrf-123",
  expires_at: "2026-11-08T20:00:00Z",
};
