import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { StrictMode } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import App from "./App";
import { CSRF_HEADER, resetClientState } from "./api/client";
import { HEALTHY, SCANS_LIST, SESSION, json, mockApi } from "./test/mockApi";

const unauthorized = () => json({ detail: "Authentication required" }, 401);
const PROJECTS = [
  {
    id: 1,
    name: "acme",
    authorization_ref: "SOW-42",
    authorized_from: null,
    authorized_until: null,
    created_at: "2026-11-08T10:00:00Z",
    scope_rule_count: 3,
  },
];
const signedIn = {
  "GET /health": () => json(HEALTHY),
  "GET /api/v1/auth/session": () => json(SESSION),
  "GET /api/v1/projects": () => json(PROJECTS),
  [SCANS_LIST]: () => json([]),
};

beforeEach(() => {
  resetClientState();
  localStorage.clear();
  sessionStorage.clear();
});

describe("health", () => {
  it("shows healthy backend status on the sign-in screen", async () => {
    const calls = mockApi({ "GET /health": () => json(HEALTHY), "GET /api/v1/auth/session": unauthorized });
    render(<App />);
    expect(await screen.findByText(/API OK/)).toBeInTheDocument();
    expect(screen.getByText("0.2.0")).toBeInTheDocument();
    // Same-origin relative URLs only: never an absolute, cross-origin API URL.
    expect(calls.every((c) => c.path.startsWith("/"))).toBe(true);
  });

  it("shows degraded status from a 503 response", async () => {
    mockApi({
      "GET /health": () => json({ ...HEALTHY, status: "degraded", database: "error" }, 503),
      "GET /api/v1/auth/session": unauthorized,
    });
    render(<App />);
    expect(await screen.findByText(/API DEGRADED/)).toBeInTheDocument();
  });

  it("explains how to start the backend when it is unreachable", async () => {
    vi.spyOn(globalThis, "fetch").mockRejectedValue(new TypeError("Failed to fetch"));
    render(<App />);
    const alerts = await screen.findAllByRole("alert");
    expect(alerts.some((a) => a.textContent?.includes("Cannot reach the TraceForge API"))).toBe(true);
    expect(screen.getByText("traceforge serve")).toBeInTheDocument();
    expect(screen.getByText(/API unreachable/)).toBeInTheDocument();
  });
});

describe("authentication", () => {
  it("asks the user to sign in when there is no session", async () => {
    mockApi({ "GET /health": () => json(HEALTHY), "GET /api/v1/auth/session": unauthorized });
    render(<App />);
    expect(await screen.findByRole("heading", { name: "Sign in" })).toBeInTheDocument();
    expect(screen.getByText("traceforge dashboard-link")).toBeInTheDocument();
    expect(screen.queryByRole("navigation", { name: "Main" })).not.toBeInTheDocument();
  });

  it("redeems a sign-in link exactly once, even under StrictMode", async () => {
    const calls = mockApi({
      ...signedIn,
      "GET /api/v1/auth/session": unauthorized,
      "POST /api/v1/auth/session": () => json(SESSION),
    });

    render(
      <StrictMode>
        <App loginCode="one-time-code" />
      </StrictMode>,
    );

    expect(await screen.findByText("acme")).toBeInTheDocument();
    const redemptions = calls.filter((c) => c.method === "POST" && c.path === "/api/v1/auth/session");
    expect(redemptions).toHaveLength(1);
    expect(redemptions[0].body).toEqual({ code: "one-time-code" });
    expect(redemptions[0].credentials).toBe("same-origin");
    // The bootstrap must not also probe the existing session and race the sign-in.
    expect(calls.some((c) => c.method === "GET" && c.path === "/api/v1/auth/session")).toBe(false);
  });

  it("reports an invalid or used sign-in link", async () => {
    mockApi({
      "GET /health": () => json(HEALTHY),
      "POST /api/v1/auth/session": () => json({ detail: "Invalid or expired login code" }, 401),
    });
    render(<App loginCode="stale" />);
    expect(await screen.findByText(/invalid, expired or already used/)).toBeInTheDocument();
  });

  it("signs in with a pasted code", async () => {
    let session = false;
    mockApi({
      ...signedIn,
      "GET /api/v1/auth/session": () => (session ? json(SESSION) : unauthorized()),
      "POST /api/v1/auth/session": () => {
        session = true;
        return json(SESSION);
      },
      "GET /api/v1/projects": () => json([]),
    });
    render(<App />);
    fireEvent.change(await screen.findByLabelText("Or paste a sign-in code"), {
      target: { value: "  pasted-code  " },
    });
    fireEvent.click(screen.getByRole("button", { name: "Sign in" }));
    expect(await screen.findByText("No projects yet")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Overview", level: 1 })).toBeInTheDocument();
  });

  it("sends the CSRF token only on state-changing requests", async () => {
    const calls = mockApi({ ...signedIn, "DELETE /api/v1/auth/session": () => json(null, 204) });
    render(<App />);
    fireEvent.click(await screen.findByRole("button", { name: "Sign out" }));
    expect(await screen.findByRole("heading", { name: "Sign in" })).toBeInTheDocument();

    const signOut = calls.find((c) => c.method === "DELETE");
    expect(signOut?.headers[CSRF_HEADER]).toBe("csrf-123");
    for (const read of calls.filter((c) => c.method === "GET")) {
      expect(read.headers[CSRF_HEADER]).toBeUndefined();
    }
  });

  it("returns to sign-in when the session expires", async () => {
    mockApi({ ...signedIn, "GET /api/v1/projects": unauthorized });
    render(<App />);
    expect(await screen.findByText("Your session has expired.")).toBeInTheDocument();
  });

  it("never persists credentials in web storage or script-visible cookies", async () => {
    const setItem = vi.spyOn(Storage.prototype, "setItem");
    mockApi({
      ...signedIn,
      "GET /api/v1/auth/session": unauthorized,
      "POST /api/v1/auth/session": () => json(SESSION),
    });
    render(<App loginCode="one-time-code" />);
    await screen.findByText("acme");

    expect(setItem).not.toHaveBeenCalled();
    expect(localStorage.length).toBe(0);
    expect(sessionStorage.length).toBe(0);
    expect(document.cookie).toBe("");
  });
});

describe("console", () => {
  it("shows summary tiles from scan history", async () => {
    const scan = (id: number, status: string, open_ports = 0) => ({
      id,
      project_id: 1,
      tool: "nmap",
      name: "nmap scan",
      status,
      targets: ["10.0.0.5"],
      scan_addresses: ["10.0.0.5"],
      options: {},
      command: [],
      actor: "cli",
      timeout_seconds: 1800,
      created_at: "2026-11-08T12:00:00Z",
      started_at: null,
      finished_at: null,
      exit_code: null,
      error: null,
      tool_version: null,
      evidence: null,
      hosts_up: 1,
      open_ports,
    });
    mockApi({
      ...signedIn,
      [SCANS_LIST]: () => json([scan(3, "running"), scan(2, "completed", 4), scan(1, "completed", 2)]),
    });
    render(<App />);

    const summary = await screen.findByLabelText("Summary");
    const tile = (label: string) => within(summary).getByText(label).closest(".stat");
    await waitFor(() => expect(tile("Open ports found")).toHaveTextContent("Open ports found6"));
    expect(tile("Active scans")).toHaveTextContent("Active scans1");
    expect(within(summary).getByText("1 running · 0 queued")).toBeInTheDocument();
    expect(within(summary).getByText("2 completed · 0 failed")).toBeInTheDocument();
    expect(within(screen.getByRole("table", { name: "Recent scans" })).getAllByRole("row")).toHaveLength(4);
  });

  it("navigates between views with linkable URLs", async () => {
    mockApi({ ...signedIn, "GET /api/v1/projects/1/scope": () => json([]) });
    render(<App />);
    const nav = await screen.findByRole("navigation", { name: "Main" });

    fireEvent.click(within(nav).getByRole("link", { name: "Projects" }));
    expect(await screen.findByRole("heading", { name: "Projects", level: 1 })).toBeInTheDocument();
    expect(window.location.hash).toBe("#/projects");
    expect(within(nav).getByRole("link", { name: "Projects" })).toHaveAttribute("aria-current", "page");

    act(() => {
      window.history.back();
    });
    expect(await screen.findByRole("heading", { name: "Overview", level: 1 })).toBeInTheDocument();
  });

  it("shows a project's authorized scope", async () => {
    mockApi({
      ...signedIn,
      "GET /api/v1/projects/1/scope": () =>
        json([
          { id: 1, project_id: 1, kind: "include", value: "10.0.0.0/24", note: null, created_at: "2026-11-08T10:00:00Z" },
          { id: 2, project_id: 1, kind: "exclude", value: "10.0.0.13/32", note: "prod db", created_at: "2026-11-08T10:00:00Z" },
        ]),
    });
    window.history.replaceState(null, "", "/#/projects");
    render(<App />);
    fireEvent.click(await screen.findByRole("button", { name: "Open project acme" }));

    const rules = await screen.findByRole("table", { name: "Scope rules" });
    const rows = within(rules).getAllByRole("row").slice(1).map((r) => r.textContent);
    expect(rows).toEqual(["include10.0.0.0/24", "exclude10.0.0.13/32prod db"]);
  });
});

describe("takeLoginCodeFromUrl", () => {
  it("reads the code from the fragment and scrubs it from the URL", async () => {
    const { takeLoginCodeFromUrl } = await import("./api/client");
    window.history.replaceState(null, "", "/dashboard?x=1#code=abc123");

    await act(async () => {
      expect(takeLoginCodeFromUrl()).toBe("abc123");
    });

    expect(window.location.hash).toBe("");
    expect(window.location.pathname + window.location.search).toBe("/dashboard?x=1");
    expect(takeLoginCodeFromUrl()).toBeNull();
  });

  it("ignores URLs without a code", async () => {
    const { takeLoginCodeFromUrl } = await import("./api/client");
    window.history.replaceState(null, "", "/#section");
    expect(takeLoginCodeFromUrl()).toBeNull();
    await waitFor(() => expect(window.location.hash).toBe("#section"));
  });
});
