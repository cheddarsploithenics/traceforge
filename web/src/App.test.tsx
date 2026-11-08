import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { StrictMode } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import App from "./App";
import { CSRF_HEADER, resetClientState } from "./api/client";
import { HEALTHY, SESSION, json, mockApi } from "./test/mockApi";

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

beforeEach(() => {
  resetClientState();
  localStorage.clear();
  sessionStorage.clear();
});

describe("health", () => {
  it("shows healthy backend status", async () => {
    const calls = mockApi({ "GET /health": () => json(HEALTHY), "GET /api/v1/auth/session": unauthorized });
    render(<App />);
    expect(await screen.findByText("OK")).toBeInTheDocument();
    expect(screen.getByText("0.1.0")).toBeInTheDocument();
    // Same-origin relative URLs only: never an absolute, cross-origin API URL.
    expect(calls.every((c) => c.path.startsWith("/"))).toBe(true);
  });

  it("shows degraded status from a 503 response", async () => {
    mockApi({
      "GET /health": () => json({ ...HEALTHY, status: "degraded", database: "error" }, 503),
      "GET /api/v1/auth/session": unauthorized,
    });
    render(<App />);
    expect(await screen.findByText("DEGRADED")).toBeInTheDocument();
  });

  it("explains how to start the backend when it is unreachable", async () => {
    vi.spyOn(globalThis, "fetch").mockRejectedValue(new TypeError("Failed to fetch"));
    render(<App />);
    const alerts = await screen.findAllByRole("alert");
    expect(alerts[0]).toHaveTextContent("Cannot reach the TraceForge API");
    expect(screen.getByText("traceforge serve")).toBeInTheDocument();
  });
});

describe("authentication", () => {
  it("asks the user to sign in when there is no session", async () => {
    mockApi({ "GET /health": () => json(HEALTHY), "GET /api/v1/auth/session": unauthorized });
    render(<App />);
    expect(await screen.findByRole("heading", { name: "Sign in" })).toBeInTheDocument();
    expect(screen.getByText("traceforge dashboard-link")).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Projects" })).not.toBeInTheDocument();
  });

  it("redeems a sign-in link exactly once, even under StrictMode", async () => {
    const calls = mockApi({
      "GET /health": () => json(HEALTHY),
      "POST /api/v1/auth/session": () => json(SESSION),
      "GET /api/v1/projects": () => json(PROJECTS),
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
    let signedIn = false;
    mockApi({
      "GET /health": () => json(HEALTHY),
      "GET /api/v1/auth/session": () => (signedIn ? json(SESSION) : unauthorized()),
      "POST /api/v1/auth/session": () => {
        signedIn = true;
        return json(SESSION);
      },
      "GET /api/v1/projects": () => json([]),
    });
    render(<App />);
    fireEvent.change(await screen.findByLabelText("Or paste a sign-in code"), {
      target: { value: "  pasted-code  " },
    });
    fireEvent.click(screen.getByRole("button", { name: "Sign in" }));
    expect(await screen.findByText(/No projects yet/)).toBeInTheDocument();
  });

  it("sends the CSRF token only on state-changing requests", async () => {
    const calls = mockApi({
      "GET /health": () => json(HEALTHY),
      "GET /api/v1/auth/session": () => json(SESSION),
      "GET /api/v1/projects": () => json(PROJECTS),
      "DELETE /api/v1/auth/session": () => json(null, 204),
    });
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
    mockApi({
      "GET /health": () => json(HEALTHY),
      "GET /api/v1/auth/session": () => json(SESSION),
      "GET /api/v1/projects": unauthorized,
    });
    render(<App />);
    expect(await screen.findByText("Your session has expired.")).toBeInTheDocument();
  });

  it("never persists credentials in web storage or script-visible cookies", async () => {
    const setItem = vi.spyOn(Storage.prototype, "setItem");
    mockApi({
      "GET /health": () => json(HEALTHY),
      "POST /api/v1/auth/session": () => json(SESSION),
      "GET /api/v1/projects": () => json(PROJECTS),
    });
    render(<App loginCode="one-time-code" />);
    await screen.findByText("acme");

    expect(setItem).not.toHaveBeenCalled();
    expect(localStorage.length).toBe(0);
    expect(sessionStorage.length).toBe(0);
    expect(document.cookie).toBe("");
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
