import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import App from "./App";
import { CSRF_HEADER, parseTargets, resetClientState } from "./api/client";
import { POLL_INTERVAL_MS } from "./components/ScansPage";
import { HEALTHY, SESSION, json, mockApi } from "./test/mockApi";

const LIST = "GET /api/v1/scans?limit=50";
const PROJECTS = [
  {
    id: 1,
    name: "acme",
    authorization_ref: "SOW-42",
    authorized_from: null,
    authorized_until: null,
    created_at: "2026-11-08T10:00:00Z",
    scope_rule_count: 2,
  },
];

function scan(overrides: Record<string, unknown> = {}) {
  return {
    id: 7,
    project_id: 1,
    tool: "nmap",
    name: "nmap scan",
    status: "completed",
    targets: ["app.example.com"],
    scan_addresses: ["93.184.216.34"],
    options: { ports: "22,80" },
    command: ["/usr/bin/nmap", "-sT", "--", "93.184.216.34"],
    actor: "dashboard",
    timeout_seconds: 1800,
    created_at: "2026-11-08T12:00:00Z",
    started_at: "2026-11-08T12:00:01Z",
    finished_at: "2026-11-08T12:00:09Z",
    exit_code: 0,
    error: null,
    tool_version: "7.99",
    evidence: { file: "scan-7-nmap-ab12.xml", sha256: "f".repeat(64), size_bytes: 1234 },
    hosts_up: 1,
    open_ports: 1,
    ...overrides,
  };
}

function results(product = "OpenSSH") {
  return {
    scan: scan(),
    hosts: [
      {
        asset_id: 1,
        address: "93.184.216.34",
        addr_type: "ipv4",
        state: "up",
        reason: "syn-ack",
        hostnames: ["app.example.com"],
        ports: [
          {
            protocol: "tcp",
            port: 22,
            state: "open",
            reason: "syn-ack",
            service_name: "ssh",
            service_product: product,
            service_version: "9.6p1",
            service_extrainfo: null,
            service_tunnel: null,
            service_method: "probed",
            service_confidence: 10,
            cpe: [],
          },
        ],
      },
    ],
  };
}

const signedInRoutes = {
  "GET /health": () => json(HEALTHY),
  "GET /api/v1/auth/session": () => json(SESSION),
  "GET /api/v1/projects": () => json(PROJECTS),
};

async function openScans() {
  render(<App />);
  fireEvent.click(await screen.findByRole("button", { name: "Scans" }));
}

beforeEach(() => {
  resetClientState();
});

afterEach(() => {
  vi.useRealTimers();
});

describe("scans page", () => {
  it("is only reachable when signed in", async () => {
    mockApi({
      "GET /health": () => json(HEALTHY),
      "GET /api/v1/auth/session": () => json({ detail: "Authentication required" }, 401),
    });
    render(<App />);
    expect(await screen.findByRole("heading", { name: "Sign in" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Scans" })).not.toBeInTheDocument();
  });

  it("lists scan history with statuses", async () => {
    mockApi({
      ...signedInRoutes,
      [LIST]: () => json([scan(), scan({ id: 8, status: "failed", open_ports: 0 })]),
    });
    await openScans();

    const table = await screen.findByRole("table", { name: "Scan history" });
    const rows = within(table).getAllByRole("row");
    expect(rows).toHaveLength(3);
    expect(within(rows[1]).getByText("completed")).toHaveClass("badge--completed");
    expect(within(rows[1]).getByText("acme")).toBeInTheDocument();
    expect(within(rows[2]).getByText("failed")).toBeInTheDocument();
    // Finished scans can't be cancelled.
    expect(screen.queryByRole("button", { name: /Cancel/ })).not.toBeInTheDocument();
  });

  it("launches a scan with CSRF and the chosen options", async () => {
    let launched = false;
    const calls = mockApi({
      ...signedInRoutes,
      [LIST]: () => json(launched ? [scan({ status: "queued" })] : []),
      "POST /api/v1/projects/1/scans": () => {
        launched = true;
        return json(
          {
            scan_id: 7,
            tool: "nmap",
            targets: ["10.0.0.5", "app.example.com"],
            scan_addresses: ["10.0.0.5", "93.184.216.34"],
            status: "queued",
          },
          202,
        );
      },
      "GET /api/v1/scans/7/results": () => json({ scan: scan({ status: "queued" }), hosts: [] }),
    });
    await openScans();
    expect(await screen.findByText(/No scans yet/)).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText("Authorized targets"), {
      target: { value: "10.0.0.5\napp.example.com, 10.0.0.5" },
    });
    fireEvent.change(screen.getByLabelText("Ports"), { target: { value: " 22,80 " } });
    fireEvent.change(screen.getByLabelText("Timing"), { target: { value: "4" } });
    fireEvent.click(screen.getByRole("button", { name: "Start scan" }));

    expect(await screen.findByText(/Queued scan #7 of 10.0.0.5, 93.184.216.34/)).toBeInTheDocument();
    const post = calls.find((c) => c.method === "POST" && c.path === "/api/v1/projects/1/scans");
    expect(post?.headers[CSRF_HEADER]).toBe("csrf-123");
    expect(post?.body).toEqual({
      tool: "nmap",
      targets: ["10.0.0.5", "app.example.com"],
      options: { service_detection: true, timing: 4, skip_host_discovery: false, ports: "22,80" },
    });
    expect(await screen.findByRole("heading", { name: "Scan results" })).toBeInTheDocument();
  });

  it("explains which targets are outside the authorized scope", async () => {
    mockApi({
      ...signedInRoutes,
      [LIST]: () => json([]),
      "POST /api/v1/projects/1/scans": () =>
        json(
          {
            detail: {
              message: "Targets outside authorized scope; nothing was launched",
              decisions: [
                { target: "10.0.0.5", allowed: true, reason: "within authorized range 10.0.0.0/24" },
                { target: "8.8.8.8", allowed: false, reason: "not within any authorized range" },
              ],
            },
          },
          403,
        ),
    });
    await openScans();
    fireEvent.change(await screen.findByLabelText("Authorized targets"), {
      target: { value: "10.0.0.5 8.8.8.8" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Start scan" }));

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("nothing was launched");
    expect(within(alert).getByText("8.8.8.8").closest("li")).toHaveClass("denied");
    expect(alert).toHaveTextContent("not within any authorized range");
  });

  it("shows validation errors from the API", async () => {
    mockApi({
      ...signedInRoutes,
      [LIST]: () => json([]),
      "POST /api/v1/projects/1/scans": () =>
        json({ detail: "ports: Value error, ports must look like '22,80,443'" }, 422),
    });
    await openScans();
    fireEvent.change(await screen.findByLabelText("Authorized targets"), {
      target: { value: "10.0.0.5" },
    });
    fireEvent.change(screen.getByLabelText("Ports"), { target: { value: "22;id" } });
    fireEvent.click(screen.getByRole("button", { name: "Start scan" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("ports must look like");
  });

  it("shows ports and services for a selected scan", async () => {
    mockApi({
      ...signedInRoutes,
      [LIST]: () => json([scan()]),
      "GET /api/v1/scans/7/results": () => json(results()),
    });
    await openScans();
    fireEvent.click(await screen.findByRole("button", { name: "Results for scan 7" }));

    const table = await screen.findByRole("table", { name: "Ports and services" });
    const cells = within(within(table).getAllByRole("row")[1])
      .getAllByRole("cell")
      .map((c) => c.textContent);
    expect(cells).toEqual(["93.184.216.34 (app.example.com)", "22/tcp", "open", "ssh", "OpenSSH 9.6p1"]);
    expect(screen.getByText("scan-7-nmap-ab12.xml", { exact: false })).toBeInTheDocument();
  });

  it("renders target-controlled banners as inert text", async () => {
    const hostile = '<img src=x onerror="alert(1)"><script>alert(2)</script>';
    mockApi({
      ...signedInRoutes,
      [LIST]: () => json([scan()]),
      "GET /api/v1/scans/7/results": () => json(results(hostile)),
    });
    await openScans();
    fireEvent.click(await screen.findByRole("button", { name: "Results for scan 7" }));

    expect(await screen.findByText(`${hostile} 9.6p1`)).toBeInTheDocument();
    expect(document.querySelector("img")).toBeNull();
    expect(document.querySelector("main script")).toBeNull();
  });

  it("cancels a running scan", async () => {
    let status = "running";
    const calls = mockApi({
      ...signedInRoutes,
      [LIST]: () => json([scan({ status, finished_at: null, evidence: null })]),
      "POST /api/v1/scans/7/cancel": () => {
        status = "cancelled";
        return json(scan({ status }));
      },
    });
    await openScans();
    fireEvent.click(await screen.findByRole("button", { name: "Cancel scan 7" }));

    expect(await screen.findByText("Scan #7 cancelled.")).toBeInTheDocument();
    expect(calls.find((c) => c.method === "POST")?.headers[CSRF_HEADER]).toBe("csrf-123");
    await waitFor(() =>
      expect(screen.queryByRole("button", { name: "Cancel scan 7" })).not.toBeInTheDocument(),
    );
  });

  it("polls while scans are active and stops when they finish", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    let status = "running";
    const calls = mockApi({
      ...signedInRoutes,
      [LIST]: () => json([scan({ status })]),
    });
    await openScans();
    await screen.findByText("running");
    const listCalls = () => calls.filter((c) => c.path === "/api/v1/scans?limit=50").length;
    const before = listCalls();

    status = "completed";
    await act(async () => {
      await vi.advanceTimersByTimeAsync(POLL_INTERVAL_MS);
    });
    expect(await screen.findByText("completed")).toBeInTheDocument();
    const after = listCalls();
    expect(after).toBe(before + 1);

    await act(async () => {
      await vi.advanceTimersByTimeAsync(POLL_INTERVAL_MS * 3);
    });
    expect(listCalls()).toBe(after);
  });

  it("explains how to create a project when there are none", async () => {
    mockApi({ ...signedInRoutes, "GET /api/v1/projects": () => json([]), [LIST]: () => json([]) });
    await openScans();
    expect(await screen.findByText(/Scans need a project with an authorized scope/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Start scan" })).not.toBeInTheDocument();
  });

  it("returns to sign-in when the session expires", async () => {
    mockApi({
      ...signedInRoutes,
      [LIST]: () => json({ detail: "Session expired or invalid" }, 401),
    });
    await openScans();
    expect(await screen.findByText("Your session has expired.")).toBeInTheDocument();
  });
});

describe("parseTargets", () => {
  it("splits on whitespace and commas and removes duplicates", () => {
    expect(parseTargets(" 10.0.0.1,10.0.0.2\n\n10.0.0.1  a.example.com ")).toEqual([
      "10.0.0.1",
      "10.0.0.2",
      "a.example.com",
    ]);
    expect(parseTargets("   ")).toEqual([]);
  });
});
