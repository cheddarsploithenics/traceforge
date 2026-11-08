import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import App from "./App";
import { CSRF_HEADER, parseTargets, resetClientState } from "./api/client";
import { POLL_INTERVAL_MS } from "./hooks/useScans";
import { HEALTHY, SCANS_LIST, SESSION, json, mockApi } from "./test/mockApi";

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
    options: { ports: "22,80", service_detection: true, timing: 3 },
    command: ["/usr/bin/nmap", "-sT", "-sV", "--", "93.184.216.34"],
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

function results(product = "OpenSSH", overrides: Record<string, unknown> = {}) {
  return {
    scan: scan(overrides),
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

const signedIn = {
  "GET /health": () => json(HEALTHY),
  "GET /api/v1/auth/session": () => json(SESSION),
  "GET /api/v1/projects": () => json(PROJECTS),
};

async function openScans() {
  window.history.replaceState(null, "", "/#/scans");
  render(<App />);
  await screen.findByRole("heading", { name: "Scans", level: 1 });
}

async function startNewScan(targets: string) {
  const button = screen.getByRole("button", { name: "New scan" });
  await waitFor(() => expect(button).toBeEnabled()); // enabled once projects load
  fireEvent.click(button);
  fireEvent.change(await screen.findByLabelText("Authorized targets"), { target: { value: targets } });
}

beforeEach(() => {
  resetClientState();
});

afterEach(() => {
  vi.useRealTimers();
});

describe("scans page", () => {
  it("lists scan history with statuses and filters", async () => {
    mockApi({
      ...signedIn,
      [SCANS_LIST]: () =>
        json([
          scan(),
          scan({ id: 8, status: "failed", open_ports: 0, targets: ["10.0.0.9"] }),
          scan({ id: 9, status: "running", targets: ["10.0.0.10"] }),
        ]),
    });
    await openScans();

    const table = await screen.findByRole("table", { name: "Scan history" });
    const rows = within(table).getAllByRole("row");
    expect(rows).toHaveLength(4);
    expect(within(rows[1]).getByText("Completed")).toBeInTheDocument();
    expect(within(rows[1]).getByText("acme")).toBeInTheDocument();

    const filters = screen.getByRole("group", { name: "Filter by status" });
    fireEvent.click(within(filters).getByRole("button", { name: /Failed/ }));
    expect(within(table).getAllByRole("row")).toHaveLength(2);
    expect(within(table).getByText("10.0.0.9")).toBeInTheDocument();

    fireEvent.click(within(filters).getByRole("button", { name: /All/ }));
    fireEvent.change(screen.getByLabelText("Search scans"), { target: { value: "10.0.0.10" } });
    expect(within(table).getAllByRole("row")).toHaveLength(2);
    expect(within(table).getByText("Running")).toBeInTheDocument();
  });

  it("launches a scan with CSRF and the chosen options", async () => {
    let launched = false;
    const calls = mockApi({
      ...signedIn,
      [SCANS_LIST]: () => json(launched ? [scan({ status: "queued" })] : []),
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
    expect(await screen.findByText("No scans yet")).toBeInTheDocument();

    await startNewScan("10.0.0.5\napp.example.com, 10.0.0.5");
    expect(screen.getByText(/2 target\(s\)\./)).toBeInTheDocument();
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
    // The new scan opens in the detail panel.
    expect(await screen.findByRole("heading", { name: "Scan #7" })).toBeInTheDocument();
  });

  it("explains which targets are outside the authorized scope", async () => {
    mockApi({
      ...signedIn,
      [SCANS_LIST]: () => json([]),
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
    await startNewScan("10.0.0.5 8.8.8.8");
    fireEvent.click(screen.getByRole("button", { name: "Start scan" }));

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("nothing was launched");
    expect(within(alert).getByText("8.8.8.8").closest("li")).toHaveClass("denied");
    expect(alert).toHaveTextContent("not within any authorized range");
  });

  it("shows validation errors from the API", async () => {
    mockApi({
      ...signedIn,
      [SCANS_LIST]: () => json([]),
      "POST /api/v1/projects/1/scans": () =>
        json({ detail: [{ loc: ["body", "options", "ports"], msg: "ports must look like '22,80,443'" }], }, 422),
    });
    await openScans();
    await startNewScan("10.0.0.5");
    fireEvent.change(screen.getByLabelText("Ports"), { target: { value: "22;id" } });
    fireEvent.click(screen.getByRole("button", { name: "Start scan" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("options.ports: ports must look like");
  });

  it("shows ports, services, command and evidence for a selected scan", async () => {
    mockApi({
      ...signedIn,
      [SCANS_LIST]: () => json([scan()]),
      "GET /api/v1/scans/7/results": () => json(results()),
    });
    await openScans();
    fireEvent.click(await screen.findByRole("button", { name: "Open scan 7" }));

    const table = await screen.findByRole("table", { name: "Ports and services" });
    const cells = within(within(table).getAllByRole("row")[1])
      .getAllByRole("cell")
      .map((c) => c.textContent);
    expect(cells).toEqual(["93.184.216.34app.example.com", "22/tcp", "open", "ssh", "OpenSSH 9.6p1"]);
    expect(screen.getByText("/usr/bin/nmap -sT -sV -- 93.184.216.34")).toBeInTheDocument();
    expect(screen.getByText("scan-7-nmap-ab12.xml")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Evidence XML" })).toHaveAttribute(
      "href",
      "/api/v1/scans/7/evidence",
    );
    expect(screen.getByText("ports 22,80 · -sV · T3")).toBeInTheDocument();

    fireEvent.keyDown(window, { key: "Escape" });
    await waitFor(() => expect(screen.queryByRole("heading", { name: "Scan #7" })).not.toBeInTheDocument());
  });

  it("renders target-controlled banners as inert text", async () => {
    const hostile = '<img src=x onerror="alert(1)"><script>alert(2)</script>';
    mockApi({
      ...signedIn,
      [SCANS_LIST]: () => json([scan()]),
      "GET /api/v1/scans/7/results": () => json(results(hostile)),
    });
    await openScans();
    fireEvent.click(await screen.findByRole("button", { name: "Open scan 7" }));

    expect(await screen.findByText(`${hostile} 9.6p1`)).toBeInTheDocument();
    expect(document.querySelector("main img")).toBeNull();
    expect(document.querySelector("main script")).toBeNull();
  });

  it("cancels a running scan", async () => {
    let status = "running";
    const running = { finished_at: null, evidence: null };
    const calls = mockApi({
      ...signedIn,
      [SCANS_LIST]: () => json([scan({ status, ...running })]),
      "GET /api/v1/scans/7/results": () => json({ scan: scan({ status, ...running }), hosts: [] }),
      "POST /api/v1/scans/7/cancel": () => {
        status = "cancelled";
        return json(scan({ status }));
      },
    });
    await openScans();
    fireEvent.click(await screen.findByRole("button", { name: "Open scan 7" }));
    fireEvent.click(await screen.findByRole("button", { name: "Cancel scan" }));

    expect(await screen.findByText("Scan #7 cancelled.")).toBeInTheDocument();
    expect(calls.find((c) => c.method === "POST")?.headers[CSRF_HEADER]).toBe("csrf-123");
    await waitFor(() =>
      expect(screen.queryByRole("button", { name: "Cancel scan" })).not.toBeInTheDocument(),
    );
  });

  it("polls while scans are active and stops when they finish", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    let status = "running";
    const calls = mockApi({ ...signedIn, [SCANS_LIST]: () => json([scan({ status })]) });
    await openScans();
    const table = await screen.findByRole("table", { name: "Scan history" });
    await within(table).findByText("Running");
    const listCalls = () => calls.filter((c) => `GET ${c.path}` === SCANS_LIST).length;
    const before = listCalls();

    status = "completed";
    await act(async () => {
      await vi.advanceTimersByTimeAsync(POLL_INTERVAL_MS);
    });
    expect(await within(table).findByText("Completed")).toBeInTheDocument();
    const after = listCalls();
    expect(after).toBe(before + 1);

    await act(async () => {
      await vi.advanceTimersByTimeAsync(POLL_INTERVAL_MS * 3);
    });
    expect(listCalls()).toBe(after);
  });

  it("opens a scan clicked on the overview", async () => {
    mockApi({
      ...signedIn,
      [SCANS_LIST]: () => json([scan()]),
      "GET /api/v1/scans/7/results": () => json(results()),
    });
    render(<App />);
    const recent = await screen.findByRole("table", { name: "Recent scans" });
    fireEvent.click(within(recent).getByRole("button", { name: "Open scan 7" }));

    expect(await screen.findByRole("heading", { name: "Scans", level: 1 })).toBeInTheDocument();
    expect(await screen.findByRole("table", { name: "Ports and services" })).toBeInTheDocument();
    expect(window.location.hash).toBe("#/scans");
  });

  it("explains how to create a project when there are none", async () => {
    mockApi({ ...signedIn, "GET /api/v1/projects": () => json([]), [SCANS_LIST]: () => json([]) });
    await openScans();
    expect(await screen.findByText(/Scans need a project with an authorized scope/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "New scan" })).toBeDisabled();
  });

  it("returns to sign-in when the session expires", async () => {
    mockApi({ ...signedIn, [SCANS_LIST]: () => json({ detail: "Session expired or invalid" }, 401) });
    await openScans().catch(() => undefined);
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
