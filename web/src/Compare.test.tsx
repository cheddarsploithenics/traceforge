import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { beforeEach, describe, expect, it } from "vitest";

import App from "./App";
import { resetClientState } from "./api/client";
import { HEALTHY, SCANS_LIST, SESSION, json, mockApi } from "./test/mockApi";

const PROJECTS = [
  { id: 1, name: "acme", authorization_ref: "SOW-42", authorized_from: null, authorized_until: null, created_at: "2026-11-08T10:00:00Z", scope_rule_count: 1 },
];

function scan(id: number, status = "completed") {
  return {
    id, project_id: 1, tool: "nmap", name: "nmap scan", status, targets: ["10.0.0.0/24"],
    scan_addresses: ["10.0.0.0/24"], options: {}, command: [], actor: "cli", timeout_seconds: 1800,
    created_at: `2026-11-08T1${id}:00:00Z`, started_at: `2026-11-08T1${id}:00:01Z`,
    finished_at: `2026-11-08T1${id}:00:09Z`, exit_code: 0, error: null, tool_version: "7.99",
    evidence: null, hosts_up: 1, open_ports: 1, ports_scanned: { tcp: "22,8080" },
  };
}

function side(id: number, extra: Record<string, unknown> = {}) {
  return {
    scan_id: id, status: "completed", created_at: "2026-11-08T12:00:00Z", finished_at: "2026-11-08T12:00:09Z",
    tool: "nmap", tool_version: "7.99", targets: ["10.0.0.0/24"], scan_addresses: ["10.0.0.0/24"],
    ports_scanned: { tcp: "22,8080" }, host_discovery: true, service_detection: true,
    hosts_responsive: 2, evidence: null, ...extra,
  };
}

const port = (p: number, state: string, service: string | null = null, version: string | null = null) => ({
  protocol: "tcp", port: p, state, reason: null, service_name: service, service_product: null,
  service_version: version, service_extrainfo: null, service_method: service ? "probed" : null,
  identification: service ? "detected" : null, cpe: [],
});

const change = (category: string, kind: string, p: number | null, detail: string, before: unknown, after: unknown) => ({
  category, kind, address: "10.0.0.5", asset_uid: "ast_0123456789abcdef", hostnames: [],
  protocol: p === null ? null : "tcp", port: p, before, after, detail,
});

const COMPARISON = {
  project_id: 1,
  baseline: side(6),
  comparison: side(7, { ports_scanned: { tcp: "22" }, host_discovery: false }),
  summary: { added: 1, removed: 1, changed: 1, inconclusive: 1, unchanged_open_ports: 3 },
  changes: [
    change("added", "port_opened", 443, "was closed, now open", port(443, "closed"), port(443, "open", "https")),
    change("removed", "port_closed", 25, "was open, now confirmed closed", port(25, "open", "smtp"), port(25, "closed")),
    change("changed", "version_changed", 22, "ssh version OpenSSH 9.6 → OpenSSH 9.7", port(22, "open", "ssh", "9.6"), port(22, "open", "ssh", "9.7")),
    change("inconclusive", "port_not_checked", 8080, "was open; not observed in this scan (port not scanned)", port(8080, "open", "http"), null),
  ],
  notes: ["The comparison scan used -Pn: hosts count as present only if a port answered."],
};

const signedIn = {
  "GET /health": () => json(HEALTHY),
  "GET /api/v1/auth/session": () => json(SESSION),
  "GET /api/v1/projects": () => json(PROJECTS),
  [SCANS_LIST]: () => json([scan(7), scan(6), scan(5, "failed")]),
};
const COMPARE_URL = "GET /api/v1/projects/1/scans/compare?baseline=6&comparison=7";

async function openCompare() {
  window.history.replaceState(null, "", "/#/scans");
  render(<App />);
  fireEvent.click(await screen.findByRole("button", { name: "Compare scans" }));
}

beforeEach(() => {
  resetClientState();
});

describe("compare scans", () => {
  it("compares the two latest completed scans and groups the results", async () => {
    const calls = mockApi({ ...signedIn, [COMPARE_URL]: () => json(COMPARISON) });
    await openCompare();

    const baseline = await screen.findByLabelText("Baseline (A)");
    await waitFor(() => expect(baseline).toHaveValue("6"));
    expect(screen.getByLabelText("Comparison (B)")).toHaveValue("7");
    // Failed scans are not offered: they would make missing observations look like changes.
    expect(within(baseline).queryByText(/^#5/)).toBeNull();

    fireEvent.click(screen.getByRole("button", { name: "Compare" }));
    const summary = await screen.findByRole("region", { name: "Comparison summary" });
    expect(calls.some((c) => `GET ${c.path}` === COMPARE_URL)).toBe(true);
    for (const label of ["Added", "Removed", "Changed", "Inconclusive"]) {
      expect(within(summary).getByText(label).closest(".compare-count")).toHaveTextContent(`1${label}`);
    }
    expect(within(summary).getByText("open ports unchanged")).toBeInTheDocument();
    expect(within(summary).getByText(/used -Pn/)).toBeInTheDocument();

    const coverage = screen.getByRole("table", { name: "Scan coverage" });
    expect(within(coverage).getByText("tcp 22")).toBeInTheDocument();
    expect(within(coverage).getByText("off (-Pn)")).toBeInTheDocument();

    const removed = screen.getByRole("table", { name: "Removed changes" });
    expect(within(removed).getByText("Port closed")).toBeInTheDocument();
    expect(within(removed).getByText("open smtp")).toBeInTheDocument();
    const inconclusive = screen.getByRole("table", { name: "Inconclusive changes" });
    expect(within(inconclusive).getByText("Not checked")).toBeInTheDocument();
    expect(within(inconclusive).getByText(/port not scanned/)).toBeInTheDocument();
    expect(screen.getByRole("table", { name: "Changed changes" })).toHaveTextContent("Version changed");
    expect(screen.getByRole("table", { name: "Added changes" })).toHaveTextContent("open https");
  });

  it("shows why a comparison is refused", async () => {
    mockApi({
      ...signedIn,
      [COMPARE_URL]: () => json({ detail: "scan 7 is failed; only completed scans can be compared" }, 409),
    });
    await openCompare();
    await waitFor(() => expect(screen.getByLabelText("Comparison (B)")).toHaveValue("7"));
    fireEvent.click(screen.getByRole("button", { name: "Compare" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("only completed scans can be compared");
  });

  it("compares a scan with the previous one from its detail panel", async () => {
    const calls = mockApi({
      ...signedIn,
      [COMPARE_URL]: () => json(COMPARISON),
      "GET /api/v1/scans/7/results": () => json({ scan: scan(7), hosts: [] }),
    });
    window.history.replaceState(null, "", "/#/scans");
    render(<App />);
    fireEvent.click(await screen.findByRole("button", { name: "Open scan 7" }));
    fireEvent.click(await screen.findByRole("button", { name: "Compare with #6" }));

    expect(await screen.findByRole("region", { name: "Comparison summary" })).toBeInTheDocument();
    expect(calls.filter((c) => `GET ${c.path}` === COMPARE_URL)).toHaveLength(1);
  });

  it("links changed hosts to the asset inventory", async () => {
    mockApi({
      ...signedIn,
      [COMPARE_URL]: () => json(COMPARISON),
      "GET /api/v1/assets?limit=500": () => json([]),
      "GET /api/v1/assets/ast_0123456789abcdef": () => json({ detail: "gone" }, 404),
    });
    await openCompare();
    await waitFor(() => expect(screen.getByLabelText("Comparison (B)")).toHaveValue("7"));
    fireEvent.click(screen.getByRole("button", { name: "Compare" }));
    const removed = await screen.findByRole("table", { name: "Removed changes" });
    fireEvent.click(within(removed).getByRole("button", { name: "10.0.0.5" }));
    expect(await screen.findByRole("heading", { name: "Assets", level: 1 })).toBeInTheDocument();
    expect(window.location.hash).toBe("#/assets");
  });
});
