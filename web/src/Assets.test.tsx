import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { beforeEach, describe, expect, it } from "vitest";

import App from "./App";
import { resetClientState } from "./api/client";
import { HEALTHY, SCANS_LIST, SESSION, json, mockApi } from "./test/mockApi";

const UID = "ast_0123456789abcdef";
const PROJECTS = [
  { id: 1, name: "acme", authorization_ref: "SOW-42", authorized_from: null, authorized_until: null, created_at: "2026-11-08T10:00:00Z", scope_rule_count: 1 },
  { id: 2, name: "beta", authorization_ref: "SOW-7", authorized_from: null, authorized_until: null, created_at: "2026-11-08T10:00:00Z", scope_rule_count: 1 },
];

function summary(overrides: Record<string, unknown> = {}) {
  return {
    uid: UID,
    project_id: 1,
    project_name: "acme",
    address: "10.0.0.5",
    addr_type: "ipv4",
    hostnames: ["app.acme.example"],
    first_seen: "2026-11-08T12:00:00.000Z",
    last_seen: "2026-11-08T14:00:00.000Z",
    confirmed: true,
    open_ports: 2,
    last_scan_id: 2,
    services: [
      { protocol: "tcp", port: 22, service_name: "ssh", identification: "detected" },
      { protocol: "tcp", port: 8080, service_name: "http-proxy", identification: "port-label" },
    ],
    ...overrides,
  };
}

function provenance(scanId: number) {
  return {
    project_id: 1,
    scan_id: scanId,
    tool: "nmap",
    tool_version: "7.99",
    observed_at: "2026-11-08T14:00:00.000Z",
    requested_targets: ["10.0.0.0/24"],
    scanned_address: "10.0.0.5",
    configuration: {
      options: { service_detection: true },
      command: ["/usr/bin/nmap", "-sT"],
      timeout_seconds: 1800,
      ports_scanned: { tcp: "22,8080" },
      host_discovery: true,
      service_detection: true,
    },
    evidence: { file: `scan-${scanId}-nmap-ab.xml`, sha256: "a".repeat(64), size_bytes: 900 },
  };
}

function detail(product = "OpenSSH") {
  return {
    ...summary(),
    ports: [
      {
        protocol: "tcp", port: 22, state: "open", state_scan_id: 2, first_seen: "2026-11-08T12:00:00.000Z",
        last_seen: "2026-11-08T14:00:00.000Z", last_open_at: "2026-11-08T14:00:00.000Z",
        service_name: "ssh", service_product: product, service_version: "9.7p1", service_extrainfo: null,
        service_method: "probed", identification: "detected", service_confidence: 10, cpe: [], service_scan_id: 2,
      },
      {
        protocol: "tcp", port: 8080, state: "closed", state_scan_id: 2, first_seen: "2026-11-08T12:00:00.000Z",
        last_seen: "2026-11-08T14:00:00.000Z", last_open_at: "2026-11-08T12:00:00.000Z",
        service_name: "http-proxy", service_product: null, service_version: null, service_extrainfo: null,
        service_method: "table", identification: "port-label", service_confidence: 3, cpe: [], service_scan_id: 1,
      },
    ],
    observations: [
      { scan_id: 2, observed_at: "2026-11-08T14:00:00.000Z", state: "up", reason: "conn-refused", responsive: true, timed_out: false, hostnames: [], ports: [{ protocol: "tcp", port: 22, state: "open", reason: "syn-ack", service_name: "ssh", service_product: product, service_version: "9.7p1", service_extrainfo: null, service_method: "probed", identification: "detected", cpe: [] }], provenance: provenance(2) },
      { scan_id: 1, observed_at: "2026-11-08T12:00:00.000Z", state: "up", reason: "conn-refused", responsive: true, timed_out: false, hostnames: [], ports: [], provenance: provenance(1) },
    ],
  };
}

const signedIn = {
  "GET /health": () => json(HEALTHY),
  "GET /api/v1/auth/session": () => json(SESSION),
  "GET /api/v1/projects": () => json(PROJECTS),
  [SCANS_LIST]: () => json([]),
  "GET /api/v1/assets?limit=500": () => json([summary()]),
  [`GET /api/v1/assets/${UID}`]: () => json(detail()),
};

async function openAssets() {
  window.history.replaceState(null, "", "/#/assets");
  render(<App />);
  return screen.findByRole("table", { name: "Asset inventory" });
}

beforeEach(() => {
  resetClientState();
});

describe("assets page", () => {
  it("is in the sidebar", async () => {
    mockApi(signedIn);
    render(<App />);
    const nav = await screen.findByRole("navigation", { name: "Main" });
    fireEvent.click(within(nav).getByRole("link", { name: "Assets" }));
    expect(await screen.findByRole("heading", { name: "Assets", level: 1 })).toBeInTheDocument();
    expect(window.location.hash).toBe("#/assets");
  });

  it("lists assets with services, counts and timestamps", async () => {
    mockApi(signedIn);
    const table = await openAssets();
    const row = within(table).getAllByRole("row")[1];
    expect(within(row).getByText("10.0.0.5")).toBeInTheDocument();
    expect(within(row).getByText("app.acme.example")).toBeInTheDocument();
    expect(within(row).getByText("acme")).toBeInTheDocument();
    expect(within(row).getByText("2")).toHaveClass("num");
    // Detected services and port-number labels are styled differently.
    expect(within(row).getByText("ssh").closest(".service")).toHaveClass("service--detected");
    expect(within(row).getByText("http-proxy").closest(".service")).not.toHaveClass("service--detected");
  });

  it("searches and filters by project through the API", async () => {
    const calls = mockApi({
      ...signedIn,
      "GET /api/v1/assets?limit=500&q=jetty": () => json([]),
      "GET /api/v1/assets?limit=500&project_id=2": () => json([]),
    });
    await openAssets();

    fireEvent.change(screen.getByLabelText("Search assets"), { target: { value: "jetty" } });
    expect(await screen.findByText("No assets match these filters")).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Search assets"), { target: { value: "" } });
    fireEvent.change(screen.getByLabelText("Filter by project"), { target: { value: "2" } });
    await waitFor(() =>
      expect(calls.some((c) => c.path === "/api/v1/assets?limit=500&project_id=2")).toBe(true),
    );
    expect(calls.some((c) => c.path === "/api/v1/assets?limit=500&q=jetty")).toBe(true);
  });

  it("expands an asset to show ports, provenance and evidence", async () => {
    const calls = mockApi({
      ...signedIn,
      "GET /api/v1/scans/2/evidence/verify": () =>
        json({ scan_id: 2, file: "scan-2-nmap-ab.xml", recorded_sha256: "a".repeat(64), actual_sha256: "a".repeat(64), size_bytes: 900, verified: true, detail: "ok" }),
    });
    await openAssets();
    const button = screen.getByRole("button", { name: "Asset 10.0.0.5" });
    fireEvent.click(button);

    const ports = await screen.findByRole("table", { name: "Asset ports" });
    expect(button).toHaveAttribute("aria-expanded", "true");
    const [ssh, proxy] = within(ports).getAllByRole("row").slice(1);
    expect(within(ssh).getByText("detected")).toHaveClass("tag--detected");
    expect(within(ssh).getByText("OpenSSH 9.7p1")).toBeInTheDocument();
    expect(within(proxy).getByText("port label")).toHaveClass("tag--label");
    expect(within(proxy).getByText("closed")).toBeInTheDocument();

    expect(screen.getByText(UID)).toBeInTheDocument();
    expect(screen.getAllByText("10.0.0.0/24")).toHaveLength(2);
    const downloads = screen.getAllByRole("link", { name: "Download" });
    expect(downloads.map((a) => a.getAttribute("href"))).toEqual([
      "/api/v1/scans/2/evidence",
      "/api/v1/scans/1/evidence",
    ]);
    // Each observation states the scan configuration that produced it.
    expect(screen.getAllByText("tcp 22,8080 · -sV")).toHaveLength(2);

    fireEvent.click(screen.getAllByRole("button", { name: "Verify hash" })[0]);
    expect(await screen.findByText("Verified")).toBeInTheDocument();
    expect(calls.filter((c) => c.path.endsWith("/evidence/verify"))).toHaveLength(1);
  });

  it("links observations to their originating scan", async () => {
    mockApi({
      ...signedIn,
      [SCANS_LIST]: () => json([]),
      "GET /api/v1/scans/1/results": () => json({ scan: null, hosts: [] }, 404),
    });
    await openAssets();
    fireEvent.click(screen.getByRole("button", { name: "Asset 10.0.0.5" }));
    await screen.findByRole("table", { name: "Asset ports" });
    const scanLinks = screen.getAllByRole("button", { name: "#1" });
    fireEvent.click(scanLinks[0]);
    expect(await screen.findByRole("heading", { name: "Scans", level: 1 })).toBeInTheDocument();
    expect(await screen.findByRole("heading", { name: "Scan #1" })).toBeInTheDocument();
  });

  it("renders target-controlled text inertly", async () => {
    const hostile = '<img src=x onerror="alert(1)">';
    mockApi({ ...signedIn, [`GET /api/v1/assets/${UID}`]: () => json(detail(hostile)) });
    await openAssets();
    fireEvent.click(screen.getByRole("button", { name: "Asset 10.0.0.5" }));
    expect(await screen.findByText(`${hostile} 9.7p1`)).toBeInTheDocument();
    expect(document.querySelector("main img")).toBeNull();
  });

  it("explains an empty inventory", async () => {
    mockApi({ ...signedIn, "GET /api/v1/assets?limit=500": () => json([]) });
    window.history.replaceState(null, "", "/#/assets");
    render(<App />);
    expect(await screen.findByText("No assets yet")).toBeInTheDocument();
  });
});
