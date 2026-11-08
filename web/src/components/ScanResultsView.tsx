import type { ScanHost, ScanPort, ScanResults } from "../api/client";
import { StatusBadge, formatTime } from "./ScanHistory";

export type ResultsState =
  | { kind: "none" }
  | { kind: "loading" }
  | { kind: "ready"; results: ScanResults }
  | { kind: "error"; message: string };

export function ScanResultsView({ state }: { state: ResultsState }) {
  if (state.kind === "none") return null;
  return (
    <section className="card" aria-labelledby="results-title">
      <h2 id="results-title">Scan results</h2>
      {state.kind === "loading" && <p role="status">Loading results…</p>}
      {state.kind === "error" && <p role="alert">{state.message}</p>}
      {state.kind === "ready" && <Results results={state.results} />}
    </section>
  );
}

function Results({ results }: { results: ScanResults }) {
  const { scan, hosts } = results;
  const rows = hosts.flatMap((host): { host: ScanHost; port: ScanPort | null }[] =>
    host.ports.length ? host.ports.map((port) => ({ host, port })) : [{ host, port: null }],
  );
  return (
    <>
      <dl className="details">
        <dt>Scan</dt>
        <dd>
          #{scan.id} {scan.tool} <StatusBadge status={scan.status} />
        </dd>
        <dt>Targets</dt>
        <dd className="mono">{scan.targets.join(", ")}</dd>
        <dt>Scanned</dt>
        <dd className="mono">{scan.scan_addresses.join(", ")}</dd>
        <dt>Started</dt>
        <dd>{formatTime(scan.started_at)}</dd>
        <dt>Finished</dt>
        <dd>{formatTime(scan.finished_at)}</dd>
        {scan.error && (
          <>
            <dt>Error</dt>
            <dd className="status--error">{scan.error}</dd>
          </>
        )}
        {scan.evidence && (
          <>
            <dt>Evidence</dt>
            <dd className="mono">
              {scan.evidence.file}
              <br />
              <span className="muted">sha256 {scan.evidence.sha256}</span>
            </dd>
          </>
        )}
      </dl>

      {rows.length === 0 ? (
        <p className="results-empty">
          {scan.status === "completed" ? "No hosts responded." : "No results yet."}
        </p>
      ) : (
        <div className="table-wrap">
          <table className="table" aria-label="Ports and services">
            <thead>
              <tr>
                <th scope="col">Host</th>
                <th scope="col">Port</th>
                <th scope="col">State</th>
                <th scope="col">Service</th>
                <th scope="col">Version</th>
              </tr>
            </thead>
            <tbody>
              {rows.map(({ host, port }) => (
                <tr key={`${host.asset_id}-${port ? `${port.protocol}-${port.port}` : "host"}`}>
                  <td className="mono">
                    {host.address}
                    {host.hostnames.length > 0 && (
                      <span className="muted"> ({host.hostnames.join(", ")})</span>
                    )}
                  </td>
                  <td className="mono">{port ? `${port.port}/${port.protocol}` : "—"}</td>
                  <td className={port?.state === "open" ? "status--ok" : "muted"}>
                    {port ? port.state : host.state}
                  </td>
                  <td>{port?.service_name ?? ""}</td>
                  <td>
                    {port
                      ? [port.service_product, port.service_version, port.service_extrainfo]
                          .filter(Boolean)
                          .join(" ")
                      : ""}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </>
  );
}
