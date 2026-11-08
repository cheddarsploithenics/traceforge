import type { ScanHost, ScanPort, ScanResults } from "../api/client";
import { formatBytes, formatDateTime, formatDuration } from "../lib/format";
import { PortState } from "./StatusBadge";
import { EmptyState, Field } from "./ui";

function describeOptions(options: Record<string, unknown>): string {
  const parts: string[] = [];
  if (typeof options.ports === "string") parts.push(`ports ${options.ports}`);
  else if (typeof options.top_ports === "number") parts.push(`top ${options.top_ports} ports`);
  else parts.push("top 1,000 ports");
  if (options.service_detection) parts.push("-sV");
  if (typeof options.timing === "number") parts.push(`T${options.timing}`);
  if (options.skip_host_discovery) parts.push("-Pn");
  return parts.join(" · ");
}

const version = (p: ScanPort) =>
  [p.service_product, p.service_version, p.service_extrainfo].filter(Boolean).join(" ");

/** Everything known about one scan; target-controlled text is rendered as plain text. */
export function ScanDetail({ results, projectName }: { results: ScanResults; projectName: string }) {
  const { scan, hosts } = results;
  const rows = hosts.flatMap((host): { host: ScanHost; port: ScanPort | null }[] =>
    host.ports.length ? host.ports.map((port) => ({ host, port })) : [{ host, port: null }],
  );
  const duration = formatDuration(scan.started_at, scan.finished_at);

  return (
    <>
      {scan.error && (
        <div className={`callout ${scan.status === "failed" ? "callout--critical" : "callout--neutral"}`}>
          <p className="callout__title">{scan.status === "failed" ? "Scan failed" : "Note"}</p>
          <p className="mono pre">{scan.error}</p>
        </div>
      )}

      <section className="section" aria-label="Summary">
        <dl className="kv">
          <Field label="Project">{projectName}</Field>
          <Field label="Requested by">{scan.actor ?? "—"}</Field>
          <Field label="Targets">
            <span className="mono">{scan.targets.join(", ")}</span>
          </Field>
          <Field label="Scanned">
            <span className="mono">{scan.scan_addresses.join(", ") || "—"}</span>
          </Field>
          <Field label="Options">{describeOptions(scan.options)}</Field>
          <Field label="Created">{formatDateTime(scan.created_at)}</Field>
          <Field label="Started">{formatDateTime(scan.started_at)}</Field>
          <Field label="Finished">
            {formatDateTime(scan.finished_at)}
            {duration && <span className="muted"> · {duration}</span>}
          </Field>
          {scan.exit_code !== null && <Field label="Exit code">{scan.exit_code}</Field>}
          {scan.tool_version && <Field label="Nmap">{scan.tool_version}</Field>}
        </dl>
      </section>

      <section className="section">
        <h3 className="section__title">
          Services
          <span className="section__count">
            {scan.hosts_up} host(s) up · {scan.open_ports} open
          </span>
        </h3>
        {rows.length === 0 ? (
          <EmptyState
            title={
              scan.status === "completed"
                ? "No hosts responded"
                : scan.status === "queued" || scan.status === "running"
                  ? "No results yet"
                  : "No results"
            }
          />
        ) : (
          <div className="table-scroll table-scroll--framed">
            <table className="table table--dense" aria-label="Ports and services">
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
                        <div className="muted small">{host.hostnames.join(", ")}</div>
                      )}
                    </td>
                    <td className="mono nowrap">{port ? `${port.port}/${port.protocol}` : "—"}</td>
                    <td>
                      <PortState state={port ? port.state : host.state} />
                    </td>
                    <td>{port?.service_name ?? ""}</td>
                    <td>{port ? version(port) : ""}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section className="section">
        <h3 className="section__title">Command</h3>
        <pre className="code">{scan.command.join(" ") || "—"}</pre>
      </section>

      {scan.evidence && (
        <section className="section">
          <h3 className="section__title">Evidence</h3>
          <dl className="kv">
            <Field label="File">
              <span className="mono">{scan.evidence.file}</span>
            </Field>
            <Field label="Size">{formatBytes(scan.evidence.size_bytes)}</Field>
            <Field label="SHA-256">
              <span className="mono break">{scan.evidence.sha256}</span>
            </Field>
          </dl>
        </section>
      )}
    </>
  );
}
