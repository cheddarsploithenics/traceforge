import type { Project, Scan } from "../api/client";
import { formatDateTime, formatDuration, formatShort } from "../lib/format";
import { StatusBadge } from "./StatusBadge";

interface ScanTableProps {
  scans: Scan[];
  projects: Project[];
  onOpen: (scanId: number) => void;
  selectedId?: number | null;
  /** Fewer columns, for dashboard summaries. */
  compact?: boolean;
  label?: string;
}

export function ScanTable({
  scans,
  projects,
  onOpen,
  selectedId = null,
  compact = false,
  label = "Scan history",
}: ScanTableProps) {
  const projectName = (id: number | null) => projects.find((p) => p.id === id)?.name ?? `#${id}`;

  return (
    <div className="table-scroll">
      <table className="table table--interactive" aria-label={label}>
        <thead>
          <tr>
            <th scope="col">Status</th>
            <th scope="col">Scan</th>
            {!compact && <th scope="col">Project</th>}
            <th scope="col">Targets</th>
            <th scope="col" className="num">
              Open ports
            </th>
            {!compact && (
              <th scope="col" className="num">
                Hosts up
              </th>
            )}
            <th scope="col">Created</th>
            {!compact && <th scope="col">Duration</th>}
          </tr>
        </thead>
        <tbody>
          {scans.map((scan) => (
            <tr
              key={scan.id}
              className={scan.id === selectedId ? "is-selected" : undefined}
              aria-selected={scan.id === selectedId || undefined}
              onClick={() => onOpen(scan.id)}
            >
              <td>
                <StatusBadge status={scan.status} />
              </td>
              <td>
                <button type="button" className="link mono" aria-label={`Open scan ${scan.id}`}>
                  #{scan.id}
                </button>
              </td>
              {!compact && <td className="nowrap">{projectName(scan.project_id)}</td>}
              <td className="mono truncate" title={scan.targets.join(", ")}>
                {scan.targets.join(", ")}
              </td>
              <td className="num">{scan.open_ports}</td>
              {!compact && <td className="num">{scan.hosts_up}</td>}
              <td className="nowrap" title={formatDateTime(scan.created_at)}>
                {formatShort(scan.created_at)}
              </td>
              {!compact && (
                <td className="nowrap muted">
                  {formatDuration(scan.started_at, scan.finished_at) ?? "—"}
                </td>
              )}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
