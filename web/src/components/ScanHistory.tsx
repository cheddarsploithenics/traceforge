import { ACTIVE_STATUSES, type Project, type Scan } from "../api/client";

interface ScanHistoryProps {
  scans: Scan[];
  projects: Project[];
  selectedId: number | null;
  onSelect: (scanId: number) => void;
  onCancel: (scanId: number) => void;
}

export function formatTime(iso: string | null): string {
  return iso ? new Date(iso).toLocaleString([], { dateStyle: "short", timeStyle: "medium" }) : "—";
}

export function StatusBadge({ status }: { status: Scan["status"] }) {
  return <span className={`badge badge--${status}`}>{status}</span>;
}

export function ScanHistory({ scans, projects, selectedId, onSelect, onCancel }: ScanHistoryProps) {
  const projectName = (id: number | null) => projects.find((p) => p.id === id)?.name ?? `#${id}`;

  if (scans.length === 0) {
    return <p>No scans yet. Start one above.</p>;
  }
  return (
    <div className="table-wrap">
      <table className="table" aria-label="Scan history">
        <thead>
          <tr>
            <th scope="col">ID</th>
            <th scope="col">Status</th>
            <th scope="col">Project</th>
            <th scope="col">Targets</th>
            <th scope="col">Open ports</th>
            <th scope="col">Created</th>
            <th scope="col">Actions</th>
          </tr>
        </thead>
        <tbody>
          {scans.map((scan) => (
            <tr key={scan.id} className={scan.id === selectedId ? "is-selected" : undefined}>
              <td>#{scan.id}</td>
              <td>
                <StatusBadge status={scan.status} />
              </td>
              <td>{projectName(scan.project_id)}</td>
              <td className="mono">{scan.targets.join(", ")}</td>
              <td>{scan.open_ports}</td>
              <td>{formatTime(scan.created_at)}</td>
              <td className="actions">
                <button
                  type="button"
                  aria-label={`Results for scan ${scan.id}`}
                  onClick={() => onSelect(scan.id)}
                >
                  Results
                </button>
                {ACTIVE_STATUSES.has(scan.status) && (
                  <button
                    type="button"
                    className="danger"
                    aria-label={`Cancel scan ${scan.id}`}
                    onClick={() => onCancel(scan.id)}
                  >
                    Cancel
                  </button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
