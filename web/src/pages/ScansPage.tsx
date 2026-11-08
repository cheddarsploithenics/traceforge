import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import {
  ACTIVE_STATUSES,
  type Project,
  type Scan,
  type ScanResults,
  type ScanStatus,
  UnauthorizedError,
  cancelScan,
  evidenceUrl,
  getScanResults,
} from "../api/client";
import { Icon } from "../components/Icon";
import { ScanDetail } from "../components/ScanDetail";
import { ScanForm } from "../components/ScanForm";
import { ScanTable } from "../components/ScanTable";
import { StatusBadge } from "../components/StatusBadge";
import { EmptyState, PageHeader, Panel, SidePanel } from "../components/ui";
import { useScans } from "../hooks/useScans";
import { errorMessage } from "../lib/format";

type Filter = "all" | "active" | Exclude<ScanStatus, "queued" | "running">;
const FILTERS: { value: Filter; label: string }[] = [
  { value: "all", label: "All" },
  { value: "active", label: "Active" },
  { value: "completed", label: "Completed" },
  { value: "failed", label: "Failed" },
  { value: "cancelled", label: "Cancelled" },
];

const matches = (scan: Scan, filter: Filter) =>
  filter === "all" ||
  (filter === "active" ? ACTIVE_STATUSES.has(scan.status) : scan.status === filter);

type Detail =
  | { kind: "none" }
  | { kind: "new" }
  | { kind: "scan"; id: number; results: ScanResults | null; error: string | null };

interface ScansPageProps {
  projects: Project[];
  /** Scan to open on arrival (e.g. clicked on the overview). */
  initialScanId: number | null;
  onUnauthorized: () => void;
}

export function ScansPage({ projects, initialScanId, onUnauthorized }: ScansPageProps) {
  const [detail, setDetail] = useState<Detail>(
    initialScanId === null ? { kind: "none" } : { kind: "scan", id: initialScanId, results: null, error: null },
  );
  const [filter, setFilter] = useState<Filter>("all");
  const [projectFilter, setProjectFilter] = useState<number | "">("");
  const [query, setQuery] = useState("");
  const [notice, setNotice] = useState<string | null>(null);
  const openId = detail.kind === "scan" ? detail.id : null;
  const openRef = useRef(openId);
  openRef.current = openId;

  const loadResults = useCallback(
    (scanId: number) => {
      getScanResults(scanId)
        .then((results) => {
          if (openRef.current === scanId) setDetail({ kind: "scan", id: scanId, results, error: null });
        })
        .catch((err: unknown) => {
          if (err instanceof UnauthorizedError) return onUnauthorized();
          if (openRef.current === scanId)
            setDetail({ kind: "scan", id: scanId, results: null, error: errorMessage(err) });
        });
    },
    [onUnauthorized],
  );

  // Keep the open scan's details in step with list refreshes (polling included).
  const { state, refresh } = useScans(onUnauthorized, {
    onRefreshed: (scans) => {
      const id = openRef.current;
      if (id !== null && scans.some((s) => s.id === id)) loadResults(id);
    },
  });

  useEffect(() => {
    if (initialScanId !== null) loadResults(initialScanId);
  }, [initialScanId, loadResults]);

  const open = (scanId: number, message: string | null = null) => {
    setNotice(message);
    setDetail({ kind: "scan", id: scanId, results: null, error: null });
    loadResults(scanId);
  };
  const close = useCallback(() => setDetail({ kind: "none" }), []);

  const cancel = (scanId: number) => {
    cancelScan(scanId)
      .then((scan) => setNotice(`Scan #${scan.id} ${scan.status}.`))
      .catch((err: unknown) => {
        if (err instanceof UnauthorizedError) onUnauthorized();
        else setNotice(errorMessage(err));
      })
      .finally(refresh);
  };

  const scans = state.kind === "ready" ? state.scans : [];
  const counts = useMemo(
    () => Object.fromEntries(FILTERS.map((f) => [f.value, scans.filter((s) => matches(s, f.value)).length])),
    [scans],
  );
  const needle = query.trim().toLowerCase();
  const visible = scans.filter(
    (s) =>
      matches(s, filter) &&
      (projectFilter === "" || s.project_id === projectFilter) &&
      (!needle ||
        `#${s.id} ${s.targets.join(" ")} ${s.scan_addresses.join(" ")}`.toLowerCase().includes(needle)),
  );

  const openScan = detail.kind === "scan" ? scans.find((s) => s.id === detail.id) : undefined;
  const openStatus = detail.kind === "scan" ? (detail.results?.scan.status ?? openScan?.status) : undefined;
  const projectName = (id: number | null) => projects.find((p) => p.id === id)?.name ?? `#${id}`;

  return (
    <>
      <PageHeader
        title="Scans"
        description="Nmap TCP connect scans of authorized targets."
        actions={
          <>
            <button type="button" className="btn btn--secondary" onClick={refresh}>
              <Icon name="refresh" size={14} />
              Refresh
            </button>
            <button
              type="button"
              className="btn btn--primary"
              onClick={() => setDetail({ kind: "new" })}
              disabled={projects.length === 0}
            >
              <Icon name="plus" size={14} />
              New scan
            </button>
          </>
        }
      />

      {projects.length === 0 && (
        <div className="callout callout--warning">
          <p className="callout__title">No projects yet</p>
          <p>
            Scans need a project with an authorized scope. Create one with{" "}
            <code>traceforge project create NAME --authorization-ref REF</code> and add targets
            with <code>traceforge scope add ID include 10.0.0.0/24</code>.
          </p>
        </div>
      )}

      {notice && (
        <p role="status" className="callout callout--neutral">
          {notice}
        </p>
      )}

      <div className={detail.kind === "none" ? "split" : "split split--open"}>
        <Panel flush className="split__main">
          <div className="toolbar">
            <div className="segmented" role="group" aria-label="Filter by status">
              {FILTERS.map((f) => (
                <button
                  key={f.value}
                  type="button"
                  className="segmented__item"
                  aria-pressed={filter === f.value}
                  onClick={() => setFilter(f.value)}
                >
                  {f.label}
                  <span className="segmented__count">{counts[f.value]}</span>
                </button>
              ))}
            </div>
            <div className="toolbar__right">
              <select
                className="input input--sm"
                aria-label="Filter by project"
                value={projectFilter}
                onChange={(e) => setProjectFilter(e.target.value ? Number(e.target.value) : "")}
              >
                <option value="">All projects</option>
                {projects.map((p) => (
                  <option key={p.id} value={p.id}>
                    {p.name}
                  </option>
                ))}
              </select>
              <input
                type="search"
                className="input input--sm"
                placeholder="Search targets or #id"
                aria-label="Search scans"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
              />
            </div>
          </div>

          {state.kind === "loading" && (
            <p role="status" className="panel__note">
              Loading scans…
            </p>
          )}
          {state.kind === "error" && (
            <p role="alert" className="panel__note callout--critical">
              {state.message}
            </p>
          )}
          {state.kind === "ready" && scans.length === 0 && (
            <EmptyState title="No scans yet">
              <p>Use New scan to scan targets from a project&apos;s authorized scope.</p>
            </EmptyState>
          )}
          {state.kind === "ready" && scans.length > 0 && visible.length === 0 && (
            <EmptyState title="No scans match these filters" />
          )}
          {visible.length > 0 && (
            <ScanTable
              scans={visible}
              projects={projects}
              selectedId={openId}
              compact={detail.kind !== "none"}
              onOpen={(id) => open(id)}
            />
          )}
        </Panel>

        {detail.kind === "new" && (
          <SidePanel title="New scan" onClose={close}>
            <ScanForm
              projects={projects}
              onUnauthorized={onUnauthorized}
              onLaunched={(launched) => {
                refresh();
                open(
                  launched.scan_id,
                  `Queued scan #${launched.scan_id} of ${launched.scan_addresses.join(", ")}`,
                );
              }}
            />
          </SidePanel>
        )}

        {detail.kind === "scan" && (
          <SidePanel
            title={`Scan #${detail.id}`}
            meta={openStatus && <StatusBadge status={openStatus} />}
            onClose={close}
            actions={
              <>
                {openStatus && ACTIVE_STATUSES.has(openStatus) && (
                  <button type="button" className="btn btn--danger btn--sm" onClick={() => cancel(detail.id)}>
                    <Icon name="stop" size={14} />
                    Cancel scan
                  </button>
                )}
                {detail.results?.scan.evidence && (
                  <a className="btn btn--secondary btn--sm" href={evidenceUrl(detail.id)} download>
                    <Icon name="download" size={14} />
                    Evidence XML
                  </a>
                )}
              </>
            }
          >
            {detail.error && (
              <p role="alert" className="callout callout--critical">
                {detail.error}
              </p>
            )}
            {!detail.error && !detail.results && <p role="status">Loading results…</p>}
            {detail.results && (
              <ScanDetail results={detail.results} projectName={projectName(detail.results.scan.project_id)} />
            )}
          </SidePanel>
        )}
      </div>
    </>
  );
}
