import type { Project, SessionInfo } from "../api/client";
import { Icon } from "../components/Icon";
import { ScanTable } from "../components/ScanTable";
import { EmptyState, Field, PageHeader, Panel, StatTile } from "../components/ui";
import { useScans } from "../hooks/useScans";
import { formatCount, formatDateTime } from "../lib/format";
import type { HealthState } from "../layout/Topbar";

const RECENT = 8;

interface OverviewPageProps {
  health: HealthState;
  session: SessionInfo;
  projects: Project[];
  projectsError: string | null;
  onRefreshHealth: () => void;
  onOpenScan: (scanId: number) => void;
  onShowScans: () => void;
  onShowProjects: () => void;
  onUnauthorized: () => void;
}

export function OverviewPage({
  health,
  session,
  projects,
  projectsError,
  onRefreshHealth,
  onOpenScan,
  onShowScans,
  onShowProjects,
  onUnauthorized,
}: OverviewPageProps) {
  const { state, refresh } = useScans(onUnauthorized);
  const scans = state.kind === "ready" ? state.scans : [];
  const running = scans.filter((s) => s.status === "running").length;
  const queued = scans.filter((s) => s.status === "queued").length;
  const completed = scans.filter((s) => s.status === "completed");
  const failed = scans.filter((s) => s.status === "failed").length;
  const openPorts = completed.reduce((sum, s) => sum + s.open_ports, 0);
  const scopedProjects = projects.filter((p) => p.scope_rule_count > 0).length;
  const loaded = state.kind === "ready";

  return (
    <>
      <PageHeader
        title="Overview"
        description="Engagement activity and platform status."
        actions={
          <button
            type="button"
            className="btn btn--secondary"
            onClick={() => {
              refresh();
              onRefreshHealth();
            }}
          >
            <Icon name="refresh" size={14} />
            Refresh
          </button>
        }
      />

      <dl className="stats" aria-label="Summary">
        <StatTile
          label="Projects"
          value={formatCount(projects.length)}
          caption={`${scopedProjects} with authorized scope`}
        />
        <StatTile
          label="Scans"
          value={loaded ? formatCount(scans.length) : "—"}
          caption={loaded ? `${completed.length} completed · ${failed} failed` : undefined}
        />
        <StatTile
          label="Active scans"
          value={loaded ? formatCount(running + queued) : "—"}
          caption={loaded ? `${running} running · ${queued} queued` : undefined}
        />
        <StatTile
          label="Open ports found"
          value={loaded ? formatCount(openPorts) : "—"}
          caption={loaded ? `across ${completed.length} completed scans` : undefined}
        />
      </dl>

      <div className="grid grid--overview">
        <Panel
          title="Recent scans"
          flush
          actions={
            <button type="button" className="btn btn--ghost btn--sm" onClick={onShowScans}>
              View all
            </button>
          }
        >
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
              <p>
                Open <strong>Scans</strong> and start one against a target in a project&apos;s
                authorized scope.
              </p>
            </EmptyState>
          )}
          {scans.length > 0 && (
            <ScanTable
              compact
              label="Recent scans"
              scans={scans.slice(0, RECENT)}
              projects={projects}
              onOpen={onOpenScan}
            />
          )}
        </Panel>

        <div className="stack">
          <Panel title="Platform">
            {health.kind === "loading" && <p role="status">Checking backend…</p>}
            {health.kind === "error" && (
              <div role="alert" className="callout callout--critical">
                <p>{health.message}</p>
                <p>
                  Start it with <code>traceforge serve</code>.
                </p>
              </div>
            )}
            {health.kind === "ready" && (
              <dl className="kv">
                <Field label="API">
                  <span className={health.health.status === "ok" ? "text-good" : "text-warning"}>
                    {health.health.status.toUpperCase()}
                  </span>
                </Field>
                <Field label="Version">{health.health.version}</Field>
                <Field label="Database">{health.health.database}</Field>
                <Field label="Session expires">{formatDateTime(session.expires_at)}</Field>
                <Field label="Binding">127.0.0.1 only</Field>
              </dl>
            )}
          </Panel>

          <Panel
            title="Projects"
            flush
            actions={
              <button type="button" className="btn btn--ghost btn--sm" onClick={onShowProjects}>
                Manage
              </button>
            }
          >
            {projectsError && (
              <p role="alert" className="panel__note callout--critical">
                {projectsError}
              </p>
            )}
            {!projectsError && projects.length === 0 && (
              <EmptyState title="No projects yet">
                <p>
                  Create one with{" "}
                  <code>traceforge project create NAME --authorization-ref REF</code>.
                </p>
              </EmptyState>
            )}
            {projects.length > 0 && (
              <ul className="list">
                {projects.slice(0, 6).map((p) => (
                  <li key={p.id} className="list__item">
                    <div>
                      <strong>{p.name}</strong>
                      <div className="muted small">{p.authorization_ref}</div>
                    </div>
                    <span className="muted small nowrap">{p.scope_rule_count} scope rule(s)</span>
                  </li>
                ))}
              </ul>
            )}
          </Panel>
        </div>
      </div>
    </>
  );
}
