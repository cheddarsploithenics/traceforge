import { useState } from "react";

import {
  type AssetStats,
  type Project,
  type SessionInfo,
  UnauthorizedError,
  getAssetStats,
} from "../api/client";
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
  onShowAssets: () => void;
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
  onShowAssets,
  onShowProjects,
  onUnauthorized,
}: OverviewPageProps) {
  const [assetStats, setAssetStats] = useState<AssetStats | null>(null);
  const { state, refresh } = useScans(onUnauthorized, {
    // Scan completions change the inventory, so refresh its numbers with the list.
    onRefreshed: () => {
      getAssetStats()
        .then(setAssetStats)
        .catch((err: unknown) => {
          if (err instanceof UnauthorizedError) onUnauthorized();
        });
    },
  });
  const scans = state.kind === "ready" ? state.scans : [];
  const running = scans.filter((s) => s.status === "running").length;
  const queued = scans.filter((s) => s.status === "queued").length;
  const completed = scans.filter((s) => s.status === "completed");
  const failed = scans.filter((s) => s.status === "failed").length;
  const loaded = state.kind === "ready";
  const stats = assetStats;

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
          label="Assets"
          value={stats ? formatCount(stats.assets) : "—"}
          caption={stats ? `${stats.assets_with_open_ports} with open ports` : undefined}
        />
        <StatTile
          label="Open ports"
          value={stats ? formatCount(stats.open_ports) : "—"}
          caption={stats ? `${stats.detected_services} service(s) detected by probing` : undefined}
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
            title={`Projects · ${projects.length}`}
            flush
            actions={
              <>
                <button type="button" className="btn btn--ghost btn--sm" onClick={onShowAssets}>
                  Assets
                </button>
                <button type="button" className="btn btn--ghost btn--sm" onClick={onShowProjects}>
                  Manage
                </button>
              </>
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
