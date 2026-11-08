import { type ReactNode, useEffect, useMemo, useState } from "react";

import {
  type ChangeCategory,
  type ComparisonChange,
  type ComparisonSide,
  type Project,
  type Scan,
  type ScanComparison,
  UnauthorizedError,
  compareScans,
} from "../api/client";
import { errorMessage, formatDateTime, formatShort } from "../lib/format";
import { Icon, type IconName } from "./Icon";
import { EmptyState } from "./ui";

export interface ComparePreset {
  projectId: number;
  baseline: number;
  comparison: number;
}

const CATEGORIES: { key: ChangeCategory; label: string; icon: IconName; hint: string }[] = [
  { key: "added", label: "Added", icon: "plusSmall", hint: "confirmed by both scans" },
  { key: "removed", label: "Removed", icon: "minusSmall", hint: "confirmed by both scans" },
  { key: "changed", label: "Changed", icon: "tilde", hint: "confirmed by both scans" },
  {
    key: "inconclusive",
    label: "Inconclusive",
    icon: "question",
    hint: "one scan did not observe it, or the observation is ambiguous",
  },
];

const KIND_LABELS: Record<string, string> = {
  host_appeared: "Host responding",
  host_appeared_unverified: "Host responding, not checked before",
  host_not_observed: "Host not responding",
  host_not_checked: "Host not checked",
  host_incomplete: "Host timed out",
  port_opened: "Port opened",
  port_open_unverified: "Open, not checked before",
  port_closed: "Port closed",
  port_unreachable: "No answer (filtered)",
  port_not_checked: "Not checked",
  service_changed: "Service changed",
  version_changed: "Version changed",
  version_not_reported: "Version not reported",
  service_not_checked: "Service not re-checked",
  service_identified: "Service identified",
};

const scanLabel = (s: Scan) =>
  `#${s.id} · ${formatShort(s.finished_at ?? s.created_at)} · ${s.targets.join(", ")}`;

interface ScanCompareProps {
  projects: Project[];
  scans: Scan[];
  preset: ComparePreset | null;
  onOpenScan: (scanId: number) => void;
  onOpenAsset: (uid: string) => void;
  onUnauthorized: () => void;
}

type ResultState =
  | { kind: "idle" }
  | { kind: "loading" }
  | { kind: "ready"; result: ScanComparison }
  | { kind: "error"; message: string };

export function ScanCompare({
  projects,
  scans,
  preset,
  onOpenScan,
  onOpenAsset,
  onUnauthorized,
}: ScanCompareProps) {
  const [projectId, setProjectId] = useState<number | "">(preset?.projectId ?? projects[0]?.id ?? "");
  const completed = useMemo(
    () => scans.filter((s) => s.status === "completed" && s.project_id === projectId),
    [scans, projectId],
  );
  const [baseline, setBaseline] = useState<number | "">(preset?.baseline ?? "");
  const [comparison, setComparison] = useState<number | "">(preset?.comparison ?? "");
  const [state, setState] = useState<ResultState>({ kind: "idle" });

  // Default to the two most recent completed scans of the chosen project.
  useEffect(() => {
    if (preset && preset.projectId === projectId) return;
    setComparison(completed[0]?.id ?? "");
    setBaseline(completed[1]?.id ?? "");
    setState({ kind: "idle" });
  }, [projectId, completed, preset]);

  const run = (pid: number, a: number, b: number) => {
    setState({ kind: "loading" });
    compareScans(pid, a, b)
      .then((result) => setState({ kind: "ready", result }))
      .catch((err: unknown) => {
        if (err instanceof UnauthorizedError) onUnauthorized();
        else setState({ kind: "error", message: errorMessage(err) });
      });
  };

  useEffect(() => {
    // Run once per preset (e.g. "Compare with previous" from a scan's panel).
    if (preset) run(preset.projectId, preset.baseline, preset.comparison);
  }, [preset]);

  const ready = projectId !== "" && baseline !== "" && comparison !== "" && baseline !== comparison;

  return (
    <div className="stack">
      <form
        className="panel compare-form"
        aria-label="Compare scans"
        onSubmit={(event) => {
          event.preventDefault();
          if (ready) run(projectId as number, baseline as number, comparison as number);
        }}
      >
        <div className="form__field">
          <label className="form__label" htmlFor="compare-project">
            Project
          </label>
          <select
            id="compare-project"
            className="input"
            value={projectId}
            onChange={(e) => setProjectId(e.target.value ? Number(e.target.value) : "")}
          >
            {projects.map((p) => (
              <option key={p.id} value={p.id}>
                {p.name}
              </option>
            ))}
          </select>
        </div>
        <ScanSelect id="compare-baseline" label="Baseline (A)" scans={completed} value={baseline} onChange={setBaseline} />
        <ScanSelect id="compare-comparison" label="Comparison (B)" scans={completed} value={comparison} onChange={setComparison} />
        <div className="compare-form__action">
          <button type="submit" className="btn btn--primary" disabled={!ready || state.kind === "loading"}>
            <Icon name="compare" size={14} />
            Compare
          </button>
        </div>
        {completed.length < 2 && (
          <p className="form__hint compare-form__hint">
            Comparisons need two completed scans of the same project. Failed and cancelled scans
            are excluded: their missing observations would look like changes.
          </p>
        )}
      </form>

      {state.kind === "loading" && <p role="status">Comparing…</p>}
      {state.kind === "error" && (
        <p role="alert" className="callout callout--critical">
          {state.message}
        </p>
      )}
      {state.kind === "ready" && (
        <ComparisonResult result={state.result} onOpenScan={onOpenScan} onOpenAsset={onOpenAsset} />
      )}
    </div>
  );
}

function ScanSelect({
  id,
  label,
  scans,
  value,
  onChange,
}: {
  id: string;
  label: string;
  scans: Scan[];
  value: number | "";
  onChange: (value: number | "") => void;
}) {
  return (
    <div className="form__field">
      <label className="form__label" htmlFor={id}>
        {label}
      </label>
      <select
        id={id}
        className="input"
        value={value}
        onChange={(e) => onChange(e.target.value ? Number(e.target.value) : "")}
      >
        <option value="">Select a completed scan</option>
        {scans.map((s) => (
          <option key={s.id} value={s.id}>
            {scanLabel(s)}
          </option>
        ))}
      </select>
    </div>
  );
}

function ComparisonResult({
  result,
  onOpenScan,
  onOpenAsset,
}: {
  result: ScanComparison;
  onOpenScan: (scanId: number) => void;
  onOpenAsset: (uid: string) => void;
}) {
  const { summary } = result;
  return (
    <>
      <section className="panel" aria-label="Comparison summary">
        <div className="compare-summary">
          {CATEGORIES.map((c) => (
            <div key={c.key} className={`compare-count compare-count--${c.key}`} title={c.hint}>
              <span className="compare-count__icon" aria-hidden="true">
                <Icon name={c.icon} size={14} strokeWidth={2.4} />
              </span>
              <span className="compare-count__value">{summary[c.key]}</span>
              <span className="compare-count__label">{c.label}</span>
            </div>
          ))}
          <div className="compare-count compare-count--unchanged">
            <span className="compare-count__value">{summary.unchanged_open_ports}</span>
            <span className="compare-count__label">open ports unchanged</span>
          </div>
        </div>
        <CoverageTable baseline={result.baseline} comparison={result.comparison} onOpenScan={onOpenScan} />
        {result.notes.length > 0 && (
          <ul className="compare-notes">
            {result.notes.map((note) => (
              <li key={note}>{note}</li>
            ))}
          </ul>
        )}
      </section>

      {result.changes.length === 0 ? (
        <section className="panel">
          <EmptyState title="No differences">
            <p>Everything both scans observed is the same.</p>
          </EmptyState>
        </section>
      ) : (
        CATEGORIES.map((c) => {
          const items = result.changes.filter((change) => change.category === c.key);
          if (items.length === 0) return null;
          return (
            <ChangeSection key={c.key} category={c} items={items} onOpenAsset={onOpenAsset} />
          );
        })
      )}
    </>
  );
}

function CoverageTable({
  baseline,
  comparison,
  onOpenScan,
}: {
  baseline: ComparisonSide;
  comparison: ComparisonSide;
  onOpenScan: (scanId: number) => void;
}) {
  const ports = (s: ComparisonSide) =>
    s.ports_scanned
      ? Object.entries(s.ports_scanned)
          .map(([proto, spec]) => `${proto} ${spec}`)
          .join(", ")
      : "unknown";
  const rows: [string, (s: ComparisonSide) => ReactNode][] = [
    [
      "Scan",
      (s) => (
        <button type="button" className="link mono" onClick={() => onOpenScan(s.scan_id)}>
          #{s.scan_id}
        </button>
      ),
    ],
    ["Finished", (s) => formatDateTime(s.finished_at)],
    ["Ports scanned", (s) => <span className="mono">{ports(s)}</span>],
    ["Host discovery", (s) => (s.host_discovery ? "on" : "off (-Pn)")],
    ["Service detection", (s) => (s.service_detection ? "on (-sV)" : "off")],
    ["Hosts responding", (s) => s.hosts_responsive],
  ];
  return (
    <div className="table-scroll">
      <table className="table table--dense compare-coverage" aria-label="Scan coverage">
        <thead>
          <tr>
            <th scope="col">Coverage</th>
            <th scope="col">Baseline (A)</th>
            <th scope="col">Comparison (B)</th>
          </tr>
        </thead>
        <tbody>
          {rows.map(([label, value]) => (
            <tr key={label}>
              <th scope="row">{label}</th>
              <td>{value(baseline)}</td>
              <td>{value(comparison)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function describe(side: Record<string, unknown> | null): string {
  if (!side) return "—";
  if (Array.isArray(side.open_ports)) {
    const ports = side.open_ports as { port: number; service_name: string | null }[];
    return ports.length
      ? `${ports.length} open: ${ports.map((p) => `${p.port}${p.service_name ? ` ${p.service_name}` : ""}`).join(", ")}`
      : "no open ports";
  }
  // A service name on a port that is not open is only a port-number label or a
  // stale identification: show the state alone.
  if (side.state !== "open") return typeof side.state === "string" ? side.state : "—";
  const parts = [side.state, side.service_name, side.service_product, side.service_version]
    .filter((v) => typeof v === "string" && v)
    .join(" ");
  const label = side.identification === "port-label" ? " (port label)" : "";
  return parts ? parts + label : "—";
}

function ChangeSection({
  category,
  items,
  onOpenAsset,
}: {
  category: (typeof CATEGORIES)[number];
  items: ComparisonChange[];
  onOpenAsset: (uid: string) => void;
}) {
  return (
    <section className={`panel change-section change-section--${category.key}`} aria-label={category.label}>
      <header className="panel__header">
        <h2 className="change-section__title">
          <span className="compare-count__icon" aria-hidden="true">
            <Icon name={category.icon} size={14} strokeWidth={2.4} />
          </span>
          {category.label}
          <span className="muted"> · {items.length}</span>
        </h2>
        <span className="muted small">{category.hint}</span>
      </header>
      <div className="table-scroll">
        <table className="table table--dense" aria-label={`${category.label} changes`}>
          <thead>
            <tr>
              <th scope="col">Host</th>
              <th scope="col">Port</th>
              <th scope="col">Change</th>
              <th scope="col">Before (A)</th>
              <th scope="col">After (B)</th>
              <th scope="col">Why</th>
            </tr>
          </thead>
          <tbody>
            {items.map((c) => (
              <tr key={`${c.kind}-${c.address}-${c.protocol}-${c.port}`}>
                <td className="nowrap">
                  {c.asset_uid ? (
                    <button type="button" className="link mono" onClick={() => onOpenAsset(c.asset_uid!)}>
                      {c.address}
                    </button>
                  ) : (
                    <span className="mono">{c.address}</span>
                  )}
                  {c.hostnames.length > 0 && <div className="muted small">{c.hostnames.join(", ")}</div>}
                </td>
                <td className="mono nowrap">{c.port !== null ? `${c.port}/${c.protocol}` : "—"}</td>
                <td className="nowrap">{KIND_LABELS[c.kind] ?? c.kind}</td>
                <td>{describe(c.before)}</td>
                <td>{describe(c.after)}</td>
                <td className="muted">{c.detail}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
