import { useCallback, useEffect, useRef, useState } from "react";

import {
  type AssetDetail,
  type AssetObservation,
  type AssetSummary,
  type EvidenceVerification,
  type Project,
  UnauthorizedError,
  evidenceUrl,
  getAsset,
  listAssets,
  verifyEvidence,
} from "../api/client";
import { Icon } from "../components/Icon";
import { IdentTag } from "../components/IdentTag";
import { PortState } from "../components/StatusBadge";
import { EmptyState, Field, PageHeader, Panel, SidePanel } from "../components/ui";
import { errorMessage, formatDateTime, formatShort } from "../lib/format";

const SEARCH_DELAY_MS = 250;

type ListState =
  | { kind: "loading" }
  | { kind: "ready"; assets: AssetSummary[] }
  | { kind: "error"; message: string };

type Detail =
  | { kind: "none" }
  | { kind: "asset"; uid: string; asset: AssetDetail | null; error: string | null };

interface AssetsPageProps {
  projects: Project[];
  /** Asset to open on arrival (e.g. from a scan comparison). */
  initialUid: string | null;
  onOpenScan: (scanId: number) => void;
  onUnauthorized: () => void;
}

export function AssetsPage({ projects, initialUid, onOpenScan, onUnauthorized }: AssetsPageProps) {
  const [list, setList] = useState<ListState>({ kind: "loading" });
  const [projectFilter, setProjectFilter] = useState<number | "">("");
  const [query, setQuery] = useState("");
  const [showUnconfirmed, setShowUnconfirmed] = useState(false);
  const [detail, setDetail] = useState<Detail>(
    initialUid ? { kind: "asset", uid: initialUid, asset: null, error: null } : { kind: "none" },
  );
  const openUid = detail.kind === "asset" ? detail.uid : null;
  const openRef = useRef(openUid);
  openRef.current = openUid;

  const fail = useCallback(
    (err: unknown, other: (message: string) => void) => {
      if (err instanceof UnauthorizedError) onUnauthorized();
      else other(errorMessage(err));
    },
    [onUnauthorized],
  );

  // Reload the list when the filters change (search is debounced).
  useEffect(() => {
    const controller = new AbortController();
    const timer = window.setTimeout(() => {
      listAssets(
        {
          projectId: projectFilter === "" ? undefined : projectFilter,
          query: query.trim() || undefined,
          includeUnconfirmed: showUnconfirmed,
        },
        controller.signal,
      )
        .then((assets) => setList({ kind: "ready", assets }))
        .catch((err: unknown) => {
          if (!controller.signal.aborted) fail(err, (message) => setList({ kind: "error", message }));
        });
    }, query ? SEARCH_DELAY_MS : 0);
    return () => {
      window.clearTimeout(timer);
      controller.abort();
    };
  }, [projectFilter, query, showUnconfirmed, fail]);

  const load = useCallback(
    (uid: string) => {
      getAsset(uid)
        .then((asset) => {
          if (openRef.current === uid) setDetail({ kind: "asset", uid, asset, error: null });
        })
        .catch((err: unknown) =>
          fail(err, (message) => {
            if (openRef.current === uid) setDetail({ kind: "asset", uid, asset: null, error: message });
          }),
        );
    },
    [fail],
  );

  useEffect(() => {
    if (initialUid) load(initialUid);
  }, [initialUid, load]);

  const open = (uid: string) => {
    if (openUid === uid) {
      setDetail({ kind: "none" });
      return;
    }
    setDetail({ kind: "asset", uid, asset: null, error: null });
    load(uid);
  };
  const close = useCallback(() => setDetail({ kind: "none" }), []);
  const compact = detail.kind !== "none";
  const assets = list.kind === "ready" ? list.assets : [];
  const filtered = projectFilter !== "" || query.trim() !== "";

  return (
    <>
      <PageHeader
        title="Assets"
        description="Hosts found by completed scans, with the evidence behind every observation."
      />
      <div className={compact ? "split split--open" : "split"}>
        <Panel flush className="split__main">
          <div className="toolbar">
            <div className="toolbar__right toolbar__left">
              <input
                type="search"
                className="input input--sm input--search"
                placeholder="Address, hostname, service, port…"
                aria-label="Search assets"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
              />
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
            </div>
            <label className="check check--sm">
              <input
                type="checkbox"
                checked={showUnconfirmed}
                onChange={(e) => setShowUnconfirmed(e.target.checked)}
              />
              <span>Include hosts that never answered</span>
            </label>
          </div>

          {list.kind === "loading" && (
            <p role="status" className="panel__note">
              Loading assets…
            </p>
          )}
          {list.kind === "error" && (
            <p role="alert" className="panel__note callout--critical">
              {list.message}
            </p>
          )}
          {list.kind === "ready" && assets.length === 0 && (
            <EmptyState title={filtered ? "No assets match these filters" : "No assets yet"}>
              {!filtered && <p>Assets appear here when a completed scan finds a responding host.</p>}
            </EmptyState>
          )}
          {assets.length > 0 && (
            <div className="table-scroll">
              <table className="table table--interactive" aria-label="Asset inventory">
                <thead>
                  <tr>
                    <th scope="col">Asset</th>
                    {!compact && <th scope="col">Project</th>}
                    <th scope="col" className="num">
                      Open ports
                    </th>
                    <th scope="col">Services</th>
                    {!compact && <th scope="col">First seen</th>}
                    <th scope="col">Last seen</th>
                  </tr>
                </thead>
                <tbody>
                  {assets.map((a) => (
                    <tr
                      key={a.uid}
                      className={a.uid === openUid ? "is-selected" : undefined}
                      aria-selected={a.uid === openUid || undefined}
                      onClick={() => open(a.uid)}
                    >
                      <td>
                        <button
                          type="button"
                          className="link mono"
                          aria-expanded={a.uid === openUid}
                          aria-label={`Asset ${a.address}`}
                        >
                          {a.address}
                        </button>
                        {a.hostnames.length > 0 && (
                          <div className="muted small">{a.hostnames.join(", ")}</div>
                        )}
                        {!a.confirmed && <div className="muted small">never answered (-Pn)</div>}
                      </td>
                      {!compact && <td className="nowrap">{a.project_name}</td>}
                      <td className="num">{a.open_ports}</td>
                      <td>
                        <ServiceList asset={a} />
                      </td>
                      {!compact && (
                        <td className="nowrap" title={formatDateTime(a.first_seen)}>
                          {formatShort(a.first_seen)}
                        </td>
                      )}
                      <td className="nowrap" title={formatDateTime(a.last_seen)}>
                        {formatShort(a.last_seen)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Panel>

        {detail.kind === "asset" && (
          <SidePanel
            title={detail.asset?.address ?? "Asset"}
            meta={detail.asset && <span className="muted mono small">{detail.asset.uid}</span>}
            onClose={close}
          >
            {detail.error && (
              <p role="alert" className="callout callout--critical">
                {detail.error}
              </p>
            )}
            {!detail.error && !detail.asset && <p role="status">Loading asset…</p>}
            {detail.asset && <AssetDetailView asset={detail.asset} onOpenScan={onOpenScan} />}
          </SidePanel>
        )}
      </div>
    </>
  );
}

function ServiceList({ asset }: { asset: AssetSummary }) {
  if (asset.services.length === 0) return <span className="muted">—</span>;
  const shown = asset.services.slice(0, 4);
  return (
    <span className="services">
      {shown.map((s) => (
        <span
          key={`${s.protocol}-${s.port}`}
          className={s.identification === "detected" ? "service service--detected" : "service"}
          title={
            s.identification === "detected"
              ? "detected by probing"
              : s.service_name
                ? "conventional label for this port"
                : "not identified"
          }
        >
          <span className="mono">{s.port}</span> {s.service_name ?? "?"}
        </span>
      ))}
      {asset.services.length > shown.length && (
        <span className="muted small">+{asset.services.length - shown.length}</span>
      )}
    </span>
  );
}

function ScanLink({ scanId, onOpenScan }: { scanId: number | null; onOpenScan: (id: number) => void }) {
  if (scanId === null) return <span className="muted">—</span>;
  return (
    <button type="button" className="link mono" onClick={() => onOpenScan(scanId)}>
      #{scanId}
    </button>
  );
}

function AssetDetailView({
  asset,
  onOpenScan,
}: {
  asset: AssetDetail;
  onOpenScan: (scanId: number) => void;
}) {
  return (
    <>
      <section className="section" aria-label="Summary">
        <dl className="kv">
          <Field label="Project">{asset.project_name}</Field>
          <Field label="Hostnames">{asset.hostnames.join(", ") || "—"}</Field>
          <Field label="First seen">{formatDateTime(asset.first_seen)}</Field>
          <Field label="Last seen">{formatDateTime(asset.last_seen)}</Field>
          <Field label="Latest scan">
            <ScanLink scanId={asset.last_scan_id} onOpenScan={onOpenScan} />
          </Field>
        </dl>
      </section>

      <section className="section">
        <h3 className="section__title">
          Ports
          <span className="section__count">{asset.open_ports} open now</span>
        </h3>
        {asset.ports.length === 0 ? (
          <EmptyState title="No open ports observed" />
        ) : (
          <div className="table-scroll table-scroll--framed">
            <table className="table table--dense" aria-label="Asset ports">
              <thead>
                <tr>
                  <th scope="col">Port</th>
                  <th scope="col">State</th>
                  <th scope="col">Service</th>
                  <th scope="col">Last checked</th>
                </tr>
              </thead>
              <tbody>
                {asset.ports.map((p) => {
                  const version = [p.service_product, p.service_version].filter(Boolean).join(" ");
                  const current = p.state === "open";
                  return (
                    <tr key={`${p.protocol}-${p.port}`}>
                      <td className="mono nowrap">
                        {p.port}/{p.protocol}
                      </td>
                      <td>
                        <PortState state={p.state} />
                      </td>
                      <td className={current ? undefined : "muted"}>
                        {!current && p.service_name && <span className="small">last seen as </span>}
                        {p.service_name ?? ""} <IdentTag identification={p.identification} />
                        {version && <div className="small muted">{version}</div>}
                      </td>
                      <td className="nowrap">
                        <span title={formatDateTime(p.last_seen)}>{formatShort(p.last_seen)}</span>
                        <div className="small">
                          scan <ScanLink scanId={p.state_scan_id} onOpenScan={onOpenScan} />
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
        <p className="form__hint section__footnote">
          An open port is an observation, not a finding. “Port label” means the name is only the
          usual service for that port number.
        </p>
      </section>

      <section className="section">
        <h3 className="section__title">
          Observations
          <span className="section__count">{asset.observations.length} scan(s), newest first</span>
        </h3>
        <ol className="observations">
          {asset.observations.map((o) => (
            <ObservationCard key={o.scan_id} observation={o} onOpenScan={onOpenScan} />
          ))}
        </ol>
      </section>
    </>
  );
}

function configSummary(o: AssetObservation): string {
  const config = o.provenance.configuration;
  const ports = config.ports_scanned
    ? Object.entries(config.ports_scanned)
        .map(([proto, spec]) => `${proto} ${spec}`)
        .join(", ")
    : "ports scanned unknown";
  return [ports, config.service_detection ? "-sV" : null, config.host_discovery ? null : "-Pn"]
    .filter(Boolean)
    .join(" · ");
}

function ObservationCard({
  observation: o,
  onOpenScan,
}: {
  observation: AssetObservation;
  onOpenScan: (scanId: number) => void;
}) {
  const [check, setCheck] = useState<
    { kind: "idle" } | { kind: "checking" } | { kind: "done"; result: EvidenceVerification } | { kind: "error"; message: string }
  >({ kind: "idle" });
  const prov = o.provenance;
  const open = o.ports.filter((p) => p.state === "open").length;

  const verify = () => {
    setCheck({ kind: "checking" });
    verifyEvidence(o.scan_id)
      .then((result) => setCheck({ kind: "done", result }))
      .catch((err: unknown) => setCheck({ kind: "error", message: errorMessage(err) }));
  };

  return (
    <li className="observation">
      <div className="observation__head">
        <span>
          Scan <ScanLink scanId={o.scan_id} onOpenScan={onOpenScan} />
        </span>
        <span className="muted small">{formatDateTime(o.observed_at)}</span>
      </div>
      <dl className="kv kv--compact">
        <Field label="Tool">
          {prov.tool} {prov.tool_version}
        </Field>
        <Field label="Target">
          <span className="mono">{prov.requested_targets.join(", ") || "—"}</span>
          {" → "}
          <span className="mono">{prov.scanned_address}</span>
        </Field>
        <Field label="Config">{configSummary(o)}</Field>
        <Field label="Result">
          {o.timed_out
            ? "host timed out (incomplete)"
            : o.responsive
              ? `${open} open port(s) reported`
              : "no answer"}
        </Field>
        {prov.evidence && (
          <Field label="Evidence">
            <span className="mono break small">{prov.evidence.file}</span>
            <div className="mono break small muted">sha256 {prov.evidence.sha256}</div>
            <div className="observation__actions">
              <a className="btn btn--secondary btn--sm" href={evidenceUrl(o.scan_id)} download>
                <Icon name="download" size={13} />
                Download
              </a>
              <button
                type="button"
                className="btn btn--ghost btn--sm"
                onClick={verify}
                disabled={check.kind === "checking"}
              >
                Verify hash
              </button>
              {check.kind === "done" && (
                <span
                  role="status"
                  className={check.result.verified ? "text-good small" : "text-critical small"}
                >
                  <Icon name={check.result.verified ? "check" : "x"} size={13} strokeWidth={2.4} />{" "}
                  {check.result.verified ? "Verified" : check.result.detail}
                </span>
              )}
              {check.kind === "error" && (
                <span role="alert" className="text-critical small">
                  {check.message}
                </span>
              )}
            </div>
          </Field>
        )}
      </dl>
    </li>
  );
}
