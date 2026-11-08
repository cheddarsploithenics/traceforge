import { useCallback, useEffect, useRef, useState } from "react";

import {
  ACTIVE_STATUSES,
  type Project,
  type Scan,
  UnauthorizedError,
  cancelScan,
  getScanResults,
  listScans,
} from "../api/client";
import { ScanForm } from "./ScanForm";
import { ScanHistory } from "./ScanHistory";
import { type ResultsState, ScanResultsView } from "./ScanResultsView";

/** How often to refresh while any scan is queued or running. */
export const POLL_INTERVAL_MS = 3000;

interface ScansPageProps {
  projects: Project[];
  onUnauthorized: () => void;
}

type ListState =
  | { kind: "loading" }
  | { kind: "ready"; scans: Scan[] }
  | { kind: "error"; message: string };

const message = (err: unknown) => (err instanceof Error ? err.message : String(err));

export function ScansPage({ projects, onUnauthorized }: ScansPageProps) {
  const [list, setList] = useState<ListState>({ kind: "loading" });
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [results, setResults] = useState<ResultsState>({ kind: "none" });
  const [notice, setNotice] = useState<string | null>(null);
  const selectedRef = useRef<number | null>(null);

  const fail = useCallback(
    (err: unknown, onOther: (text: string) => void) => {
      if (err instanceof UnauthorizedError) onUnauthorized();
      else onOther(message(err));
    },
    [onUnauthorized],
  );

  const loadResults = useCallback(
    (scanId: number, quiet = false) => {
      if (!quiet) setResults({ kind: "loading" });
      getScanResults(scanId)
        .then((data) => {
          if (selectedRef.current === scanId) setResults({ kind: "ready", results: data });
        })
        .catch((err: unknown) => fail(err, (text) => setResults({ kind: "error", message: text })));
    },
    [fail],
  );

  const refresh = useCallback(() => {
    listScans()
      .then((scans) => {
        setList({ kind: "ready", scans });
        const selected = scans.find((s) => s.id === selectedRef.current);
        if (selected) loadResults(selected.id, true);
      })
      .catch((err: unknown) => fail(err, (text) => setList({ kind: "error", message: text })));
  }, [fail, loadResults]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  // Poll only while something is queued or running.
  const hasActive = list.kind === "ready" && list.scans.some((s) => ACTIVE_STATUSES.has(s.status));
  useEffect(() => {
    if (!hasActive) return;
    const timer = window.setInterval(refresh, POLL_INTERVAL_MS);
    return () => window.clearInterval(timer);
  }, [hasActive, refresh]);

  const select = (scanId: number) => {
    selectedRef.current = scanId;
    setSelectedId(scanId);
    loadResults(scanId);
  };

  const cancel = (scanId: number) => {
    setNotice(null);
    cancelScan(scanId)
      .then((scan) => setNotice(`Scan #${scan.id} ${scan.status}.`))
      .catch((err: unknown) => fail(err, setNotice))
      .finally(refresh);
  };

  return (
    <>
      {projects.length === 0 ? (
        <section className="card card--error" aria-labelledby="new-scan-title">
          <h2 id="new-scan-title">New scan</h2>
          <p>
            Scans need a project with an authorized scope. Create one with{" "}
            <code>traceforge project create NAME --authorization-ref REF</code> and add targets
            with <code>traceforge scope add ID include 10.0.0.0/24</code>.
          </p>
        </section>
      ) : (
        <ScanForm
          projects={projects}
          onLaunched={(launched) => {
            refresh();
            select(launched.scan_id);
          }}
        />
      )}

      <section className="card" aria-labelledby="history-title">
        <header className="card__header">
          <h2 id="history-title">Scan history</h2>
          <button type="button" onClick={refresh}>
            Refresh
          </button>
        </header>
        {notice && <p role="status">{notice}</p>}
        {list.kind === "loading" && <p role="status">Loading scans…</p>}
        {list.kind === "error" && <p role="alert">{list.message}</p>}
        {list.kind === "ready" && (
          <ScanHistory
            scans={list.scans}
            projects={projects}
            selectedId={selectedId}
            onSelect={select}
            onCancel={cancel}
          />
        )}
      </section>

      <ScanResultsView state={results} />
    </>
  );
}
