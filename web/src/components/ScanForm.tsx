import { type FormEvent, useState } from "react";

import {
  ApiError,
  type NmapScanOptions,
  type Project,
  type ScanLaunchResult,
  type ScopeDecision,
  launchScan,
  parseTargets,
} from "../api/client";

interface ScanFormProps {
  projects: Project[];
  onLaunched: (result: ScanLaunchResult) => void;
}

type Feedback =
  | { kind: "idle" }
  | { kind: "submitting" }
  | { kind: "error"; message: string; decisions: ScopeDecision[] }
  | { kind: "queued"; result: ScanLaunchResult };

export function ScanForm({ projects, onLaunched }: ScanFormProps) {
  const [projectId, setProjectId] = useState<number | "">(projects[0]?.id ?? "");
  const [targets, setTargets] = useState("");
  const [ports, setPorts] = useState("");
  const [serviceDetection, setServiceDetection] = useState(true);
  const [timing, setTiming] = useState<2 | 3 | 4>(3);
  const [skipDiscovery, setSkipDiscovery] = useState(false);
  const [feedback, setFeedback] = useState<Feedback>({ kind: "idle" });

  const project = projects.find((p) => p.id === projectId);
  const targetList = parseTargets(targets);

  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (projectId === "" || targetList.length === 0) return;
    const options: NmapScanOptions = {
      service_detection: serviceDetection,
      timing,
      skip_host_discovery: skipDiscovery,
    };
    if (ports.trim()) options.ports = ports.trim();
    setFeedback({ kind: "submitting" });
    launchScan(projectId, { targets: targetList, options })
      .then((result) => {
        setFeedback({ kind: "queued", result });
        setTargets("");
        onLaunched(result);
      })
      .catch((err: unknown) => {
        if (err instanceof ApiError) {
          setFeedback({ kind: "error", message: err.message, decisions: err.decisions });
        } else {
          setFeedback({ kind: "error", message: String(err), decisions: [] });
        }
      });
  };

  return (
    <section className="card" aria-labelledby="new-scan-title">
      <h2 id="new-scan-title">New scan</h2>
      <p className="muted">
        Nmap TCP connect scan (<code>-sT</code>). Every target must be inside the project&apos;s
        authorized scope; hostnames are resolved once, checked, and scanned by IP address.
      </p>
      <form className="scan-form" onSubmit={submit}>
        <label htmlFor="scan-project">Project</label>
        <select
          id="scan-project"
          value={projectId}
          onChange={(e) => setProjectId(e.target.value ? Number(e.target.value) : "")}
        >
          {projects.map((p) => (
            <option key={p.id} value={p.id}>
              #{p.id} {p.name} ({p.authorization_ref})
            </option>
          ))}
        </select>
        {project && project.scope_rule_count === 0 && (
          <p className="hint hint--warn">
            This project has no authorized scope yet. Add rules with{" "}
            <code>traceforge scope add {project.id} include …</code>
          </p>
        )}

        <label htmlFor="scan-targets">Authorized targets</label>
        <textarea
          id="scan-targets"
          rows={3}
          spellCheck={false}
          placeholder="10.0.0.5&#10;10.0.0.0/28&#10;app.example.com"
          value={targets}
          onChange={(e) => setTargets(e.target.value)}
        />

        <label htmlFor="scan-ports">Ports</label>
        <input
          id="scan-ports"
          spellCheck={false}
          placeholder="default: Nmap top 1000, e.g. 22,80,443 or 1-1024"
          value={ports}
          onChange={(e) => setPorts(e.target.value)}
        />

        <label htmlFor="scan-timing">Timing</label>
        <select
          id="scan-timing"
          value={timing}
          onChange={(e) => setTiming(Number(e.target.value) as 2 | 3 | 4)}
        >
          <option value={2}>T2 polite</option>
          <option value={3}>T3 normal</option>
          <option value={4}>T4 aggressive</option>
        </select>

        <div className="scan-form__checks">
          <label>
            <input
              type="checkbox"
              checked={serviceDetection}
              onChange={(e) => setServiceDetection(e.target.checked)}
            />{" "}
            Service/version detection (<code>-sV</code>)
          </label>
          <label>
            <input
              type="checkbox"
              checked={skipDiscovery}
              onChange={(e) => setSkipDiscovery(e.target.checked)}
            />{" "}
            Treat hosts as online (<code>-Pn</code>)
          </label>
        </div>

        <div className="scan-form__actions">
          <button
            type="submit"
            disabled={feedback.kind === "submitting" || projectId === "" || !targetList.length}
          >
            Start scan
          </button>
        </div>
      </form>

      {feedback.kind === "queued" && (
        <p role="status" className="status--ok">
          Queued scan #{feedback.result.scan_id} of {feedback.result.scan_addresses.join(", ")}
        </p>
      )}
      {feedback.kind === "error" && (
        <div role="alert" className="scan-error">
          <p>{feedback.message}</p>
          {feedback.decisions.length > 0 && (
            <ul className="decisions">
              {feedback.decisions.map((d) => (
                <li key={d.target} className={d.allowed ? "allowed" : "denied"}>
                  <strong>{d.allowed ? "ALLOW" : "DENY"}</strong> {d.target}{" "}
                  <span className="muted">— {d.reason}</span>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
    </section>
  );
}
