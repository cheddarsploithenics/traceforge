import { type FormEvent, useState } from "react";

import {
  ApiError,
  type NmapScanOptions,
  type Project,
  type ScanLaunchResult,
  type ScopeDecision,
  UnauthorizedError,
  launchScan,
  parseTargets,
} from "../api/client";
import { errorMessage } from "../lib/format";

interface ScanFormProps {
  projects: Project[];
  onLaunched: (result: ScanLaunchResult) => void;
  onUnauthorized: () => void;
}

type Feedback =
  | { kind: "idle" }
  | { kind: "submitting" }
  | { kind: "error"; message: string; decisions: ScopeDecision[] };

export function ScanForm({ projects, onLaunched, onUnauthorized }: ScanFormProps) {
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
        setFeedback({ kind: "idle" });
        onLaunched(result);
      })
      .catch((err: unknown) => {
        if (err instanceof UnauthorizedError) return onUnauthorized();
        const decisions = err instanceof ApiError ? err.decisions : [];
        setFeedback({ kind: "error", message: errorMessage(err), decisions });
      });
  };

  return (
    <form className="form" onSubmit={submit} aria-label="New scan">
      <p className="form__intro">
        Nmap TCP connect scan (<code>-sT</code>). Every target must be inside the project&apos;s
        authorized scope. Hostnames are resolved once, checked, and scanned by IP address.
      </p>

      <div className="form__field">
        <label className="form__label" htmlFor="scan-project">
          Project
        </label>
        <select
          id="scan-project"
          className="input"
          value={projectId}
          onChange={(e) => setProjectId(e.target.value ? Number(e.target.value) : "")}
        >
          {projects.map((p) => (
            <option key={p.id} value={p.id}>
              {p.name} — {p.authorization_ref}
            </option>
          ))}
        </select>
        {project && project.scope_rule_count === 0 && (
          <p className="form__hint text-warning">
            No authorized scope yet. Add rules with{" "}
            <code>traceforge scope add {project.id} include …</code>
          </p>
        )}
      </div>

      <div className="form__field">
        <label className="form__label" htmlFor="scan-targets">
          Authorized targets
        </label>
        <textarea
          id="scan-targets"
          className="input mono"
          rows={4}
          spellCheck={false}
          placeholder={"10.0.0.5\n10.0.0.0/28\napp.example.com"}
          value={targets}
          onChange={(e) => setTargets(e.target.value)}
        />
        <p className="form__hint">
          One per line, or separated by commas. {targetList.length > 0 && `${targetList.length} target(s).`}
        </p>
      </div>

      <div className="form__row">
        <div className="form__field">
          <label className="form__label" htmlFor="scan-ports">
            Ports
          </label>
          <input
            id="scan-ports"
            className="input mono"
            spellCheck={false}
            placeholder="22,80,443 or 1-1024"
            value={ports}
            onChange={(e) => setPorts(e.target.value)}
          />
          <p className="form__hint">Empty: Nmap&apos;s top 1,000 ports.</p>
        </div>
        <div className="form__field">
          <label className="form__label" htmlFor="scan-timing">
            Timing
          </label>
          <select
            id="scan-timing"
            className="input"
            value={timing}
            onChange={(e) => setTiming(Number(e.target.value) as 2 | 3 | 4)}
          >
            <option value={2}>T2 · polite</option>
            <option value={3}>T3 · normal</option>
            <option value={4}>T4 · aggressive</option>
          </select>
        </div>
      </div>

      <fieldset className="form__checks">
        <legend className="form__label">Options</legend>
        <label className="check">
          <input
            type="checkbox"
            checked={serviceDetection}
            onChange={(e) => setServiceDetection(e.target.checked)}
          />
          <span>
            Service/version detection <code>-sV</code>
          </span>
        </label>
        <label className="check">
          <input
            type="checkbox"
            checked={skipDiscovery}
            onChange={(e) => setSkipDiscovery(e.target.checked)}
          />
          <span>
            Treat hosts as online <code>-Pn</code>
          </span>
        </label>
      </fieldset>

      {feedback.kind === "error" && (
        <div role="alert" className="callout callout--critical">
          <p className="callout__title">{feedback.message}</p>
          {feedback.decisions.length > 0 && (
            <ul className="decisions">
              {feedback.decisions.map((d) => (
                <li key={d.target} className={d.allowed ? "allowed" : "denied"}>
                  <span className="decisions__verdict">{d.allowed ? "ALLOW" : "DENY"}</span>
                  <span className="mono">{d.target}</span>
                  <span className="muted">{d.reason}</span>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}

      <div className="form__actions">
        <button
          type="submit"
          className="btn btn--primary"
          disabled={feedback.kind === "submitting" || projectId === "" || !targetList.length}
        >
          {feedback.kind === "submitting" ? "Starting…" : "Start scan"}
        </button>
      </div>
    </form>
  );
}
