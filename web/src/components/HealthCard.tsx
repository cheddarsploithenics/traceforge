import type { HealthResponse } from "../api/client";

export type HealthState =
  | { kind: "loading" }
  | { kind: "ready"; health: HealthResponse }
  | { kind: "error"; message: string };

interface HealthCardProps {
  state: HealthState;
  onRefresh: () => void;
}

export function HealthCard({ state, onRefresh }: HealthCardProps) {
  const tone =
    state.kind === "ready" && state.health.status === "ok"
      ? "ok"
      : state.kind === "loading"
        ? "pending"
        : "error";

  return (
    <section className={`card card--${tone}`} aria-labelledby="health-title">
      <header className="card__header">
        <h2 id="health-title">Backend health</h2>
        <button type="button" onClick={onRefresh} disabled={state.kind === "loading"}>
          Refresh
        </button>
      </header>

      {state.kind === "loading" && <p role="status">Checking backend…</p>}

      {state.kind === "error" && (
        <div role="alert">
          <p className="status status--error">Unreachable</p>
          <p>{state.message}</p>
          <p>
            Start it with <code>traceforge serve</code>.
          </p>
        </div>
      )}

      {state.kind === "ready" && (
        <dl className="details">
          <dt>Status</dt>
          <dd className={`status status--${tone}`}>{state.health.status.toUpperCase()}</dd>
          <dt>Version</dt>
          <dd>{state.health.version}</dd>
          <dt>Database</dt>
          <dd>{state.health.database}</dd>
        </dl>
      )}
    </section>
  );
}
