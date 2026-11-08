import type { HealthResponse, SessionInfo } from "../api/client";
import { Icon } from "../components/Icon";
import { formatTime } from "../lib/format";

export type HealthState =
  | { kind: "loading" }
  | { kind: "ready"; health: HealthResponse }
  | { kind: "error"; message: string };

/** API health as a compact indicator: glyph + label, never color alone. */
export function HealthIndicator({ state }: { state: HealthState }) {
  if (state.kind === "loading") {
    return (
      <span className="health health--neutral" role="status">
        <span className="dot" aria-hidden="true" />
        Checking API…
      </span>
    );
  }
  if (state.kind === "error") {
    return (
      <span className="health health--critical" role="status">
        <Icon name="alert" size={13} />
        API unreachable
      </span>
    );
  }
  const ok = state.health.status === "ok";
  return (
    <span className={`health health--${ok ? "good" : "warning"}`} role="status">
      <Icon name={ok ? "check" : "alert"} size={13} />
      API {ok ? "OK" : "DEGRADED"}
      <span className="health__version">{state.health.version}</span>
    </span>
  );
}

interface TopbarProps {
  title: string;
  health: HealthState;
  session: SessionInfo;
  onSignOut: () => void;
}

export function Topbar({ title, health, session, onSignOut }: TopbarProps) {
  return (
    <header className="topbar">
      <div className="topbar__crumbs">
        <span className="muted">TraceForge</span>
        <span className="topbar__sep" aria-hidden="true">
          /
        </span>
        <span>{title}</span>
      </div>
      <div className="topbar__right">
        <HealthIndicator state={health} />
        <span className="topbar__session">
          Session
          {session.expires_at && <span className="muted"> · until {formatTime(session.expires_at)}</span>}
        </span>
        <button type="button" className="btn btn--ghost btn--sm" onClick={onSignOut}>
          <Icon name="logout" size={14} />
          Sign out
        </button>
      </div>
    </header>
  );
}
