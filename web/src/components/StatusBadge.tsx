import type { ScanStatus } from "../api/client";
import { Icon, type IconName } from "./Icon";

/**
 * Status is never color alone: every state has its own glyph and a text label.
 * Status colors are reserved for state and are not reused for anything else.
 */
const SCAN_STATUS: Record<ScanStatus, { icon: IconName; tone: string; label: string }> = {
  queued: { icon: "clock", tone: "neutral", label: "Queued" },
  running: { icon: "refresh", tone: "info", label: "Running" },
  completed: { icon: "check", tone: "good", label: "Completed" },
  failed: { icon: "x", tone: "critical", label: "Failed" },
  cancelled: { icon: "slash", tone: "neutral", label: "Cancelled" },
};

export function StatusBadge({ status }: { status: ScanStatus }) {
  const { icon, tone, label } = SCAN_STATUS[status];
  return (
    <span className={`status status--${tone} status--${status}`}>
      <Icon name={icon} size={14} strokeWidth={2.4} />
      {label}
    </span>
  );
}

/** Port state: open ports carry the accent dot, everything else stays muted. */
export function PortState({ state }: { state: string }) {
  return (
    <span className={state === "open" ? "port-state port-state--open" : "port-state"}>
      <span className="dot" aria-hidden="true" />
      {state}
    </span>
  );
}
