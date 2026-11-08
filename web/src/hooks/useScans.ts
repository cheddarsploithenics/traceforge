import { useCallback, useEffect, useRef, useState } from "react";

import { ACTIVE_STATUSES, type Scan, UnauthorizedError, listScans } from "../api/client";
import { errorMessage } from "../lib/format";

/** How often scan lists refresh while any scan is queued or running. */
export const POLL_INTERVAL_MS = 3000;

export type ScansState =
  | { kind: "loading" }
  | { kind: "ready"; scans: Scan[] }
  | { kind: "error"; message: string };

/**
 * Scan history, refreshed on demand and polled only while something is active.
 * `onRefreshed` lets a page reload dependent data (e.g. the open scan's results).
 */
export function useScans(
  onUnauthorized: () => void,
  { limit = 200, onRefreshed }: { limit?: number; onRefreshed?: (scans: Scan[]) => void } = {},
) {
  const [state, setState] = useState<ScansState>({ kind: "loading" });
  const callback = useRef(onRefreshed);
  callback.current = onRefreshed;

  const refresh = useCallback(() => {
    listScans({ limit })
      .then((scans) => {
        setState({ kind: "ready", scans });
        callback.current?.(scans);
      })
      .catch((err: unknown) => {
        if (err instanceof UnauthorizedError) onUnauthorized();
        else setState({ kind: "error", message: errorMessage(err) });
      });
  }, [limit, onUnauthorized]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const active = state.kind === "ready" && state.scans.some((s) => ACTIVE_STATUSES.has(s.status));
  useEffect(() => {
    if (!active) return;
    const timer = window.setInterval(refresh, POLL_INTERVAL_MS);
    return () => window.clearInterval(timer);
  }, [active, refresh]);

  return { state, refresh };
}
