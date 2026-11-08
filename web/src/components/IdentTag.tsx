import type { Identification } from "../api/client";

/**
 * How a service name was obtained. A port-number label ("8080 is usually
 * http-proxy") is not evidence that the service runs there; only a probed
 * detection is. Neither says anything about vulnerability.
 */
export function IdentTag({ identification }: { identification: Identification | null }) {
  if (!identification) return null;
  return identification === "detected" ? (
    <span className="tag tag--detected" title="Identified by probing the service (-sV)">
      detected
    </span>
  ) : (
    <span className="tag tag--label" title="Conventional service for this port number; not probed">
      port label
    </span>
  );
}
