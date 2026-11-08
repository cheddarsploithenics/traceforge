import { useCallback, useEffect, useState } from "react";

/**
 * Minimal hash routing (`#/scans`), so views are linkable and survive a reload
 * without a router dependency. The sign-in code also travels in the fragment
 * (`#code=…`), but main.tsx consumes and scrubs it before the app renders.
 */
export const ROUTES = ["overview", "scans", "projects"] as const;
export type Route = (typeof ROUTES)[number];

function readRoute(): Route {
  const name = window.location.hash.replace(/^#\/?/, "");
  return (ROUTES as readonly string[]).includes(name) ? (name as Route) : "overview";
}

export function useRoute(): [Route, (route: Route) => void] {
  const [route, setRoute] = useState<Route>(readRoute);

  useEffect(() => {
    const sync = () => setRoute(readRoute());
    window.addEventListener("hashchange", sync);
    window.addEventListener("popstate", sync);
    return () => {
      window.removeEventListener("hashchange", sync);
      window.removeEventListener("popstate", sync);
    };
  }, []);

  const navigate = useCallback((next: Route) => {
    if (readRoute() !== next) window.history.pushState(null, "", `#/${next}`);
    setRoute(next);
  }, []);

  return [route, navigate];
}
