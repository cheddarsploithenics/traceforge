import { useCallback, useEffect, useState } from "react";

import {
  type SessionInfo,
  UnauthorizedError,
  fetchHealth,
  getSession,
  listProjects,
  signIn,
  signOut,
} from "./api/client";
import { type AuthState, AuthCard } from "./components/AuthCard";
import { HealthCard, type HealthState } from "./components/HealthCard";
import { type ProjectsState, ProjectsCard } from "./components/ProjectsCard";
import { ScansPage } from "./components/ScansPage";

type View = "overview" | "scans";

const message = (err: unknown) => (err instanceof Error ? err.message : String(err));

export default function App({ loginCode = null }: { loginCode?: string | null }) {
  const [health, setHealth] = useState<HealthState>({ kind: "loading" });
  const [auth, setAuth] = useState<AuthState>({ kind: "checking" });
  const [projects, setProjects] = useState<ProjectsState>({ kind: "loading" });
  const [view, setView] = useState<View>("overview");

  const refreshHealth = useCallback((signal?: AbortSignal) => {
    setHealth({ kind: "loading" });
    fetchHealth(signal)
      .then((data) => setHealth({ kind: "ready", health: data }))
      .catch((err: unknown) => {
        if (!signal?.aborted) setHealth({ kind: "error", message: message(err) });
      });
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    refreshHealth(controller.signal);
    return () => controller.abort();
  }, [refreshHealth]);

  const handleAuth = useCallback(
    (
      attempt: Promise<SessionInfo>,
      failure: string | undefined,
      isActive: () => boolean = () => true,
    ) => {
      attempt
        .then((session) => isActive() && setAuth({ kind: "signed-in", session }))
        .catch((err: unknown) => {
          if (!isActive()) return;
          const text = err instanceof UnauthorizedError ? failure : message(err);
          setAuth({ kind: "signed-out", message: text });
        });
    },
    [],
  );

  // Bootstrap: redeem a sign-in link if we were opened with one, otherwise
  // resume an existing cookie session.
  useEffect(() => {
    let active = true;
    handleAuth(
      loginCode ? signIn(loginCode) : getSession(),
      loginCode ? "That sign-in link is invalid, expired or already used." : undefined,
      () => active,
    );
    return () => {
      active = false;
    };
  }, [loginCode, handleAuth]);

  useEffect(() => {
    if (auth.kind !== "signed-in") return;
    const controller = new AbortController();
    setProjects({ kind: "loading" });
    listProjects(controller.signal)
      .then((data) => setProjects({ kind: "ready", projects: data }))
      .catch((err: unknown) => {
        if (controller.signal.aborted) return;
        if (err instanceof UnauthorizedError) {
          setAuth({ kind: "signed-out", message: "Your session has expired." });
        } else {
          setProjects({ kind: "error", message: message(err) });
        }
      });
    return () => controller.abort();
  }, [auth.kind]);

  const onSignIn = (code: string) => {
    setAuth({ kind: "checking" });
    handleAuth(signIn(code), "That sign-in code is invalid, expired or already used.");
  };

  const onUnauthorized = useCallback(
    () => setAuth({ kind: "signed-out", message: "Your session has expired." }),
    [],
  );

  const onSignOut = () => {
    signOut()
      .catch(() => undefined)
      .finally(() => setAuth({ kind: "signed-out" }));
  };

  const signedIn = auth.kind === "signed-in";
  const current: View = signedIn ? view : "overview";

  return (
    <div className={current === "scans" ? "layout layout--wide" : "layout"}>
      <header className="masthead">
        <h1>TraceForge</h1>
        <p>Evidence-driven penetration testing orchestration</p>
        {signedIn && (
          <nav className="tabs" aria-label="Sections">
            {(["overview", "scans"] as const).map((name) => (
              <button
                key={name}
                type="button"
                className="tab"
                aria-current={current === name ? "page" : undefined}
                onClick={() => setView(name)}
              >
                {name === "overview" ? "Overview" : "Scans"}
              </button>
            ))}
          </nav>
        )}
      </header>
      <main>
        {current === "overview" && (
          <>
            <HealthCard state={health} onRefresh={() => refreshHealth()} />
            <AuthCard state={auth} onSignIn={onSignIn} onSignOut={onSignOut} />
            {signedIn && <ProjectsCard state={projects} />}
          </>
        )}
        {current === "scans" && (
          <ScansPage
            projects={projects.kind === "ready" ? projects.projects : []}
            onUnauthorized={onUnauthorized}
          />
        )}
      </main>
    </div>
  );
}
