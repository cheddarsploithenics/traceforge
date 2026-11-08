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

const message = (err: unknown) => (err instanceof Error ? err.message : String(err));

export default function App({ loginCode = null }: { loginCode?: string | null }) {
  const [health, setHealth] = useState<HealthState>({ kind: "loading" });
  const [auth, setAuth] = useState<AuthState>({ kind: "checking" });
  const [projects, setProjects] = useState<ProjectsState>({ kind: "loading" });

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

  const onSignOut = () => {
    signOut()
      .catch(() => undefined)
      .finally(() => setAuth({ kind: "signed-out" }));
  };

  return (
    <div className="layout">
      <header className="masthead">
        <h1>TraceForge</h1>
        <p>Evidence-driven penetration testing orchestration</p>
      </header>
      <main>
        <HealthCard state={health} onRefresh={() => refreshHealth()} />
        <AuthCard state={auth} onSignIn={onSignIn} onSignOut={onSignOut} />
        {auth.kind === "signed-in" && <ProjectsCard state={projects} />}
        <p className="note">Scanning is not available in this version.</p>
      </main>
    </div>
  );
}
