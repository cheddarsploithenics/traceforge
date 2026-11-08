import { useCallback, useEffect, useState } from "react";

import {
  type Project,
  type SessionInfo,
  UnauthorizedError,
  fetchHealth,
  getSession,
  listProjects,
  signIn,
  signOut,
} from "./api/client";
import { Sidebar } from "./layout/Sidebar";
import { type HealthState, Topbar } from "./layout/Topbar";
import { errorMessage } from "./lib/format";
import { type Route, useRoute } from "./lib/route";
import { AssetsPage } from "./pages/AssetsPage";
import { OverviewPage } from "./pages/OverviewPage";
import { ProjectsPage } from "./pages/ProjectsPage";
import { ScansPage } from "./pages/ScansPage";
import { SignInPage } from "./pages/SignInPage";

type AuthState =
  | { kind: "checking" }
  | { kind: "signed-out"; message?: string }
  | { kind: "signed-in"; session: SessionInfo };

type ProjectsState =
  | { kind: "loading" }
  | { kind: "ready"; projects: Project[] }
  | { kind: "error"; message: string };

const TITLES: Record<Route, string> = {
  overview: "Overview",
  assets: "Assets",
  scans: "Scans",
  projects: "Projects",
};

export default function App({ loginCode = null }: { loginCode?: string | null }) {
  const [health, setHealth] = useState<HealthState>({ kind: "loading" });
  const [auth, setAuth] = useState<AuthState>({ kind: "checking" });
  const [projects, setProjects] = useState<ProjectsState>({ kind: "loading" });
  const [route, navigate] = useRoute();
  const [focusScan, setFocusScan] = useState<number | null>(null);
  const [focusAsset, setFocusAsset] = useState<string | null>(null);

  const refreshHealth = useCallback((signal?: AbortSignal) => {
    setHealth({ kind: "loading" });
    fetchHealth(signal)
      .then((data) => setHealth({ kind: "ready", health: data }))
      .catch((err: unknown) => {
        if (!signal?.aborted) setHealth({ kind: "error", message: errorMessage(err) });
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
          const text = err instanceof UnauthorizedError ? failure : errorMessage(err);
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

  const onUnauthorized = useCallback(
    () => setAuth({ kind: "signed-out", message: "Your session has expired." }),
    [],
  );

  useEffect(() => {
    if (auth.kind !== "signed-in") return;
    const controller = new AbortController();
    setProjects({ kind: "loading" });
    listProjects(controller.signal)
      .then((data) => setProjects({ kind: "ready", projects: data }))
      .catch((err: unknown) => {
        if (controller.signal.aborted) return;
        if (err instanceof UnauthorizedError) onUnauthorized();
        else setProjects({ kind: "error", message: errorMessage(err) });
      });
    return () => controller.abort();
  }, [auth.kind, onUnauthorized]);

  if (auth.kind !== "signed-in") {
    return (
      <SignInPage
        health={health}
        checking={auth.kind === "checking"}
        message={auth.kind === "signed-out" ? auth.message : undefined}
        onSignIn={(code) => {
          setAuth({ kind: "checking" });
          handleAuth(signIn(code), "That sign-in code is invalid, expired or already used.");
        }}
        onRetryHealth={() => refreshHealth()}
      />
    );
  }

  const projectList = projects.kind === "ready" ? projects.projects : [];
  const projectsError = projects.kind === "error" ? projects.message : null;
  const onSignOut = () => {
    signOut()
      .catch(() => undefined)
      .finally(() => setAuth({ kind: "signed-out" }));
  };
  const go = (next: Route) => {
    setFocusScan(null);
    setFocusAsset(null);
    navigate(next);
  };
  const openScan = (id: number) => {
    setFocusScan(id);
    navigate("scans");
  };
  const openAsset = (uid: string) => {
    setFocusAsset(uid);
    navigate("assets");
  };

  return (
    <div className="shell">
      <Sidebar
        route={route}
        onNavigate={go}
        version={health.kind === "ready" ? health.health.version : null}
      />
      <div className="shell__main">
        <Topbar title={TITLES[route]} health={health} session={auth.session} onSignOut={onSignOut} />
        <main className="content">
          {route === "overview" && (
            <OverviewPage
              health={health}
              session={auth.session}
              projects={projectList}
              projectsError={projectsError}
              onRefreshHealth={() => refreshHealth()}
              onOpenScan={openScan}
              onShowScans={() => go("scans")}
              onShowAssets={() => go("assets")}
              onShowProjects={() => go("projects")}
              onUnauthorized={onUnauthorized}
            />
          )}
          {route === "scans" && (
            <ScansPage
              key={focusScan ?? "all"}
              projects={projectList}
              initialScanId={focusScan}
              onOpenAsset={openAsset}
              onUnauthorized={onUnauthorized}
            />
          )}
          {route === "assets" && (
            <AssetsPage
              key={focusAsset ?? "all"}
              projects={projectList}
              initialUid={focusAsset}
              onOpenScan={openScan}
              onUnauthorized={onUnauthorized}
            />
          )}
          {route === "projects" && (
            <ProjectsPage projects={projectList} error={projectsError} onUnauthorized={onUnauthorized} />
          )}
        </main>
      </div>
    </div>
  );
}
