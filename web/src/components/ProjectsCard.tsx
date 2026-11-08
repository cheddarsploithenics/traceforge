import type { Project } from "../api/client";

export type ProjectsState =
  | { kind: "loading" }
  | { kind: "ready"; projects: Project[] }
  | { kind: "error"; message: string };

export function ProjectsCard({ state }: { state: ProjectsState }) {
  return (
    <section className="card" aria-labelledby="projects-title">
      <h2 id="projects-title">Projects</h2>
      {state.kind === "loading" && <p role="status">Loading projects…</p>}
      {state.kind === "error" && <p role="alert">{state.message}</p>}
      {state.kind === "ready" && state.projects.length === 0 && (
        <p>
          No projects yet. Create one with{" "}
          <code>traceforge project create NAME --authorization-ref REF</code>.
        </p>
      )}
      {state.kind === "ready" && state.projects.length > 0 && (
        <ul className="projects">
          {state.projects.map((p) => (
            <li key={p.id}>
              <strong>{p.name}</strong>
              <span className="muted"> · {p.authorization_ref}</span>
              <span className="muted"> · {p.scope_rule_count} scope rule(s)</span>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
