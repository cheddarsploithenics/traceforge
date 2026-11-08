import { useCallback, useState } from "react";

import { type Project, type ScopeRule, UnauthorizedError, listScope } from "../api/client";
import { EmptyState, Field, PageHeader, Panel, SidePanel } from "../components/ui";
import { errorMessage, formatDate, formatDateTime, formatShort } from "../lib/format";

type Detail =
  | { kind: "none" }
  | { kind: "project"; project: Project; rules: ScopeRule[] | null; error: string | null };

interface ProjectsPageProps {
  projects: Project[];
  error: string | null;
  onUnauthorized: () => void;
}

function windowLabel(p: Project, format: (iso: string | null) => string = formatDateTime): string {
  if (!p.authorized_from && !p.authorized_until) return "Not time-limited";
  const from = p.authorized_from ? format(p.authorized_from) : "…";
  const until = p.authorized_until ? format(p.authorized_until) : "…";
  return `${from} → ${until}`;
}

/** Projects and their authorized scope (read-only; scope is managed from the CLI). */
export function ProjectsPage({ projects, error, onUnauthorized }: ProjectsPageProps) {
  const [detail, setDetail] = useState<Detail>({ kind: "none" });
  const close = useCallback(() => setDetail({ kind: "none" }), []);

  const open = (project: Project) => {
    setDetail({ kind: "project", project, rules: null, error: null });
    listScope(project.id)
      .then((rules) => setDetail({ kind: "project", project, rules, error: null }))
      .catch((err: unknown) => {
        if (err instanceof UnauthorizedError) onUnauthorized();
        else setDetail({ kind: "project", project, rules: null, error: errorMessage(err) });
      });
  };

  const selectedId = detail.kind === "project" ? detail.project.id : null;
  // Beside the open detail panel, show only the columns that fit.
  const full = detail.kind === "none";

  return (
    <>
      <PageHeader
        title="Projects"
        description="Engagements, their written authorization, and the scope scans are limited to."
      />
      <div className={detail.kind === "none" ? "split" : "split split--open"}>
        <Panel flush className="split__main">
          {error && (
            <p role="alert" className="panel__note callout--critical">
              {error}
            </p>
          )}
          {!error && projects.length === 0 && (
            <EmptyState title="No projects yet">
              <p>
                Create one with{" "}
                <code>traceforge project create NAME --authorization-ref REF</code>.
              </p>
            </EmptyState>
          )}
          {projects.length > 0 && (
            <div className="table-scroll">
              <table className="table table--interactive" aria-label="Projects">
                <thead>
                  <tr>
                    <th scope="col">Project</th>
                    <th scope="col">Authorization</th>
                    {full && <th scope="col">Window</th>}
                    <th scope="col" className="num">
                      Scope rules
                    </th>
                    {full && <th scope="col">Created</th>}
                  </tr>
                </thead>
                <tbody>
                  {projects.map((p) => (
                    <tr
                      key={p.id}
                      className={p.id === selectedId ? "is-selected" : undefined}
                      aria-selected={p.id === selectedId || undefined}
                      onClick={() => open(p)}
                    >
                      <td className="nowrap">
                        <button type="button" className="link" aria-label={`Open project ${p.name}`}>
                          {p.name}
                        </button>
                        <span className="muted small"> #{p.id}</span>
                      </td>
                      <td>{p.authorization_ref}</td>
                      {full && <td className="nowrap">{windowLabel(p, formatDate)}</td>}
                      <td className={p.scope_rule_count === 0 ? "num text-warning" : "num"}>
                        {p.scope_rule_count}
                      </td>
                      {full && (
                        <td className="nowrap" title={formatDateTime(p.created_at)}>
                          {formatShort(p.created_at)}
                        </td>
                      )}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Panel>

        {detail.kind === "project" && (
          <SidePanel title={detail.project.name} onClose={close}>
            <section className="section" aria-label="Authorization">
              <dl className="kv">
                <Field label="Authorization">{detail.project.authorization_ref}</Field>
                <Field label="Window">{windowLabel(detail.project)}</Field>
                <Field label="Created">{formatDateTime(detail.project.created_at)}</Field>
              </dl>
            </section>
            <section className="section">
              <h3 className="section__title">Authorized scope</h3>
              {detail.error && (
                <p role="alert" className="callout callout--critical">
                  {detail.error}
                </p>
              )}
              {!detail.error && !detail.rules && <p role="status">Loading scope…</p>}
              {detail.rules && detail.rules.length === 0 && (
                <EmptyState title="No scope rules">
                  <p>Nothing can be scanned in this project until targets are authorized.</p>
                </EmptyState>
              )}
              {detail.rules && detail.rules.length > 0 && (
                <div className="table-scroll table-scroll--framed">
                  <table className="table table--dense" aria-label="Scope rules">
                    <thead>
                      <tr>
                        <th scope="col">Rule</th>
                        <th scope="col">Value</th>
                        <th scope="col">Note</th>
                      </tr>
                    </thead>
                    <tbody>
                      {detail.rules.map((rule) => (
                        <tr key={rule.id}>
                          <td>
                            <span className={`tag tag--${rule.kind}`}>{rule.kind}</span>
                          </td>
                          <td className="mono">{rule.value}</td>
                          <td className="muted">{rule.note ?? ""}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
              <p className="form__hint section__footnote">
                Scope changes are audited and made from the CLI:{" "}
                <code>traceforge scope add {detail.project.id} include|exclude VALUE</code>
              </p>
            </section>
          </SidePanel>
        )}
      </div>
    </>
  );
}
