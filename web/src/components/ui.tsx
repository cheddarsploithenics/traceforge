import { type ReactNode, useEffect, useId } from "react";

import { Icon } from "./Icon";

export function PageHeader({
  title,
  description,
  actions,
}: {
  title: string;
  description?: ReactNode;
  actions?: ReactNode;
}) {
  return (
    <header className="page-header">
      <div>
        <h1>{title}</h1>
        {description && <p className="page-header__desc">{description}</p>}
      </div>
      {actions && <div className="page-header__actions">{actions}</div>}
    </header>
  );
}

export function Panel({
  title,
  actions,
  children,
  flush = false,
  className,
}: {
  title?: string;
  actions?: ReactNode;
  children: ReactNode;
  /** Remove body padding, for tables that run edge to edge. */
  flush?: boolean;
  className?: string;
}) {
  const id = useId();
  return (
    <section
      className={["panel", className].filter(Boolean).join(" ")}
      aria-labelledby={title ? id : undefined}
    >
      {(title || actions) && (
        <header className="panel__header">
          {title && <h2 id={id}>{title}</h2>}
          {actions && <div className="panel__actions">{actions}</div>}
        </header>
      )}
      <div className={flush ? "panel__body panel__body--flush" : "panel__body"}>{children}</div>
    </section>
  );
}

/** Stat tile: label, value, optional caption. The number is the chart. */
export function StatTile({ label, value, caption }: { label: string; value: string; caption?: ReactNode }) {
  return (
    <div className="stat">
      <dt className="stat__label">{label}</dt>
      <dd className="stat__value">{value}</dd>
      {caption && <dd className="stat__caption">{caption}</dd>}
    </div>
  );
}

export function EmptyState({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="empty">
      <p className="empty__title">{title}</p>
      {children && <div className="empty__body">{children}</div>}
    </div>
  );
}

/**
 * Detail panel docked beside a table (not a modal: the table stays usable).
 * Escape closes it.
 */
export function SidePanel({
  title,
  meta,
  actions,
  onClose,
  children,
}: {
  title: ReactNode;
  meta?: ReactNode;
  actions?: ReactNode;
  onClose: () => void;
  children: ReactNode;
}) {
  const id = useId();
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  return (
    <aside className="side-panel" aria-labelledby={id}>
      <header className="side-panel__header">
        <div className="side-panel__title">
          <h2 id={id}>{title}</h2>
          {meta}
        </div>
        <button type="button" className="btn btn--icon" aria-label="Close panel" onClick={onClose}>
          <Icon name="close" />
        </button>
      </header>
      {actions && <div className="side-panel__actions">{actions}</div>}
      <div className="side-panel__body">{children}</div>
    </aside>
  );
}

export function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="kv__row">
      <dt>{label}</dt>
      <dd>{children}</dd>
    </div>
  );
}
