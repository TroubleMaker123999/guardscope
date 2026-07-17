import type { ReactNode } from "react";

/**
 * Page-level loading / error / empty states.
 *
 * Keeps each page's empty/loading/error layout consistent without forcing
 * callers to reach for CSS classes directly.
 */
export function State({
  icon,
  title,
  detail,
  variant = "default",
}: {
  icon?: ReactNode;
  title: string;
  detail?: string;
  variant?: "default" | "loading";
}) {
  return (
    <div className="state" role="status" aria-live="polite">
      {icon ? <div className="state-icon">{icon}</div> : null}
      <div className="state-title">{title}</div>
      {detail ? <div className="state-detail">{detail}</div> : null}
      {variant === "loading" ? <div className="state-detail">{"\u23F3"}</div> : null}
    </div>
  );
}

export function Panel({
  title,
  actions,
  children,
  flush = false,
}: {
  title?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  flush?: boolean;
}) {
  return (
    <section className="panel">
      {title !== undefined ? (
        <header className="panel-header">
          <h2>{title}</h2>
          {actions ? <div className="row">{actions}</div> : null}
        </header>
      ) : null}
      <div className={`panel-body${flush ? " is-flush" : ""}`}>{children}</div>
    </section>
  );
}

export function SeverityPill({ severity }: { severity: string }) {
  const cls = `severity-pill sev-${severity || "unknown"}`;
  return <span className={cls}>{severity || "unknown"}</span>;
}

export function Tag({ children }: { children: ReactNode }) {
  return <span className="tag">{children}</span>;
}

export function CopyButton({
  value,
  label = "复制",
}: {
  value: string;
  label?: string;
}) {
  return (
    <button
      type="button"
      className="copy-btn"
      onClick={(e) => {
        e.stopPropagation();
        if (navigator.clipboard) {
          navigator.clipboard.writeText(value).catch(() => undefined);
        }
      }}
      aria-label={`${label} ${value}`}
      title={`${label} ${value}`}
    >
      复制
    </button>
  );
}