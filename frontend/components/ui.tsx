"use client";

import { ReactNode } from "react";

export function PageHeading({
  title,
  subtitle,
  action,
}: {
  title: string;
  subtitle?: string;
  action?: ReactNode;
}) {
  return (
    <div className="flex items-start justify-between" style={{ marginBottom: 32, gap: 24 }}>
      <div>
        <h1 style={{ fontSize: 40, fontWeight: 700, lineHeight: "48px" }}>{title}</h1>
        {subtitle && (
          <p style={{ fontSize: 18, color: "var(--color-on-surface-variant)", marginTop: 4 }}>
            {subtitle}
          </p>
        )}
      </div>
      {action}
    </div>
  );
}

export function Alert({ kind, children }: { kind: "error" | "success" | "info"; children: ReactNode }) {
  const palette = {
    error: {
      background: "var(--color-error-container)",
      color: "var(--color-on-error-container)",
      border: "2px solid var(--color-error)",
    },
    success: {
      background: "#e3f5ec",
      color: "#00432c",
      border: "2px solid var(--color-status-success)",
    },
    info: {
      background: "var(--color-surface-container)",
      color: "var(--color-on-surface)",
      border: "2px solid var(--color-outline-variant)",
    },
  }[kind];

  return (
    <div style={{ ...palette, padding: 16, fontWeight: 600, marginBottom: 24 }}>{children}</div>
  );
}

export function Field({
  label,
  hint,
  children,
}: {
  label: string;
  hint?: string;
  children: ReactNode;
}) {
  return (
    <div style={{ marginBottom: 20 }}>
      <label className="label-bold" style={{ display: "block", marginBottom: 8 }}>
        {label}
      </label>
      {children}
      {hint && (
        <p style={{ fontSize: 16, color: "var(--color-on-surface-variant)", marginTop: 6 }}>{hint}</p>
      )}
    </div>
  );
}

export function Card({ title, children }: { title?: string; children: ReactNode }) {
  return (
    <div className="card" style={{ marginBottom: 32 }}>
      {title && (
        <div className="card-header">
          <h2 style={{ fontSize: 24, fontWeight: 700 }}>{title}</h2>
        </div>
      )}
      <div style={{ padding: 24 }}>{children}</div>
    </div>
  );
}

export function Badge({ kind, children }: { kind: "success" | "error" | "warning" | "neutral"; children: ReactNode }) {
  return <span className={`status-badge status-badge--${kind}`}>{children}</span>;
}

export function Mono({ children, truncate }: { children: string | null | undefined; truncate?: number }) {
  if (!children) return <span style={{ color: "var(--color-outline)" }}>—</span>;
  const text = truncate && children.length > truncate ? `${children.slice(0, truncate)}…` : children;
  return (
    <span className="data-mono" title={children}>
      {text}
    </span>
  );
}

export function Table({ headers, children }: { headers: string[]; children: ReactNode }) {
  return (
    <div className="card" style={{ overflowX: "auto" }}>
      <table style={{ width: "100%", borderCollapse: "collapse" }}>
        <thead>
          <tr style={{ background: "var(--color-slate-dark)" }}>
            {headers.map((header, index) => (
              <th
                key={`${header}-${index}`}
                className="label-bold"
                style={{ color: "#fff", textAlign: "left", padding: "16px 20px", whiteSpace: "nowrap" }}
              >
                {header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>{children}</tbody>
      </table>
    </div>
  );
}

export function Cell({ children, bold }: { children: ReactNode; bold?: boolean }) {
  return (
    <td style={{ padding: "16px 20px", fontSize: 18, fontWeight: bold ? 700 : 400 }}>{children}</td>
  );
}

export const CLASSIFICATION_LABELS: Record<string, string> = {
  public_redacted: "Public (redacted)",
  case_restricted: "Case restricted",
  court_elevated: "Court elevated",
  admin_only: "Admin only",
};

export const CUSTODY_LABELS: Record<string, string> = {
  police_custody: "Police custody",
  forensics_custody: "Forensics custody",
  court_custody: "Court custody",
  released: "Released",
};

export function classificationKind(value: string): "success" | "warning" | "error" | "neutral" {
  if (value === "public_redacted") return "success";
  if (value === "case_restricted") return "neutral";
  if (value === "court_elevated") return "warning";
  return "error";
}
