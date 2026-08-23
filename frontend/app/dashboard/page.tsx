"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import AppShell from "@/components/AppShell";
import { useAuth } from "@/lib/auth-context";
import { fetchEvidenceList, EvidenceSummary } from "@/lib/api";

export default function DashboardPage() {
  const { user, loading: authLoading } = useAuth();
  const router = useRouter();
  const [evidence, setEvidence] = useState<EvidenceSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [caseFilter, setCaseFilter] = useState<string>("ALL");

  useEffect(() => {
    if (!authLoading && !user) {
      router.push("/login");
    }
  }, [authLoading, user, router]);

  useEffect(() => {
    if (!user) return;
    fetchEvidenceList()
      .then(setEvidence)
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  }, [user]);

  const caseIds = useMemo(() => {
    const ids = Array.from(new Set(evidence.map((e) => e.case_id)));
    return ids.sort();
  }, [evidence]);

  const filtered = useMemo(() => {
    if (caseFilter === "ALL") return evidence;
    return evidence.filter((e) => e.case_id === caseFilter);
  }, [evidence, caseFilter]);

  if (authLoading || !user) return null;

  return (
    <AppShell>
      <div className="flex items-center justify-between" style={{ marginBottom: 32 }}>
        <div>
          <h1 style={{ fontSize: 40, fontWeight: 700, lineHeight: "48px" }}>
            Evidence Dashboard
          </h1>
          <p style={{ fontSize: 18, color: "var(--color-on-surface-variant)", marginTop: 4 }}>
            All evidence records uploaded to the system.
          </p>
        </div>
        <Link href="/upload" className="btn-primary" style={{ textDecoration: "none", display: "inline-flex", alignItems: "center" }}>
          + Upload Evidence
        </Link>
      </div>

      <div style={{ marginBottom: 24 }}>
        <label className="label-bold" style={{ display: "block", marginBottom: 8 }}>
          Filter by Case ID
        </label>
        <select
          className="input-field"
          style={{ maxWidth: 320 }}
          value={caseFilter}
          onChange={(e) => setCaseFilter(e.target.value)}
        >
          <option value="ALL">All Cases ({evidence.length})</option>
          {caseIds.map((id) => (
            <option key={id} value={id}>
              {id} ({evidence.filter((e) => e.case_id === id).length})
            </option>
          ))}
        </select>
      </div>

      {loading && <p style={{ fontSize: 18 }}>Loading evidence records...</p>}
      {error && (
        <div
          style={{
            background: "var(--color-error-container)",
            color: "var(--color-on-error-container)",
            padding: 16,
            fontWeight: 600,
            border: "2px solid var(--color-error)",
          }}
        >
          {error}
        </div>
      )}

      {!loading && !error && filtered.length === 0 && (
        <div className="card" style={{ padding: 48, textAlign: "center" }}>
          <p style={{ fontSize: 20, fontWeight: 600 }}>No evidence records yet.</p>
          <p style={{ fontSize: 18, color: "var(--color-on-surface-variant)", marginTop: 8 }}>
            Upload the first piece of evidence to get started.
          </p>
          <Link
            href="/upload"
            className="btn-primary"
            style={{ marginTop: 24, textDecoration: "none", display: "inline-flex", alignItems: "center" }}
          >
            Upload Evidence
          </Link>
        </div>
      )}

      {!loading && !error && filtered.length > 0 && (
        <div className="card">
          <table style={{ width: "100%", borderCollapse: "collapse" }}>
            <thead>
              <tr style={{ background: "var(--color-slate-dark)" }}>
                {["ID", "Case ID", "Filename", "SHA-256 Hash", "Uploaded By", "Uploaded At", "OCR Status", ""].map((h) => (
                  <th
                    key={h}
                    className="label-bold"
                    style={{ color: "#fff", textAlign: "left", padding: "16px 20px" }}
                  >
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {filtered.map((item) => (
                <tr key={item.id} className="divider">
                  <td style={{ padding: "16px 20px", fontSize: 18 }}>{item.id}</td>
                  <td style={{ padding: "16px 20px", fontSize: 18, fontWeight: 700 }}>{item.case_id}</td>
                  <td style={{ padding: "16px 20px", fontSize: 18 }}>{item.filename}</td>
                  <td className="data-mono" style={{ padding: "16px 20px" }}>
                    {item.sha256_hash.slice(0, 16)}...
                  </td>
                  <td style={{ padding: "16px 20px", fontSize: 18 }}>{item.uploaded_by}</td>
                  <td style={{ padding: "16px 20px", fontSize: 16 }}>
                    {new Date(item.uploaded_at).toLocaleString()}
                  </td>
                  <td style={{ padding: "16px 20px" }}>
                    <span
                      className={`status-badge ${
                        item.ocr_status === "ok" ? "status-badge--success" : "status-badge--neutral"
                      }`}
                    >
                      {item.ocr_status}
                    </span>
                  </td>
                  <td style={{ padding: "16px 20px" }}>
                    <Link href={`/evidence/${item.id}`} className="btn-secondary" style={{ minHeight: 40, padding: "0 20px", fontSize: 16, textDecoration: "none", display: "inline-flex", alignItems: "center" }}>
                      View
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </AppShell>
  );
}
