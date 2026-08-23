"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import AppShell from "@/components/AppShell";
import { useAuth } from "@/lib/auth-context";
import { uploadEvidence, UploadResponse } from "@/lib/api";

export default function UploadPage() {
  const { user, loading: authLoading } = useAuth();
  const router = useRouter();
  const [caseId, setCaseId] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState<UploadResponse | null>(null);

  useEffect(() => {
    if (!authLoading && !user) router.push("/login");
  }, [authLoading, user, router]);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!file) return;
    setError("");
    setSubmitting(true);
    setResult(null);
    try {
      const res = await uploadEvidence(caseId, file);
      setResult(res);
      setCaseId("");
      setFile(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Upload failed");
    } finally {
      setSubmitting(false);
    }
  }

  if (authLoading || !user) return null;

  return (
    <AppShell>
      <h1 style={{ fontSize: 40, fontWeight: 700, marginBottom: 8 }}>Upload Evidence</h1>
      <p style={{ fontSize: 18, color: "var(--color-on-surface-variant)", marginBottom: 32 }}>
        Uploading a file computes a permanent hash and digital signature, then runs OCR and PII
        redaction automatically.
      </p>

      <div className="card" style={{ maxWidth: 720, padding: 32, marginBottom: 32 }}>
        <form onSubmit={handleSubmit}>
          <div style={{ marginBottom: 24 }}>
            <label className="label-bold" style={{ display: "block", marginBottom: 8 }}>
              Case ID
            </label>
            <input
              className="input-field"
              type="text"
              value={caseId}
              onChange={(e) => setCaseId(e.target.value)}
              placeholder="e.g. 2026/014"
              required
            />
          </div>

          <div style={{ marginBottom: 24 }}>
            <label className="label-bold" style={{ display: "block", marginBottom: 8 }}>
              Evidence File
            </label>
            <input
              className="input-field"
              type="file"
              onChange={(e) => setFile(e.target.files?.[0] || null)}
              style={{ paddingTop: 14 }}
              required
            />
            <p style={{ fontSize: 16, color: "var(--color-on-surface-variant)", marginTop: 8 }}>
              Scanned images (JPG, PNG) will be processed with OCR and automatic PII redaction.
            </p>
          </div>

          {error && (
            <div
              style={{
                background: "var(--color-error-container)",
                color: "var(--color-on-error-container)",
                padding: 16,
                marginBottom: 24,
                fontWeight: 600,
                border: "2px solid var(--color-error)",
              }}
            >
              {error}
            </div>
          )}

          <button type="submit" className="btn-primary" disabled={submitting || !file}>
            {submitting ? "Uploading..." : "Upload Evidence"}
          </button>
        </form>
      </div>

      {result && (
        <div className="card" style={{ maxWidth: 720 }}>
          <div className="card-header" style={{ background: "var(--color-status-success)" }}>
            <span style={{ color: "#fff", fontSize: 24, fontWeight: 700 }}>
              Upload Complete — Record #{result.id}
            </span>
          </div>
          <div style={{ padding: 24 }}>
            <Row label="Case ID" value={result.case_id} />
            <Row label="Filename" value={result.filename} />
            <Row label="SHA-256 Hash" value={result.sha256_hash} mono />
            <Row label="Digital Signature" value={`${result.signature.slice(0, 32)}...`} mono />
            <Row label="OCR Status" value={result.ocr_status} />
            {result.redacted_text && (
              <div style={{ marginTop: 16 }}>
                <div className="label-bold" style={{ marginBottom: 8 }}>
                  Redacted Extracted Text
                </div>
                <div
                  style={{
                    background: "var(--color-surface-container-low)",
                    padding: 16,
                    fontSize: 16,
                    fontFamily: "var(--font-data)",
                    whiteSpace: "pre-wrap",
                    border: "2px solid var(--color-border-heavy)",
                  }}
                >
                  {result.redacted_text}
                </div>
              </div>
            )}
            <div style={{ marginTop: 24, display: "flex", gap: 16 }}>
              <Link
                href={`/evidence/${result.id}`}
                className="btn-primary"
                style={{ textDecoration: "none", display: "inline-flex", alignItems: "center" }}
              >
                Verify Integrity
              </Link>
              <Link
                href="/dashboard"
                className="btn-secondary"
                style={{ textDecoration: "none", display: "inline-flex", alignItems: "center" }}
              >
                Back to Dashboard
              </Link>
            </div>
          </div>
        </div>
      )}
    </AppShell>
  );
}

function Row({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="divider" style={{ padding: "12px 0" }}>
      <div className="label-bold" style={{ marginBottom: 4 }}>
        {label}
      </div>
      <div className={mono ? "data-mono" : ""} style={{ fontSize: 18, wordBreak: "break-all" }}>
        {value}
      </div>
    </div>
  );
}
