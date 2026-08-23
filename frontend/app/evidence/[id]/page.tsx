"use client";

import { useEffect, useState, use as usePromise } from "react";
import { useRouter } from "next/navigation";
import AppShell from "@/components/AppShell";
import { useAuth } from "@/lib/auth-context";
import { fetchEvidenceDetail, verifyEvidence, EvidenceDetail, VerifyResponse } from "@/lib/api";

export default function EvidenceDetailPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = usePromise(params);
  const { user, loading: authLoading } = useAuth();
  const router = useRouter();
  const [record, setRecord] = useState<EvidenceDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [verifying, setVerifying] = useState(false);
  const [verifyResult, setVerifyResult] = useState<VerifyResponse | null>(null);

  useEffect(() => {
    if (!authLoading && !user) router.push("/login");
  }, [authLoading, user, router]);

  useEffect(() => {
    if (!user) return;
    fetchEvidenceDetail(Number(id))
      .then(setRecord)
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  }, [user, id]);

  async function handleVerify() {
    setVerifying(true);
    setVerifyResult(null);
    try {
      const res = await verifyEvidence(Number(id));
      setVerifyResult(res);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Verification failed");
    } finally {
      setVerifying(false);
    }
  }

  if (authLoading || !user) return null;

  return (
    <AppShell>
      <button
        onClick={() => router.push("/dashboard")}
        className="btn-secondary"
        style={{ marginBottom: 24, minHeight: 40, padding: "0 20px", fontSize: 16 }}
      >
        ← Back to Dashboard
      </button>

      {loading && <p style={{ fontSize: 18 }}>Loading record...</p>}
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

      {record && (
        <>
          <h1 style={{ fontSize: 40, fontWeight: 700, marginBottom: 8 }}>
            Evidence Record #{record.id}
          </h1>
          <p style={{ fontSize: 18, color: "var(--color-on-surface-variant)", marginBottom: 32 }}>
            Case {record.case_id} · Uploaded by {record.uploaded_by}
          </p>

          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 24, marginBottom: 24 }}>
            <div className="card">
              <div className="card-header">
                <span style={{ fontSize: 28, fontWeight: 700 }}>Record Details</span>
              </div>
              <div style={{ padding: 24 }}>
                <Row label="Filename" value={record.filename} />
                <Row label="Case ID" value={record.case_id} />
                <Row label="Uploaded By" value={record.uploaded_by} />
                <Row label="Uploaded At" value={new Date(record.uploaded_at).toLocaleString()} />
                <Row label="OCR Status" value={record.ocr_status} />
              </div>
            </div>

            <div className="card">
              <div className="card-header">
                <span style={{ fontSize: 28, fontWeight: 700 }}>Cryptographic Record</span>
              </div>
              <div style={{ padding: 24 }}>
                <Row label="SHA-256 Hash (at upload)" value={record.sha256_hash} mono />
                <Row label="RSA Signature" value={`${record.signature.slice(0, 48)}...`} mono />
              </div>
            </div>
          </div>

          {record.redacted_text && (
            <div className="card" style={{ marginBottom: 24 }}>
              <div className="card-header">
                <span style={{ fontSize: 28, fontWeight: 700 }}>Redacted Extracted Text</span>
              </div>
              <div
                style={{
                  padding: 24,
                  fontFamily: "var(--font-data)",
                  fontSize: 16,
                  whiteSpace: "pre-wrap",
                  background: "var(--color-surface-container-low)",
                }}
              >
                {record.redacted_text}
              </div>
            </div>
          )}

          <div className="card" style={{ borderColor: "var(--color-kinetic-blue)", borderWidth: 3 }}>
            <div className="card-header" style={{ background: "var(--color-slate-dark)" }}>
              <span style={{ fontSize: 28, fontWeight: 700, color: "#fff" }}>
                Integrity Verification
              </span>
            </div>
            <div style={{ padding: 32 }}>
              <p style={{ fontSize: 18, marginBottom: 24 }}>
                Recomputes the file&apos;s hash from what is currently stored and checks it against
                the hash and digital signature recorded at upload time.
              </p>

              <button onClick={handleVerify} className="btn-primary" disabled={verifying}>
                {verifying ? "Verifying..." : "Verify Integrity"}
              </button>

              {verifyResult && (
                <div style={{ marginTop: 32 }}>
                  <div
                    className={`status-badge ${
                      verifyResult.integrity === "VERIFIED"
                        ? "status-badge--success"
                        : "status-badge--error"
                    }`}
                    style={{ fontSize: 24, padding: "16px 32px", marginBottom: 24 }}
                  >
                    {verifyResult.integrity === "VERIFIED" ? "✓ VERIFIED" : "✗ TAMPERED"}
                  </div>

                  {verifyResult.reason && (
                    <p style={{ fontSize: 18, marginBottom: 16 }}>{verifyResult.reason}</p>
                  )}

                  {verifyResult.original_hash && (
                    <>
                      <Row label="Hash Recorded at Upload" value={verifyResult.original_hash} mono />
                      <Row
                        label="Hash Recomputed Just Now"
                        value={verifyResult.recomputed_hash || ""}
                        mono
                      />
                      <div style={{ display: "flex", gap: 32, marginTop: 16 }}>
                        <StatusLine label="Hash Match" ok={!!verifyResult.hash_match} />
                        <StatusLine label="Signature Valid" ok={!!verifyResult.signature_valid} />
                      </div>
                    </>
                  )}
                </div>
              )}
            </div>
          </div>
        </>
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

function StatusLine({ label, ok }: { label: string; ok: boolean }) {
  return (
    <div style={{ fontSize: 18, fontWeight: 700 }}>
      {label}:{" "}
      <span style={{ color: ok ? "var(--color-status-success)" : "var(--color-status-error)" }}>
        {ok ? "PASS" : "FAIL"}
      </span>
    </div>
  );
}
