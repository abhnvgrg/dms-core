"use client";

import { FormEvent, useEffect, useState } from "react";
import Link from "next/link";
import AppShell from "@/components/AppShell";
import { Alert, CLASSIFICATION_LABELS, Card, Field, Mono, PageHeading } from "@/components/ui";
import { useAuth } from "@/lib/auth-context";
import { CaseSummary, UploadResponse, fetchCases, uploadEvidence } from "@/lib/api";
import { NoSigningKey, sha256Hex, signMessage } from "@/lib/crypto";

const CLASSIFICATIONS = ["public_redacted", "case_restricted", "court_elevated", "admin_only"];

export default function UploadPage() {
  const { user } = useAuth();

  const [cases, setCases] = useState<CaseSummary[]>([]);
  const [caseId, setCaseId] = useState("");
  const [classification, setClassification] = useState("case_restricted");
  const [file, setFile] = useState<File | null>(null);
  const [stage, setStage] = useState("");
  const [error, setError] = useState("");
  const [result, setResult] = useState<UploadResponse | null>(null);

  useEffect(() => {
    if (!user) return;
    fetchCases()
      .then((loaded) => {
        setCases(loaded);
        if (loaded.length > 0) setCaseId(loaded[0].id);
      })
      .catch((err) => setError(err.message));
  }, [user]);

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    if (!file || !user) return;

    setError("");
    setResult(null);

    try {
      // Hash and sign before the bytes leave the browser: the server is told
      // what was signed and can only verify, never produce, that signature.
      setStage("Hashing file…");
      const sha256 = await sha256Hex(file);

      setStage("Signing with your device key…");
      const signature = await signMessage(user.badge_number, sha256);

      setStage("Uploading…");
      const response = await uploadEvidence({ caseId, file, classification, sha256, signature });
      setResult(response);
      setFile(null);
    } catch (err) {
      if (err instanceof NoSigningKey) {
        setError(
          "No signing key on this device. Generate one under Security — uploads must be signed by the officer, not the server.",
        );
      } else {
        setError(err instanceof Error ? err.message : "Upload failed");
      }
    } finally {
      setStage("");
    }
  }

  return (
    <AppShell>
      <PageHeading
        title="Upload Evidence"
        subtitle="The file is hashed and signed in your browser, scanned for malware, and structurally checked before anything parses it."
      />

      {error && <Alert kind="error">{error}</Alert>}

      {result && (
        <Alert kind="success">
          <div>Uploaded {result.filename} — processing has been queued.</div>
          <div style={{ marginTop: 8, fontWeight: 400 }}>
            SHA-256 <Mono truncate={32}>{result.sha256_hash}</Mono>
          </div>
          <Link
            href={`/evidence/${result.id}`}
            style={{ display: "inline-block", marginTop: 12, color: "var(--color-kinetic-blue)", fontWeight: 700 }}
          >
            Open the record →
          </Link>
        </Alert>
      )}

      {cases.length === 0 ? (
        <Card>
          <p style={{ fontSize: 18 }}>
            You are not assigned to any case yet. Evidence is always filed against a case —
            create one under <Link href="/cases" style={{ color: "var(--color-kinetic-blue)", fontWeight: 700 }}>Cases</Link> first.
          </p>
        </Card>
      ) : (
        <Card>
          <form onSubmit={handleSubmit} style={{ maxWidth: 640 }}>
            <Field label="Case">
              <select className="input-field" value={caseId} onChange={(e) => setCaseId(e.target.value)}>
                {cases.map((item) => (
                  <option key={item.id} value={item.id}>
                    {item.fir_number} — {item.title}
                  </option>
                ))}
              </select>
            </Field>

            <Field
              label="Classification"
              hint="Court Officials need an explicit, time-bound grant to see anything above public."
            >
              <select
                className="input-field"
                value={classification}
                onChange={(e) => setClassification(e.target.value)}
              >
                {CLASSIFICATIONS.map((value) => (
                  <option key={value} value={value}>
                    {CLASSIFICATION_LABELS[value]}
                  </option>
                ))}
              </select>
            </Field>

            <Field label="File" hint="JPEG, PNG or PDF, up to 25 MB.">
              <input
                className="input-field"
                type="file"
                accept="image/jpeg,image/png,application/pdf"
                style={{ padding: 12 }}
                onChange={(e) => setFile(e.target.files?.[0] ?? null)}
                required
              />
            </Field>

            <button type="submit" className="btn-primary" disabled={!file || Boolean(stage)}>
              {stage || "Sign and Upload"}
            </button>
          </form>
        </Card>
      )}
    </AppShell>
  );
}
