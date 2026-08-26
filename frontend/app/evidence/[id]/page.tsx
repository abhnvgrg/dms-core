"use client";

import { useCallback, useEffect, useState, use as usePromise } from "react";
import AppShell from "@/components/AppShell";
import {
  Alert,
  Badge,
  CLASSIFICATION_LABELS,
  Card,
  Cell,
  Field,
  Mono,
  PageHeading,
  Table,
  classificationKind,
} from "@/components/ui";
import { useAuth } from "@/lib/auth-context";
import {
  AccessGrant,
  AuditEntry,
  EvidenceDetail,
  VerifyResponse,
  createAccessGrant,
  downloadEvidence,
  fetchAccessGrants,
  fetchEntityAudit,
  fetchEvidenceDetail,
  reclassifyDocument,
  revokeAccessGrant,
  verifyEvidence,
} from "@/lib/api";

const CLASSIFICATIONS = ["public_redacted", "case_restricted", "court_elevated", "admin_only"];

export default function EvidenceDetailPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = usePromise(params);
  const { user } = useAuth();

  const [record, setRecord] = useState<EvidenceDetail | null>(null);
  const [grants, setGrants] = useState<AccessGrant[]>([]);
  const [trail, setTrail] = useState<AuditEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [verifyResult, setVerifyResult] = useState<VerifyResponse | null>(null);
  const [busy, setBusy] = useState("");

  const [grantBadge, setGrantBadge] = useState("");
  const [grantReason, setGrantReason] = useState("");
  const [grantHours, setGrantHours] = useState(24);
  const [grantMfa, setGrantMfa] = useState("");

  const [newClassification, setNewClassification] = useState("");
  const [classifyMfa, setClassifyMfa] = useState("");

  const canManage = user?.role === "investigating_officer" || user?.role === "admin";

  const load = useCallback(async () => {
    try {
      const detail = await fetchEvidenceDetail(id);
      setRecord(detail);
      setNewClassification(detail.classification);

      const [trailData, grantData] = await Promise.all([
        fetchEntityAudit("document", id).catch(() => [] as AuditEntry[]),
        canManage ? fetchAccessGrants(id).catch(() => [] as AccessGrant[]) : Promise.resolve([]),
      ]);
      setTrail(trailData);
      setGrants(grantData);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not load the record");
    } finally {
      setLoading(false);
    }
  }, [id, canManage]);

  useEffect(() => {
    if (!user) return;
    let cancelled = false;

    void (async () => {
      try {
        const detail = await fetchEvidenceDetail(id);
        if (cancelled) return;
        setRecord(detail);
        setNewClassification(detail.classification);

        const [trailData, grantData] = await Promise.all([
          fetchEntityAudit("document", id).catch(() => [] as AuditEntry[]),
          canManage ? fetchAccessGrants(id).catch(() => [] as AccessGrant[]) : Promise.resolve([]),
        ]);
        if (cancelled) return;
        setTrail(trailData);
        setGrants(grantData);
      } catch (err) {
        if (!cancelled) setError(err instanceof Error ? err.message : "Could not load the record");
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [user, id, canManage]);

  async function runVerify() {
    setBusy("verify");
    setError("");
    try {
      setVerifyResult(await verifyEvidence(id));
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Verification failed");
    } finally {
      setBusy("");
    }
  }

  async function runDownload() {
    if (!record) return;
    setBusy("download");
    setError("");
    try {
      await downloadEvidence(id, record.filename);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Download failed");
    } finally {
      setBusy("");
    }
  }

  async function submitGrant() {
    setBusy("grant");
    setError("");
    setNotice("");
    try {
      await createAccessGrant(
        id,
        { grantee_badge_number: grantBadge, reason: grantReason, duration_hours: grantHours },
        grantMfa,
      );
      setGrantBadge("");
      setGrantReason("");
      setGrantMfa("");
      setNotice("Access granted. It expires on its own and the grant itself is in the ledger.");
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not create the grant");
    } finally {
      setBusy("");
    }
  }

  async function revoke(grantId: string) {
    const code = window.prompt("Authenticator code (revoking access is an MFA-protected action)");
    if (!code) return;
    setBusy("revoke");
    setError("");
    try {
      await revokeAccessGrant(id, grantId, code);
      setNotice("Grant revoked.");
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not revoke the grant");
    } finally {
      setBusy("");
    }
  }

  async function submitReclassify() {
    setBusy("classify");
    setError("");
    setNotice("");
    try {
      await reclassifyDocument(id, newClassification, classifyMfa);
      setClassifyMfa("");
      setNotice("Classification changed and recorded.");
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not change classification");
    } finally {
      setBusy("");
    }
  }

  if (!user) return null;
  if (loading) {
    return (
      <AppShell>
        <p style={{ fontSize: 18 }}>Loading record…</p>
      </AppShell>
    );
  }
  if (!record) {
    return (
      <AppShell>
        <Alert kind="error">{error || "Record not found"}</Alert>
      </AppShell>
    );
  }

  const integrityKind =
    verifyResult?.integrity === "VERIFIED"
      ? "success"
      : verifyResult?.integrity === "PENDING_REVIEW"
        ? "warning"
        : "error";

  return (
    <AppShell>
      <PageHeading title={record.filename} subtitle={`Case ${record.case_id}`} />

      {error && <Alert kind="error">{error}</Alert>}
      {notice && <Alert kind="success">{notice}</Alert>}

      <Card title="Record">
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", gap: 24 }}>
          <div>
            <div className="label-bold">Classification</div>
            <div style={{ marginTop: 8 }}>
              <Badge kind={classificationKind(record.classification)}>
                {CLASSIFICATION_LABELS[record.classification] ?? record.classification}
              </Badge>
            </div>
          </div>
          <div>
            <div className="label-bold">Uploaded by</div>
            <div style={{ marginTop: 8, fontSize: 18 }}>{record.uploaded_by}</div>
          </div>
          <div>
            <div className="label-bold">Uploaded at</div>
            <div style={{ marginTop: 8, fontSize: 18 }}>
              {new Date(record.uploaded_at).toLocaleString()}
            </div>
          </div>
          <div>
            <div className="label-bold">SHA-256</div>
            <div style={{ marginTop: 8 }}>
              <Mono truncate={32}>{record.sha256_hash}</Mono>
            </div>
          </div>
          <div>
            <div className="label-bold">Officer signature</div>
            <div style={{ marginTop: 8 }}>
              <Mono truncate={32}>{record.signature}</Mono>
            </div>
          </div>
        </div>

        <div className="flex gap-4" style={{ marginTop: 24 }}>
          <button className="btn-primary" onClick={runVerify} disabled={busy === "verify"}>
            {busy === "verify" ? "Verifying…" : "Verify integrity"}
          </button>
          <button className="btn-secondary" onClick={runDownload} disabled={busy === "download"}>
            {busy === "download" ? "Downloading…" : "Download"}
          </button>
        </div>

        {verifyResult && (
          <div style={{ marginTop: 24 }}>
            <Badge kind={integrityKind}>{verifyResult.integrity}</Badge>
            <div style={{ marginTop: 12, fontSize: 18 }}>
              <div>Stored hash matches the bytes in object storage: {String(verifyResult.hash_match)}</div>
              <div>Signature verifies: {String(verifyResult.signature_valid)}</div>
              {verifyResult.signed_by && <div>Signed by {verifyResult.signed_by}</div>}
              {verifyResult.signing_key_status && (
                <div>Signing key: {verifyResult.signing_key_status.replace(/_/g, " ")}</div>
              )}
              {verifyResult.reason && <div>{verifyResult.reason}</div>}
            </div>
          </div>
        )}
      </Card>

      {(record.redacted_text || record.extracted_text) && (
        <Card title="Extracted text">
          <div style={{ display: "grid", gridTemplateColumns: record.extracted_text ? "1fr 1fr" : "1fr", gap: 24 }}>
            <div>
              <div className="label-bold" style={{ marginBottom: 8 }}>
                Redacted
              </div>
              <pre
                style={{
                  whiteSpace: "pre-wrap",
                  fontSize: 16,
                  background: "var(--color-surface-container-low)",
                  padding: 16,
                  border: "2px solid var(--color-border-heavy)",
                  maxHeight: 320,
                  overflowY: "auto",
                }}
              >
                {record.redacted_text || "—"}
              </pre>
            </div>
            {record.extracted_text && (
              <div>
                <div className="label-bold" style={{ marginBottom: 8 }}>
                  Original
                </div>
                <pre
                  style={{
                    whiteSpace: "pre-wrap",
                    fontSize: 16,
                    background: "var(--color-surface-container-low)",
                    padding: 16,
                    border: "2px solid var(--color-border-heavy)",
                    maxHeight: 320,
                    overflowY: "auto",
                  }}
                >
                  {record.extracted_text}
                </pre>
              </div>
            )}
          </div>
        </Card>
      )}

      {canManage && (
        <>
          <Card title="Classification">
            <div style={{ maxWidth: 520 }}>
              <Field label="Level">
                <select
                  className="input-field"
                  value={newClassification}
                  onChange={(e) => setNewClassification(e.target.value)}
                >
                  {CLASSIFICATIONS.map((value) => (
                    <option key={value} value={value}>
                      {CLASSIFICATION_LABELS[value]}
                    </option>
                  ))}
                </select>
              </Field>
              <Field label="Authenticator code">
                <input
                  className="input-field data-mono"
                  style={{ maxWidth: 200 }}
                  value={classifyMfa}
                  onChange={(e) => setClassifyMfa(e.target.value.replace(/\D/g, "").slice(0, 6))}
                  inputMode="numeric"
                />
              </Field>
              <button
                className="btn-primary"
                onClick={submitReclassify}
                disabled={busy === "classify" || newClassification === record.classification || classifyMfa.length < 6}
              >
                Change classification
              </button>
            </div>
          </Card>

          <Card title="Access grants">
            <p style={{ fontSize: 18, marginBottom: 24 }}>
              A Court Official never gets unredacted content from their role alone. Each grant is
              time-bound, revocable, and appears in the ledger.
            </p>

            <div style={{ maxWidth: 520, marginBottom: 32 }}>
              <Field label="Grantee badge number">
                <input
                  className="input-field"
                  value={grantBadge}
                  onChange={(e) => setGrantBadge(e.target.value)}
                />
              </Field>
              <Field label="Reason" hint="Required, and stored with the grant.">
                <input
                  className="input-field"
                  value={grantReason}
                  onChange={(e) => setGrantReason(e.target.value)}
                />
              </Field>
              <Field label="Duration (hours)" hint="Maximum 72.">
                <input
                  className="input-field"
                  type="number"
                  min={1}
                  max={72}
                  value={grantHours}
                  onChange={(e) => setGrantHours(Number(e.target.value))}
                  style={{ maxWidth: 160 }}
                />
              </Field>
              <Field label="Authenticator code">
                <input
                  className="input-field data-mono"
                  style={{ maxWidth: 200 }}
                  value={grantMfa}
                  onChange={(e) => setGrantMfa(e.target.value.replace(/\D/g, "").slice(0, 6))}
                  inputMode="numeric"
                />
              </Field>
              <button
                className="btn-primary"
                onClick={submitGrant}
                disabled={busy === "grant" || !grantBadge || !grantReason || grantMfa.length < 6}
              >
                Grant access
              </button>
            </div>

            {grants.length === 0 ? (
              <p style={{ fontSize: 18, color: "var(--color-on-surface-variant)" }}>No grants yet.</p>
            ) : (
              <Table headers={["Grantee", "Granted by", "Reason", "Expires", "State", ""]}>
                {grants.map((grant) => {
                  const expired = new Date(grant.expires_at) < new Date();
                  const inactive = Boolean(grant.revoked_at) || expired;
                  return (
                    <tr key={grant.id} className="divider">
                      <Cell bold>{grant.grantee_badge_number}</Cell>
                      <Cell>{grant.granted_by_badge_number}</Cell>
                      <Cell>{grant.reason}</Cell>
                      <Cell>{new Date(grant.expires_at).toLocaleString()}</Cell>
                      <Cell>
                        <Badge kind={inactive ? "neutral" : "success"}>
                          {grant.revoked_at ? "revoked" : expired ? "expired" : "active"}
                        </Badge>
                      </Cell>
                      <Cell>
                        {!inactive && (
                          <button
                            className="btn-secondary"
                            style={{ minHeight: 40, padding: "0 20px", fontSize: 16 }}
                            onClick={() => revoke(grant.id)}
                            disabled={busy === "revoke"}
                          >
                            Revoke
                          </button>
                        )}
                      </Cell>
                    </tr>
                  );
                })}
              </Table>
            )}
          </Card>
        </>
      )}

      <Card title="Custody record">
        {trail.length === 0 ? (
          <p style={{ fontSize: 18, color: "var(--color-on-surface-variant)" }}>
            No ledger entries visible for this document.
          </p>
        ) : (
          <Table headers={["#", "Action", "When", "Entry hash", "Anchored"]}>
            {trail.map((entry) => (
              <tr key={entry.id} className="divider">
                <Cell>{entry.id}</Cell>
                <Cell bold>{entry.action_type.replace(/_/g, " ")}</Cell>
                <Cell>{new Date(entry.created_at).toLocaleString()}</Cell>
                <Cell>
                  <Mono truncate={16}>{entry.entry_hash}</Mono>
                </Cell>
                <Cell>
                  {entry.chain_tx_hash ? (
                    <Badge kind="success">block {entry.chain_block_number}</Badge>
                  ) : (
                    <Badge kind="neutral">pending</Badge>
                  )}
                </Cell>
              </tr>
            ))}
          </Table>
        )}
      </Card>
    </AppShell>
  );
}
