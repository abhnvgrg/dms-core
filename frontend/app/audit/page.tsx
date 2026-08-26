"use client";

import { useCallback, useEffect, useState } from "react";
import AppShell from "@/components/AppShell";
import { Alert, Badge, Card, Cell, Field, Mono, PageHeading, Table } from "@/components/ui";
import { useAuth } from "@/lib/auth-context";
import {
  Checkpoint,
  LedgerVerification,
  OnchainVerification,
  createCheckpoint,
  fetchCheckpoints,
  verifyEntryOnchain,
  verifyLedger,
} from "@/lib/api";

export default function AuditPage() {
  const { user } = useAuth();

  const [verification, setVerification] = useState<LedgerVerification | null>(null);
  const [checkpoints, setCheckpoints] = useState<Checkpoint[]>([]);
  const [entryId, setEntryId] = useState("");
  const [onchain, setOnchain] = useState<OnchainVerification | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState("");

  const load = useCallback(async () => {
    setBusy("verify");
    setError("");
    try {
      const [result, points] = await Promise.all([verifyLedger(), fetchCheckpoints()]);
      setVerification(result);
      setCheckpoints(points);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not verify the ledger");
    } finally {
      setBusy("");
    }
  }, []);

  useEffect(() => {
    if (!user) return;
    let cancelled = false;

    void (async () => {
      try {
        const [result, points] = await Promise.all([verifyLedger(), fetchCheckpoints()]);
        if (cancelled) return;
        setVerification(result);
        setCheckpoints(points);
      } catch (err) {
        if (!cancelled) setError(err instanceof Error ? err.message : "Could not verify the ledger");
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [user]);

  async function forceCheckpoint() {
    setBusy("checkpoint");
    setError("");
    try {
      await createCheckpoint();
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not create a checkpoint");
    } finally {
      setBusy("");
    }
  }

  async function checkOnchain() {
    setBusy("onchain");
    setError("");
    setOnchain(null);
    try {
      setOnchain(await verifyEntryOnchain(Number(entryId)));
    } catch (err) {
      setError(err instanceof Error ? err.message : "On-chain check failed");
    } finally {
      setBusy("");
    }
  }

  if (!user) return null;

  const statusKind = (value: string | null | undefined) =>
    value === "VERIFIED" ? "success" : value === "NO_CHECKPOINTS" ? "neutral" : "error";

  return (
    <AppShell>
      <PageHeading
        title="Audit Ledger"
        subtitle="Three independent checks: the in-database hash chain, the signed checkpoints held in write-once storage, and the on-chain anchor."
        action={
          <button className="btn-secondary" onClick={load} disabled={Boolean(busy)}>
            {busy === "verify" ? "Verifying…" : "Re-verify"}
          </button>
        }
      />

      {error && <Alert kind="error">{error}</Alert>}

      {verification && (
        <Card title="Verification">
          <div style={{ marginBottom: 24 }}>
            <Badge kind={statusKind(verification.status)}>{verification.status}</Badge>
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))", gap: 24 }}>
            <div>
              <div className="label-bold">Hash chain</div>
              <div style={{ marginTop: 8 }}>
                <Badge kind={statusKind(verification.chain_status)}>
                  {verification.chain_status ?? "—"}
                </Badge>
              </div>
              <p style={{ fontSize: 16, marginTop: 8, color: "var(--color-on-surface-variant)" }}>
                {verification.entries_checked ?? 0} entries recomputed
                {verification.broken_at_entry_id
                  ? ` — breaks at entry ${verification.broken_at_entry_id}`
                  : ""}
              </p>
            </div>

            <div>
              <div className="label-bold">Signed checkpoints</div>
              <div style={{ marginTop: 8 }}>
                <Badge kind={statusKind(verification.checkpoint_status)}>
                  {verification.checkpoint_status ?? "—"}
                </Badge>
              </div>
              <p style={{ fontSize: 16, marginTop: 8, color: "var(--color-on-surface-variant)" }}>
                {verification.checkpoints_checked ?? 0} checkpoints covering{" "}
                {verification.entries_covered_by_checkpoints ?? 0} entries,{" "}
                {verification.mirrored_to_write_once_store ?? 0} mirrored to write-once storage
                {verification.broken_at_checkpoint_id
                  ? ` — breaks at checkpoint ${verification.broken_at_checkpoint_id}`
                  : ""}
              </p>
            </div>
          </div>

          {verification.reason && (
            <p style={{ fontSize: 18, marginTop: 16, fontWeight: 600 }}>{verification.reason}</p>
          )}

          <p style={{ fontSize: 16, marginTop: 24, color: "var(--color-on-surface-variant)" }}>
            A rewrite that repairs every downstream hash still passes the chain check and fails
            the checkpoint check, because the checkpoint signature was made with a key the
            database never holds.
          </p>
        </Card>
      )}

      <Card title="Checkpoints">
        <button
          className="btn-secondary"
          onClick={forceCheckpoint}
          disabled={busy === "checkpoint"}
          style={{ marginBottom: 24 }}
        >
          {busy === "checkpoint" ? "Signing…" : "Checkpoint now"}
        </button>

        {checkpoints.length === 0 ? (
          <p style={{ fontSize: 18, color: "var(--color-on-surface-variant)" }}>
            No checkpoints yet — the scheduled job signs one every five minutes.
          </p>
        ) : (
          <Table headers={["#", "Entries", "Checkpoint hash", "Key", "Mirrored", "Created"]}>
            {checkpoints.map((checkpoint) => (
              <tr key={checkpoint.id} className="divider">
                <Cell>{checkpoint.id}</Cell>
                <Cell>
                  {checkpoint.from_entry_id}–{checkpoint.to_entry_id} ({checkpoint.entry_count})
                </Cell>
                <Cell>
                  <Mono truncate={20}>{checkpoint.checkpoint_hash}</Mono>
                </Cell>
                <Cell>v{checkpoint.signing_key_version}</Cell>
                <Cell>
                  {checkpoint.object_key ? (
                    <Badge kind="success">stored</Badge>
                  ) : (
                    <Badge kind="warning">db only</Badge>
                  )}
                </Cell>
                <Cell>{new Date(checkpoint.created_at).toLocaleString()}</Cell>
              </tr>
            ))}
          </Table>
        )}
      </Card>

      <Card title="On-chain anchor">
        <div style={{ maxWidth: 420 }}>
          <Field label="Ledger entry id">
            <input
              className="input-field data-mono"
              value={entryId}
              onChange={(e) => setEntryId(e.target.value.replace(/\D/g, ""))}
              inputMode="numeric"
            />
          </Field>
          <button className="btn-primary" onClick={checkOnchain} disabled={!entryId || busy === "onchain"}>
            {busy === "onchain" ? "Checking…" : "Compare with chain"}
          </button>
        </div>

        {onchain && (
          <div style={{ marginTop: 24 }}>
            <Badge kind={onchain.status === "VERIFIED" ? "success" : onchain.status === "TAMPERED" ? "error" : "neutral"}>
              {onchain.status}
            </Badge>
            <div style={{ marginTop: 12, fontSize: 16 }}>
              <div>
                Database <Mono truncate={32}>{onchain.db_entry_hash}</Mono>
              </div>
              <div>
                On chain <Mono truncate={32}>{onchain.onchain_entry_hash}</Mono>
              </div>
            </div>
          </div>
        )}
      </Card>
    </AppShell>
  );
}
