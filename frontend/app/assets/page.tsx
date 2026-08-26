"use client";

import { FormEvent, useCallback, useEffect, useState, useSyncExternalStore } from "react";
import AppShell from "@/components/AppShell";
import QrScanner from "@/components/QrScanner";
import {
  Alert,
  Badge,
  CUSTODY_LABELS,
  Card,
  Cell,
  Field,
  Mono,
  PageHeading,
  Table,
} from "@/components/ui";
import { useAuth } from "@/lib/auth-context";
import {
  ApiError,
  Asset,
  CaseSummary,
  TransferRecord,
  fetchAssetByQr,
  fetchAssets,
  fetchCases,
  fetchTransfers,
  registerAsset,
  transferAsset,
} from "@/lib/api";
import { NoSigningKey, signMessage, transferMessage } from "@/lib/crypto";
import { QueuedTransfer, enqueue, readQueue, remove, syncQueue } from "@/lib/offline-queue";

const CUSTODY_STATES = ["police_custody", "forensics_custody", "court_custody", "released"];

export default function AssetsPage() {
  const { user } = useAuth();

  const [cases, setCases] = useState<CaseSummary[]>([]);
  const [caseId, setCaseId] = useState("");
  const [assets, setAssets] = useState<Asset[]>([]);
  const [selected, setSelected] = useState<Asset | null>(null);
  const [transfers, setTransfers] = useState<TransferRecord[]>([]);
  const [queue, setQueue] = useState<QueuedTransfer[]>([]);

  const [itemName, setItemName] = useState("");
  const [category, setCategory] = useState("");

  const [newStatus, setNewStatus] = useState(CUSTODY_STATES[1]);
  const [receivingBadge, setReceivingBadge] = useState("");
  const [transferMfa, setTransferMfa] = useState("");

  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState("");

  const canRegister =
    user?.role === "investigating_officer" || user?.role === "forensics_officer" || user?.role === "admin";

  // Connectivity is a browser fact, not React state.
  const online = useSyncExternalStore(subscribeToConnectivity, () => navigator.onLine, () => true);

  useEffect(() => {
    let cancelled = false;

    void (async () => {
      await Promise.resolve();
      if (!cancelled) setQueue(readQueue());
    })();

    return () => {
      cancelled = true;
    };
  }, []);

  // Coming back online is the moment queued handovers should be attempted.
  useEffect(() => {
    if (!online || queue.length === 0) return;
    void handleSync();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [online]);

  useEffect(() => {
    if (!user) return;
    fetchCases()
      .then((loaded) => {
        setCases(loaded);
        if (loaded.length > 0) setCaseId((current) => current || loaded[0].id);
      })
      .catch((err) => setError(err.message));
  }, [user]);

  const loadAssets = useCallback(async () => {
    if (!caseId) return;
    try {
      setAssets(await fetchAssets(caseId));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not load physical evidence");
    }
  }, [caseId]);

  useEffect(() => {
    if (!caseId) return;
    let cancelled = false;

    void (async () => {
      try {
        const loaded = await fetchAssets(caseId);
        if (!cancelled) setAssets(loaded);
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : "Could not load physical evidence");
        }
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [caseId]);

  async function selectAsset(asset: Asset) {
    setSelected(asset);
    setNewStatus(CUSTODY_STATES.find((state) => state !== asset.custody_status) ?? CUSTODY_STATES[0]);
    try {
      setTransfers(await fetchTransfers(asset.id));
    } catch {
      setTransfers([]);
    }
  }

  async function handleScan(qrUuid: string) {
    setError("");
    try {
      const asset = await fetchAssetByQr(qrUuid);
      await selectAsset(asset);
      setNotice(`Tag resolved to ${asset.item_name}.`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "No asset carries that tag");
    }
  }

  async function submitAsset(event: FormEvent) {
    event.preventDefault();
    setBusy("register");
    setError("");
    setNotice("");
    try {
      const asset = await registerAsset({ case_id: caseId, item_name: itemName, category });
      setNotice(`Registered ${asset.item_name}. Its tag id is ${asset.qr_uuid}.`);
      setItemName("");
      setCategory("");
      await loadAssets();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not register the item");
    } finally {
      setBusy("");
    }
  }

  async function submitTransfer(event: FormEvent) {
    event.preventDefault();
    if (!selected || !user) return;

    setBusy("transfer");
    setError("");
    setNotice("");

    try {
      const message = transferMessage({
        qr_uuid: selected.qr_uuid,
        expected_prior_custody_status: selected.custody_status,
        new_custody_status: newStatus,
        receiving_officer_badge_number: receivingBadge,
      });
      const signature = await signMessage(user.badge_number, message);

      const payload = {
        expected_prior_custody_status: selected.custody_status,
        new_custody_status: newStatus,
        receiving_officer_badge_number: receivingBadge,
        client_signature: signature,
      };

      if (!navigator.onLine) {
        enqueue({
          assetId: selected.id,
          itemName: selected.item_name,
          qrUuid: selected.qr_uuid,
          ...payload,
          mfaCode: transferMfa,
        });
        setQueue(readQueue());
        setNotice(
          "Offline — the signed handover is queued. It will be applied on reconnect, or rejected as a conflict if someone else moved the item first.",
        );
        setReceivingBadge("");
        setTransferMfa("");
        return;
      }

      const updated = await transferAsset(selected.id, payload, transferMfa);
      setSelected(updated);
      setTransfers(await fetchTransfers(updated.id));
      setNotice(`Custody moved to ${CUSTODY_LABELS[updated.custody_status]}.`);
      setReceivingBadge("");
      setTransferMfa("");
      await loadAssets();
    } catch (err) {
      if (err instanceof NoSigningKey) {
        setError("No signing key on this device. Generate one under Security first.");
      } else if (err instanceof ApiError && err.status === 409) {
        setError(err.message);
        await loadAssets();
      } else {
        setError(err instanceof Error ? err.message : "Transfer failed");
      }
    } finally {
      setBusy("");
    }
  }

  async function handleSync() {
    setBusy("sync");
    try {
      const outcome = await syncQueue();
      setQueue(readQueue());
      await loadAssets();
      const parts = [];
      if (outcome.applied) parts.push(`${outcome.applied} applied`);
      if (outcome.conflicts) parts.push(`${outcome.conflicts} in conflict`);
      if (outcome.failed) parts.push(`${outcome.failed} failed`);
      if (parts.length) setNotice(`Queue synced: ${parts.join(", ")}.`);
    } finally {
      setBusy("");
    }
  }

  if (!user) return null;

  return (
    <AppShell>
      <PageHeading
        title="Physical Evidence"
        subtitle="Tagged items and their custody chain. Each handover is signed on the officer's device."
        action={
          <Badge kind={online ? "success" : "warning"}>{online ? "online" : "offline"}</Badge>
        }
      />

      {error && <Alert kind="error">{error}</Alert>}
      {notice && <Alert kind="success">{notice}</Alert>}

      {queue.length > 0 && (
        <Card title={`Queued handovers (${queue.length})`}>
          <p style={{ fontSize: 18, marginBottom: 16 }}>
            Prepared while offline. Each one carries the custody status it expected to find, so a
            late sync cannot overwrite someone else&apos;s handover.
          </p>
          <Table headers={["Item", "To", "Queued", "State", ""]}>
            {queue.map((item) => (
              <tr key={item.id} className="divider">
                <Cell bold>{item.itemName}</Cell>
                <Cell>{CUSTODY_LABELS[item.new_custody_status]}</Cell>
                <Cell>{new Date(item.queuedAt).toLocaleString()}</Cell>
                <Cell>
                  {item.conflict ? (
                    <Badge kind="error">conflict</Badge>
                  ) : item.lastError ? (
                    <Badge kind="warning">retrying</Badge>
                  ) : (
                    <Badge kind="neutral">pending</Badge>
                  )}
                  {item.lastError && (
                    <div style={{ fontSize: 15, marginTop: 6 }}>{item.lastError}</div>
                  )}
                </Cell>
                <Cell>
                  <button
                    className="btn-secondary"
                    style={smallButton}
                    onClick={() => {
                      remove(item.id);
                      setQueue(readQueue());
                    }}
                  >
                    Discard
                  </button>
                </Cell>
              </tr>
            ))}
          </Table>
          <button
            className="btn-primary"
            style={{ marginTop: 24 }}
            onClick={handleSync}
            disabled={busy === "sync" || !online}
          >
            {busy === "sync" ? "Syncing…" : "Sync now"}
          </button>
        </Card>
      )}

      <Card title="Find an item by its tag">
        <QrScanner onScan={handleScan} />
      </Card>

      {cases.length > 0 && (
        <div style={{ marginBottom: 24, maxWidth: 480 }}>
          <label className="label-bold" style={{ display: "block", marginBottom: 8 }}>
            Case
          </label>
          <select className="input-field" value={caseId} onChange={(e) => setCaseId(e.target.value)}>
            {cases.map((item) => (
              <option key={item.id} value={item.id}>
                {item.fir_number} — {item.title}
              </option>
            ))}
          </select>
        </div>
      )}

      {assets.length > 0 && (
        <div style={{ marginBottom: 32 }}>
          <Table headers={["Item", "Category", "Custody", "Custodian", "Tag id", ""]}>
            {assets.map((asset) => (
              <tr key={asset.id} className="divider">
                <Cell bold>{asset.item_name}</Cell>
                <Cell>{asset.category}</Cell>
                <Cell>
                  <Badge kind={asset.custody_status === "released" ? "neutral" : "success"}>
                    {CUSTODY_LABELS[asset.custody_status]}
                  </Badge>
                </Cell>
                <Cell>{asset.current_custodian_badge_number ?? "—"}</Cell>
                <Cell>
                  <Mono truncate={13}>{asset.qr_uuid}</Mono>
                </Cell>
                <Cell>
                  <button className="btn-secondary" style={smallButton} onClick={() => selectAsset(asset)}>
                    Open
                  </button>
                </Cell>
              </tr>
            ))}
          </Table>
        </div>
      )}

      {selected && (
        <Card title={`${selected.item_name} — custody`}>
          <div style={{ marginBottom: 24, fontSize: 18 }}>
            Currently <strong>{CUSTODY_LABELS[selected.custody_status]}</strong> with{" "}
            {selected.current_custodian_badge_number ?? "nobody"}. Tag{" "}
            <Mono>{selected.qr_uuid}</Mono>
          </div>

          {canRegister && (
            <form onSubmit={submitTransfer} style={{ maxWidth: 520, marginBottom: 32 }}>
              <Field label="Move to">
                <select
                  className="input-field"
                  value={newStatus}
                  onChange={(e) => setNewStatus(e.target.value)}
                >
                  {CUSTODY_STATES.filter((state) => state !== selected.custody_status).map((state) => (
                    <option key={state} value={state}>
                      {CUSTODY_LABELS[state]}
                    </option>
                  ))}
                </select>
              </Field>
              <Field label="Receiving officer badge number">
                <input
                  className="input-field"
                  value={receivingBadge}
                  onChange={(e) => setReceivingBadge(e.target.value)}
                  required
                />
              </Field>
              <Field label="Authenticator code" hint="Custody transfer is an MFA-protected action.">
                <input
                  className="input-field data-mono"
                  style={{ maxWidth: 200 }}
                  value={transferMfa}
                  onChange={(e) => setTransferMfa(e.target.value.replace(/\D/g, "").slice(0, 6))}
                  inputMode="numeric"
                />
              </Field>
              <button
                type="submit"
                className="btn-primary"
                disabled={busy === "transfer" || !receivingBadge || transferMfa.length < 6}
              >
                {online ? "Sign and transfer" : "Sign and queue"}
              </button>
            </form>
          )}

          {transfers.length === 0 ? (
            <p style={{ fontSize: 18, color: "var(--color-on-surface-variant)" }}>
              No handovers recorded yet.
            </p>
          ) : (
            <Table headers={["From", "To", "By", "Received by", "Signature", "When"]}>
              {transfers.map((record) => (
                <tr key={record.id} className="divider">
                  <Cell>{CUSTODY_LABELS[record.from_status]}</Cell>
                  <Cell>{CUSTODY_LABELS[record.to_status]}</Cell>
                  <Cell bold>{record.performed_by}</Cell>
                  <Cell>{record.received_by}</Cell>
                  <Cell>
                    <Badge
                      kind={
                        record.signature_valid && record.signing_key_status === "valid"
                          ? "success"
                          : record.signature_valid
                            ? "warning"
                            : "error"
                      }
                    >
                      {record.signature_valid
                        ? record.signing_key_status.replace(/_/g, " ")
                        : "invalid"}
                    </Badge>
                  </Cell>
                  <Cell>{new Date(record.created_at).toLocaleString()}</Cell>
                </tr>
              ))}
            </Table>
          )}
        </Card>
      )}

      {canRegister && cases.length > 0 && (
        <Card title="Register an item">
          <form onSubmit={submitAsset} style={{ maxWidth: 520 }}>
            <Field label="Item name">
              <input
                className="input-field"
                value={itemName}
                onChange={(e) => setItemName(e.target.value)}
                required
              />
            </Field>
            <Field label="Category">
              <input
                className="input-field"
                value={category}
                onChange={(e) => setCategory(e.target.value)}
                required
              />
            </Field>
            <button type="submit" className="btn-primary" disabled={busy === "register"}>
              Register item
            </button>
          </form>
        </Card>
      )}
    </AppShell>
  );
}

const smallButton = { minHeight: 40, padding: "0 16px", fontSize: 16 } as const;

function subscribeToConnectivity(onChange: () => void) {
  window.addEventListener("online", onChange);
  window.addEventListener("offline", onChange);
  return () => {
    window.removeEventListener("online", onChange);
    window.removeEventListener("offline", onChange);
  };
}
