"use client";

import { useCallback, useEffect, useState } from "react";
import AppShell from "@/components/AppShell";
import { Alert, Badge, Card, Cell, Field, Mono, PageHeading, Table } from "@/components/ui";
import { useAuth } from "@/lib/auth-context";
import {
  SigningKey,
  activateMfa,
  enrollMfa,
  fetchSigningKeys,
  logoutEverywhere,
  registerSigningKey,
} from "@/lib/api";
import { cryptoAvailable, forgetLocalKey, generateKeypair, hasLocalKey } from "@/lib/crypto";

export default function SecurityPage() {
  const { user, refreshUser, signIn, signOut } = useAuth();

  const [keys, setKeys] = useState<SigningKey[]>([]);
  const [localKey, setLocalKey] = useState<boolean | null>(null);
  const [secret, setSecret] = useState<string | null>(null);
  const [provisioningUri, setProvisioningUri] = useState<string | null>(null);
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  const reload = useCallback(async () => {
    if (!user || user.mfa_enrollment_required) return;
    try {
      setKeys(await fetchSigningKeys());
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not load signing keys");
    }
  }, [user]);

  useEffect(() => {
    if (!user || user.mfa_enrollment_required) return;
    let cancelled = false;

    void (async () => {
      try {
        const loaded = await fetchSigningKeys();
        if (!cancelled) setKeys(loaded);
      } catch (err) {
        if (!cancelled) setError(err instanceof Error ? err.message : "Could not load signing keys");
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [user]);

  useEffect(() => {
    if (!user) return;
    let cancelled = false;

    void hasLocalKey(user.badge_number).then((present) => {
      if (!cancelled) setLocalKey(present);
    });

    return () => {
      cancelled = true;
    };
  }, [user]);

  if (!user) return null;

  async function startEnrollment() {
    setError("");
    setBusy(true);
    try {
      const response = await enrollMfa();
      setSecret(response.secret);
      setProvisioningUri(response.provisioning_uri);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not start enrollment");
    } finally {
      setBusy(false);
    }
  }

  async function confirmEnrollment() {
    setError("");
    setBusy(true);
    try {
      // Enrollment raises this account's privileges, so the server retires the
      // token it was issued at the lower level and hands back a new session.
      signIn(await activateMfa(code));
      setSecret(null);
      setProvisioningUri(null);
      setCode("");
      setNotice("Multi-factor authentication is active on this account.");
      await refreshUser();
      await reload();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not activate MFA");
    } finally {
      setBusy(false);
    }
  }

  async function createSigningKey() {
    setError("");
    setNotice("");
    if (!cryptoAvailable()) {
      setError("This browser does not expose WebCrypto or IndexedDB, so a signing key cannot be held here.");
      return;
    }

    setBusy(true);
    try {
      const pem = await generateKeypair(user!.badge_number);
      await registerSigningKey(pem);
      setLocalKey(true);
      setNotice(
        "Keypair generated in this browser. The private key stays on this device; only the public half was sent.",
      );
      await refreshUser();
      await reload();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not register the signing key");
    } finally {
      setBusy(false);
    }
  }

  async function dropLocalKey() {
    await forgetLocalKey(user!.badge_number);
    setLocalKey(false);
    setNotice("Private key removed from this device. Signatures made with it still verify.");
  }

  const activeKey = keys.find((key) => key.status === "active");
  const localMissingForActive = activeKey && localKey === false;

  return (
    <AppShell>
      <PageHeading
        title="Security"
        subtitle="Your second factor and the signing key that makes your uploads attributable to you."
      />

      {error && <Alert kind="error">{error}</Alert>}
      {notice && <Alert kind="success">{notice}</Alert>}

      {user.mfa_enrollment_required && (
        <Alert kind="error">
          Administrator accounts cannot be used until multi-factor authentication is enrolled.
          Everything else stays locked until you finish the steps below.
        </Alert>
      )}

      <Card title="Multi-factor authentication">
        {user.mfa_enabled ? (
          <div className="flex items-center gap-4">
            <Badge kind="success">Enabled</Badge>
            <span style={{ fontSize: 18 }}>
              A fresh code is required for access grants, reclassification, custody transfers,
              user management and key rotation.
            </span>
          </div>
        ) : secret ? (
          <>
            <p style={{ fontSize: 18, marginBottom: 16 }}>
              Add this secret to your authenticator app, then enter the current code to confirm.
            </p>
            <Field label="Secret">
              <div className="data-mono" style={{ wordBreak: "break-all" }}>{secret}</div>
            </Field>
            {provisioningUri && (
              <Field label="Provisioning URI">
                <div className="data-mono" style={{ fontSize: 14, wordBreak: "break-all" }}>
                  {provisioningUri}
                </div>
              </Field>
            )}
            <Field label="Current code">
              <input
                className="input-field data-mono"
                style={{ maxWidth: 200 }}
                value={code}
                onChange={(e) => setCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
                inputMode="numeric"
              />
            </Field>
            <button className="btn-primary" onClick={confirmEnrollment} disabled={busy || code.length < 6}>
              Activate
            </button>
          </>
        ) : (
          <>
            <p style={{ fontSize: 18, marginBottom: 16 }}>
              Not enrolled. Actions with legal consequence are refused without it — being
              un-enrolled is not a way around the check.
            </p>
            <button className="btn-primary" onClick={startEnrollment} disabled={busy}>
              Set up authenticator
            </button>
          </>
        )}
      </Card>

      <Card title="Signing key">
        <p style={{ fontSize: 18, marginBottom: 16 }}>
          Generated in this browser and held in device storage as a non-extractable key. The
          private half never reaches the server, which is what makes a signature attributable to
          you rather than to the backend.
        </p>

        {localMissingForActive && (
          <Alert kind="error">
            Your account has an active key registered, but its private half is not on this
            device. Generate a new keypair here — the old public key is retired, not deleted, so
            documents signed with it still verify.
          </Alert>
        )}

        <div className="flex items-center gap-4" style={{ marginBottom: 24 }}>
          <button className="btn-primary" onClick={createSigningKey} disabled={busy}>
            {activeKey ? "Rotate signing key" : "Generate signing key"}
          </button>
          {localKey && (
            <button className="btn-secondary" onClick={dropLocalKey} disabled={busy}>
              Forget key on this device
            </button>
          )}
        </div>

        {keys.length === 0 ? (
          <p style={{ fontSize: 18, color: "var(--color-on-surface-variant)" }}>
            No keys registered yet.
          </p>
        ) : (
          <Table headers={["Fingerprint", "Status", "Registered", "Retired", "Revoked"]}>
            {keys.map((key) => (
              <tr key={key.id} className="divider">
                <Cell>
                  <Mono truncate={24}>{key.fingerprint}</Mono>
                </Cell>
                <Cell>
                  <Badge
                    kind={
                      key.status === "active"
                        ? "success"
                        : key.status === "revoked"
                          ? "error"
                          : "neutral"
                    }
                  >
                    {key.status}
                  </Badge>
                </Cell>
                <Cell>{new Date(key.created_at).toLocaleString()}</Cell>
                <Cell>{key.retired_at ? new Date(key.retired_at).toLocaleString() : "—"}</Cell>
                <Cell>{key.revoked_at ? new Date(key.revoked_at).toLocaleString() : "—"}</Cell>
              </tr>
            ))}
          </Table>
        )}
      </Card>

      <Card title="Sessions">
        <p style={{ fontSize: 18, marginBottom: 16 }}>
          Session tokens are opaque and stored server-side by hash, so revoking one takes effect
          on the very next request.
        </p>
        <button
          className="btn-secondary"
          onClick={async () => {
            await logoutEverywhere();
            signOut();
          }}
        >
          Sign out of every device
        </button>
      </Card>
    </AppShell>
  );
}
