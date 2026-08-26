"use client";

import { FormEvent, useCallback, useEffect, useState } from "react";
import AppShell from "@/components/AppShell";
import { Alert, Badge, Card, Cell, Field, Mono, PageHeading, Table } from "@/components/ui";
import { ROLE_LABELS, useAuth } from "@/lib/auth-context";
import {
  AdminUser,
  EncryptionKeyInfo,
  RetentionPolicy,
  createUser,
  fetchEncryptionKeys,
  fetchRetentionPolicy,
  fetchUserSigningKeys,
  fetchUsers,
  purgeNow,
  revokeUserSigningKey,
  rotateEncryptionKey,
  updateRetentionPolicy,
  updateUser,
} from "@/lib/api";

const ROLES = ["investigating_officer", "forensics_officer", "court_official", "admin"];

interface OfficerKey {
  id: string;
  fingerprint: string;
  status: string;
  created_at: string;
  revoked_at: string | null;
}

export default function AdminPage() {
  const { user } = useAuth();

  const [users, setUsers] = useState<AdminUser[]>([]);
  const [keys, setKeys] = useState<EncryptionKeyInfo[]>([]);
  const [policy, setPolicy] = useState<RetentionPolicy | null>(null);
  const [officerKeys, setOfficerKeys] = useState<Record<string, OfficerKey[]>>({});

  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState("");

  const [mfaCode, setMfaCode] = useState("");
  const [badgeNumber, setBadgeNumber] = useState("");
  const [fullName, setFullName] = useState("");
  const [role, setRole] = useState(ROLES[0]);
  const [password, setPassword] = useState("");
  const [retentionMinutes, setRetentionMinutes] = useState(0);

  const load = useCallback(async () => {
    try {
      const [userList, keyList, currentPolicy] = await Promise.all([
        fetchUsers(),
        fetchEncryptionKeys(),
        fetchRetentionPolicy(),
      ]);
      setUsers(userList);
      setKeys(keyList);
      setPolicy(currentPolicy);
      setRetentionMinutes(currentPolicy.retention_minutes);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not load administration data");
    }
  }, []);

  useEffect(() => {
    if (!user) return;
    let cancelled = false;

    void (async () => {
      try {
        const [userList, keyList, currentPolicy] = await Promise.all([
          fetchUsers(),
          fetchEncryptionKeys(),
          fetchRetentionPolicy(),
        ]);
        if (cancelled) return;
        setUsers(userList);
        setKeys(keyList);
        setPolicy(currentPolicy);
        setRetentionMinutes(currentPolicy.retention_minutes);
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : "Could not load administration data");
        }
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [user]);

  function requireCode(): string | null {
    if (mfaCode.length < 6) {
      setError("Enter a current authenticator code first — these actions require step-up MFA.");
      return null;
    }
    return mfaCode;
  }

  async function submitUser(event: FormEvent) {
    event.preventDefault();
    const code = requireCode();
    if (!code) return;

    setBusy("user");
    setError("");
    setNotice("");
    try {
      await createUser({ badge_number: badgeNumber, full_name: fullName, role, password }, code);
      setNotice(`Created ${badgeNumber}.`);
      setBadgeNumber("");
      setFullName("");
      setPassword("");
      setMfaCode("");
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not create the user");
    } finally {
      setBusy("");
    }
  }

  async function changeRole(target: AdminUser, nextRole: string) {
    const code = requireCode();
    if (!code) return;

    setBusy(target.id);
    setError("");
    try {
      await updateUser(target.id, { role: nextRole }, code);
      setNotice(`${target.badge_number} is now ${ROLE_LABELS[nextRole]}. Their sessions were revoked.`);
      setMfaCode("");
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not change the role");
    } finally {
      setBusy("");
    }
  }

  async function toggleActive(target: AdminUser) {
    const code = requireCode();
    if (!code) return;

    setBusy(target.id);
    setError("");
    try {
      await updateUser(target.id, { is_active: !target.is_active }, code);
      setNotice(`${target.badge_number} ${target.is_active ? "deactivated" : "reactivated"}.`);
      setMfaCode("");
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not update the user");
    } finally {
      setBusy("");
    }
  }

  async function showKeys(target: AdminUser) {
    try {
      const loaded = await fetchUserSigningKeys(target.id);
      setOfficerKeys((previous) => ({ ...previous, [target.id]: loaded }));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not load that officer's keys");
    }
  }

  async function revokeKey(keyId: string, targetId: string) {
    const code = requireCode();
    if (!code) return;

    setBusy(keyId);
    setError("");
    try {
      await revokeUserSigningKey(keyId, code);
      setNotice(
        "Key revoked. Signatures made before the revocation stay valid; later ones are flagged for review.",
      );
      setMfaCode("");
      const loaded = await fetchUserSigningKeys(targetId);
      setOfficerKeys((previous) => ({ ...previous, [targetId]: loaded }));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not revoke the key");
    } finally {
      setBusy("");
    }
  }

  async function rotate(purpose: string) {
    const code = requireCode();
    if (!code) return;

    setBusy(purpose);
    setError("");
    try {
      const result = await rotateEncryptionKey(purpose, code);
      setNotice(`${purpose} is now at version ${result.active_version}. History was not re-encrypted.`);
      setMfaCode("");
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not rotate the key");
    } finally {
      setBusy("");
    }
  }

  async function saveRetention(event: FormEvent) {
    event.preventDefault();
    setBusy("retention");
    setError("");
    try {
      const updated = await updateRetentionPolicy(retentionMinutes);
      setPolicy(updated);
      setNotice("Retention window updated. It takes effect on the next sweep, no restart needed.");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not update retention");
    } finally {
      setBusy("");
    }
  }

  async function runPurge() {
    setBusy("purge");
    setError("");
    try {
      const result = await purgeNow();
      setNotice(`Purged ${result.purged_count} document(s) past the ${result.retention_minutes} minute window.`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not run the purge");
    } finally {
      setBusy("");
    }
  }

  if (!user) return null;

  return (
    <AppShell>
      <PageHeading
        title="Administration"
        subtitle="Accounts, key custody and retention. Every action here needs a fresh authenticator code."
      />

      {error && <Alert kind="error">{error}</Alert>}
      {notice && <Alert kind="success">{notice}</Alert>}

      <Card title="Step-up code">
        <div style={{ maxWidth: 260 }}>
          <Field label="Authenticator code" hint="Used for the next action, then cleared.">
            <input
              className="input-field data-mono"
              value={mfaCode}
              onChange={(e) => setMfaCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
              inputMode="numeric"
            />
          </Field>
        </div>
      </Card>

      <Card title="Officers">
        <Table headers={["Badge", "Name", "Role", "MFA", "State", ""]}>
          {users.map((target) => (
            <tr key={target.id} className="divider">
              <Cell bold>{target.badge_number}</Cell>
              <Cell>{target.full_name}</Cell>
              <Cell>
                <select
                  className="input-field"
                  style={{ minHeight: 40, fontSize: 16, maxWidth: 240 }}
                  value={target.role}
                  onChange={(e) => changeRole(target, e.target.value)}
                  disabled={busy === target.id}
                >
                  {ROLES.map((value) => (
                    <option key={value} value={value}>
                      {ROLE_LABELS[value]}
                    </option>
                  ))}
                </select>
              </Cell>
              <Cell>
                <Badge kind={target.mfa_enabled ? "success" : "warning"}>
                  {target.mfa_enabled ? "enrolled" : "none"}
                </Badge>
              </Cell>
              <Cell>
                <Badge kind={target.is_active ? "success" : "neutral"}>
                  {target.is_active ? "active" : "disabled"}
                </Badge>
              </Cell>
              <Cell>
                <div className="flex gap-2">
                  <button
                    className="btn-secondary"
                    style={smallButton}
                    onClick={() => toggleActive(target)}
                    disabled={busy === target.id}
                  >
                    {target.is_active ? "Deactivate" : "Reactivate"}
                  </button>
                  <button className="btn-secondary" style={smallButton} onClick={() => showKeys(target)}>
                    Keys
                  </button>
                </div>
                {officerKeys[target.id] && (
                  <div style={{ marginTop: 12 }}>
                    {officerKeys[target.id].length === 0 ? (
                      <span style={{ fontSize: 16, color: "var(--color-outline)" }}>
                        No signing keys registered.
                      </span>
                    ) : (
                      officerKeys[target.id].map((key) => (
                        <div
                          key={key.id}
                          className="flex items-center gap-3"
                          style={{ marginBottom: 8, fontSize: 16 }}
                        >
                          <Mono truncate={16}>{key.fingerprint}</Mono>
                          <Badge kind={key.status === "active" ? "success" : key.status === "revoked" ? "error" : "neutral"}>
                            {key.status}
                          </Badge>
                          {key.status !== "revoked" && (
                            <button
                              className="btn-secondary"
                              style={smallButton}
                              onClick={() => revokeKey(key.id, target.id)}
                              disabled={busy === key.id}
                            >
                              Revoke
                            </button>
                          )}
                        </div>
                      ))
                    )}
                  </div>
                )}
              </Cell>
            </tr>
          ))}
        </Table>
      </Card>

      <Card title="Add an officer">
        <form onSubmit={submitUser} style={{ maxWidth: 560 }}>
          <Field label="Badge number">
            <input
              className="input-field"
              value={badgeNumber}
              onChange={(e) => setBadgeNumber(e.target.value)}
              required
            />
          </Field>
          <Field label="Full name">
            <input
              className="input-field"
              value={fullName}
              onChange={(e) => setFullName(e.target.value)}
              required
            />
          </Field>
          <Field label="Role">
            <select className="input-field" value={role} onChange={(e) => setRole(e.target.value)}>
              {ROLES.map((value) => (
                <option key={value} value={value}>
                  {ROLE_LABELS[value]}
                </option>
              ))}
            </select>
          </Field>
          <Field label="Initial password" hint="At least 12 characters. Stored as an Argon2id hash.">
            <input
              className="input-field"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              minLength={12}
              required
            />
          </Field>
          <button type="submit" className="btn-primary" disabled={busy === "user"}>
            Create officer
          </button>
        </form>
      </Card>

      <Card title="Encryption keys">
        <p style={{ fontSize: 18, marginBottom: 24 }}>
          Each key is wrapped under the root key rather than stored raw. Rotation issues a new
          version without re-encrypting history, so old data still decrypts under the version it
          was written with.
        </p>
        <Table headers={["Purpose", "Version", "State", "Created", "Rotated", ""]}>
          {keys.map((key) => (
            <tr key={`${key.purpose}-${key.version}`} className="divider">
              <Cell bold>{key.purpose.replace(/_/g, " ")}</Cell>
              <Cell>v{key.version}</Cell>
              <Cell>
                <Badge kind={key.is_active ? "success" : "neutral"}>
                  {key.is_active ? "active" : "superseded"}
                </Badge>
              </Cell>
              <Cell>{new Date(key.created_at).toLocaleString()}</Cell>
              <Cell>{key.rotated_at ? new Date(key.rotated_at).toLocaleString() : "—"}</Cell>
              <Cell>
                {key.is_active && (
                  <button
                    className="btn-secondary"
                    style={smallButton}
                    onClick={() => rotate(key.purpose)}
                    disabled={busy === key.purpose}
                  >
                    Rotate
                  </button>
                )}
              </Cell>
            </tr>
          ))}
        </Table>
      </Card>

      <Card title="Retention">
        <form onSubmit={saveRetention} style={{ maxWidth: 420 }}>
          <Field
            label="Retention window (minutes)"
            hint={
              policy
                ? `Currently ${policy.retention_minutes} minutes. The sweep runs every 30 seconds and each purge is written to the ledger.`
                : undefined
            }
          >
            <input
              className="input-field"
              type="number"
              min={1}
              value={retentionMinutes}
              onChange={(e) => setRetentionMinutes(Number(e.target.value))}
            />
          </Field>
          <div className="flex gap-4">
            <button type="submit" className="btn-primary" disabled={busy === "retention"}>
              Save
            </button>
            <button type="button" className="btn-secondary" onClick={runPurge} disabled={busy === "purge"}>
              Purge now
            </button>
          </div>
        </form>
      </Card>
    </AppShell>
  );
}

const smallButton = { minHeight: 40, padding: "0 16px", fontSize: 16 } as const;
