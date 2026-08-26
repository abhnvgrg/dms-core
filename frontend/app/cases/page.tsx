"use client";

import { FormEvent, useEffect, useState } from "react";
import AppShell from "@/components/AppShell";
import { Alert, Card, Cell, Field, PageHeading, Table } from "@/components/ui";
import { ROLE_LABELS, isAdmin, useAuth } from "@/lib/auth-context";
import { AdminUser, CaseSummary, assignToCase, createCase, fetchCases, fetchUsers } from "@/lib/api";

export default function CasesPage() {
  const { user } = useAuth();

  const [cases, setCases] = useState<CaseSummary[]>([]);
  const [users, setUsers] = useState<AdminUser[]>([]);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);

  const [firNumber, setFirNumber] = useState("");
  const [title, setTitle] = useState("");
  const [actsSections, setActsSections] = useState("");

  const [assignCaseId, setAssignCaseId] = useState("");
  const [assignUserId, setAssignUserId] = useState("");

  const canCreate = user?.role === "investigating_officer" || user?.role === "admin";

  async function load() {
    try {
      setCases(await fetchCases());
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not load cases");
    }
    if (isAdmin(user)) {
      try {
        setUsers(await fetchUsers());
      } catch {
        // Assignment by picking from a list is admin-only; IOs type the id.
      }
    }
  }

  useEffect(() => {
    if (!user) return;
    let cancelled = false;

    void (async () => {
      try {
        const loaded = await fetchCases();
        if (!cancelled) setCases(loaded);
      } catch (err) {
        if (!cancelled) setError(err instanceof Error ? err.message : "Could not load cases");
      }

      if (!isAdmin(user)) return;
      try {
        const loaded = await fetchUsers();
        if (!cancelled) setUsers(loaded);
      } catch {
        // Picking from a list is admin-only; other roles type the id.
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [user]);

  async function submitCase(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    setNotice("");
    try {
      const created = await createCase({
        fir_number: firNumber,
        title,
        acts_sections: actsSections || undefined,
      });
      setNotice(`Case ${created.fir_number} created. You are assigned to it.`);
      setFirNumber("");
      setTitle("");
      setActsSections("");
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not create the case");
    } finally {
      setBusy(false);
    }
  }

  async function submitAssignment(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    setNotice("");
    try {
      await assignToCase(assignCaseId, assignUserId);
      setNotice("Officer assigned. They can now see that case and its evidence.");
      setAssignUserId("");
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not assign the officer");
    } finally {
      setBusy(false);
    }
  }

  if (!user) return null;

  return (
    <AppShell>
      <PageHeading
        title="Cases"
        subtitle="Every record is filed against a case, and access is scoped to the cases you are assigned to."
      />

      {error && <Alert kind="error">{error}</Alert>}
      {notice && <Alert kind="success">{notice}</Alert>}

      {cases.length === 0 ? (
        <Card>
          <p style={{ fontSize: 18 }}>You are not assigned to any case yet.</p>
        </Card>
      ) : (
        <div style={{ marginBottom: 32 }}>
          <Table headers={["FIR number", "Title", "Acts / sections", "Status", "Opened"]}>
            {cases.map((item) => (
              <tr key={item.id} className="divider">
                <Cell bold>{item.fir_number}</Cell>
                <Cell>{item.title}</Cell>
                <Cell>{item.acts_sections || "—"}</Cell>
                <Cell>{item.status}</Cell>
                <Cell>{new Date(item.created_at).toLocaleDateString()}</Cell>
              </tr>
            ))}
          </Table>
        </div>
      )}

      {canCreate && (
        <Card title="Register a case">
          <form onSubmit={submitCase} style={{ maxWidth: 560 }}>
            <Field label="FIR number">
              <input
                className="input-field"
                value={firNumber}
                onChange={(e) => setFirNumber(e.target.value)}
                required
              />
            </Field>
            <Field label="Title">
              <input
                className="input-field"
                value={title}
                onChange={(e) => setTitle(e.target.value)}
                required
              />
            </Field>
            <Field label="Acts and sections" hint="Optional.">
              <input
                className="input-field"
                value={actsSections}
                onChange={(e) => setActsSections(e.target.value)}
              />
            </Field>
            <button type="submit" className="btn-primary" disabled={busy}>
              Create case
            </button>
          </form>
        </Card>
      )}

      {canCreate && cases.length > 0 && (
        <Card title="Assign an officer">
          <form onSubmit={submitAssignment} style={{ maxWidth: 560 }}>
            <Field label="Case">
              <select
                className="input-field"
                value={assignCaseId}
                onChange={(e) => setAssignCaseId(e.target.value)}
                required
              >
                <option value="">Select a case</option>
                {cases.map((item) => (
                  <option key={item.id} value={item.id}>
                    {item.fir_number} — {item.title}
                  </option>
                ))}
              </select>
            </Field>
            <Field
              label="Officer"
              hint={users.length ? undefined : "Paste the officer's user id — only admins can list users."}
            >
              {users.length > 0 ? (
                <select
                  className="input-field"
                  value={assignUserId}
                  onChange={(e) => setAssignUserId(e.target.value)}
                  required
                >
                  <option value="">Select an officer</option>
                  {users
                    .filter((candidate) => candidate.is_active)
                    .map((candidate) => (
                      <option key={candidate.id} value={candidate.id}>
                        {candidate.badge_number} — {candidate.full_name} (
                        {ROLE_LABELS[candidate.role] ?? candidate.role})
                      </option>
                    ))}
                </select>
              ) : (
                <input
                  className="input-field"
                  value={assignUserId}
                  onChange={(e) => setAssignUserId(e.target.value)}
                  placeholder="user id"
                  required
                />
              )}
            </Field>
            <button type="submit" className="btn-primary" disabled={busy || !assignCaseId || !assignUserId}>
              Assign
            </button>
          </form>
        </Card>
      )}
    </AppShell>
  );
}
