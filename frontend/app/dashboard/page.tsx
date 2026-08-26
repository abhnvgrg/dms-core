"use client";

import { FormEvent, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import AppShell from "@/components/AppShell";
import { Alert, Badge, Cell, Mono, PageHeading, Table } from "@/components/ui";
import { canUpload, useAuth } from "@/lib/auth-context";
import { EvidenceSummary, SearchResult, fetchEvidenceList, searchDocuments } from "@/lib/api";

export default function DashboardPage() {
  const { user } = useAuth();
  const [evidence, setEvidence] = useState<EvidenceSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [caseFilter, setCaseFilter] = useState("ALL");

  const [query, setQuery] = useState("");
  const [searching, setSearching] = useState(false);
  const [results, setResults] = useState<SearchResult[] | null>(null);

  useEffect(() => {
    if (!user) return;
    fetchEvidenceList()
      .then(setEvidence)
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  }, [user]);

  const caseIds = useMemo(
    () => Array.from(new Set(evidence.map((item) => item.case_id))).sort(),
    [evidence],
  );

  const filtered = useMemo(
    () => (caseFilter === "ALL" ? evidence : evidence.filter((item) => item.case_id === caseFilter)),
    [evidence, caseFilter],
  );

  async function runSearch(event: FormEvent) {
    event.preventDefault();
    if (!query.trim()) {
      setResults(null);
      return;
    }
    setSearching(true);
    setError("");
    try {
      setResults(await searchDocuments(query.trim()));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Search failed");
    } finally {
      setSearching(false);
    }
  }

  if (!user) return null;

  const courtOfficial = user.role === "court_official";

  return (
    <AppShell>
      <PageHeading
        title="Evidence"
        subtitle="Records from the cases you are assigned to."
        action={
          canUpload(user) ? (
            <Link
              href="/upload"
              className="btn-primary"
              style={{ textDecoration: "none", display: "inline-flex", alignItems: "center" }}
            >
              + Upload Evidence
            </Link>
          ) : undefined
        }
      />

      {error && <Alert kind="error">{error}</Alert>}

      <form onSubmit={runSearch} style={{ marginBottom: 24, display: "flex", gap: 16, alignItems: "flex-end" }}>
        <div style={{ flex: 1, maxWidth: 560 }}>
          <label className="label-bold" style={{ display: "block", marginBottom: 8 }}>
            Semantic search
          </label>
          <input
            className="input-field"
            placeholder="Describe what you are looking for"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
        </div>
        <button type="submit" className="btn-secondary" disabled={searching}>
          {searching ? "Searching…" : "Search"}
        </button>
        {results && (
          <button
            type="button"
            className="btn-secondary"
            onClick={() => {
              setResults(null);
              setQuery("");
            }}
          >
            Clear
          </button>
        )}
      </form>

      {results ? (
        <>
          <p style={{ fontSize: 18, marginBottom: 16 }}>
            {results.length} match{results.length === 1 ? "" : "es"}, ranked by meaning rather than
            keywords.
            {courtOfficial && " As a Court Official you see metadata only; content needs a grant."}
          </p>
          {results.length > 0 && (
            <Table headers={["Case", "Filename", "Score", "Extract", ""]}>
              {results.map((item) => (
                <tr key={item.id} className="divider">
                  <Cell bold>{item.case_id}</Cell>
                  <Cell>{item.filename}</Cell>
                  <Cell>
                    <Mono>{item.score.toFixed(3)}</Mono>
                  </Cell>
                  <Cell>
                    {item.snippet ?? (
                      <span style={{ color: "var(--color-outline)" }}>metadata only</span>
                    )}
                  </Cell>
                  <Cell>
                    <Link href={`/evidence/${item.id}`} className="btn-secondary" style={linkButton}>
                      View
                    </Link>
                  </Cell>
                </tr>
              ))}
            </Table>
          )}
        </>
      ) : (
        <>
          <div style={{ marginBottom: 24 }}>
            <label className="label-bold" style={{ display: "block", marginBottom: 8 }}>
              Filter by case
            </label>
            <select
              className="input-field"
              style={{ maxWidth: 320 }}
              value={caseFilter}
              onChange={(e) => setCaseFilter(e.target.value)}
            >
              <option value="ALL">All cases ({evidence.length})</option>
              {caseIds.map((id) => (
                <option key={id} value={id}>
                  {id} ({evidence.filter((item) => item.case_id === id).length})
                </option>
              ))}
            </select>
          </div>

          {loading && <p style={{ fontSize: 18 }}>Loading evidence records…</p>}

          {!loading && filtered.length === 0 && (
            <div className="card" style={{ padding: 48, textAlign: "center" }}>
              <p style={{ fontSize: 20, fontWeight: 600 }}>No evidence records yet.</p>
              {canUpload(user) && (
                <Link href="/upload" className="btn-primary" style={{ ...linkButton, marginTop: 24 }}>
                  Upload Evidence
                </Link>
              )}
            </div>
          )}

          {!loading && filtered.length > 0 && (
            <Table
              headers={["Case", "Filename", "SHA-256", "Uploaded by", "Uploaded", "OCR", ""]}
            >
              {filtered.map((item) => (
                <tr key={item.id} className="divider">
                  <Cell bold>{item.case_id}</Cell>
                  <Cell>{item.filename}</Cell>
                  <Cell>
                    <Mono truncate={16}>{item.sha256_hash}</Mono>
                  </Cell>
                  <Cell>{item.uploaded_by}</Cell>
                  <Cell>{new Date(item.uploaded_at).toLocaleString()}</Cell>
                  <Cell>
                    <Badge kind={item.ocr_status === "ok" ? "success" : "neutral"}>
                      {item.ocr_status}
                    </Badge>
                  </Cell>
                  <Cell>
                    <Link href={`/evidence/${item.id}`} className="btn-secondary" style={linkButton}>
                      View
                    </Link>
                  </Cell>
                </tr>
              ))}
            </Table>
          )}
        </>
      )}
    </AppShell>
  );
}

const linkButton = {
  minHeight: 40,
  padding: "0 20px",
  fontSize: 16,
  textDecoration: "none",
  display: "inline-flex",
  alignItems: "center",
} as const;
