const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

export interface LoginResponse {
  access_token: string;
  token_type: string;
  role: string;
  full_name: string;
}

export interface EvidenceSummary {
  id: number;
  case_id: string;
  filename: string;
  sha256_hash: string;
  uploaded_by: string;
  uploaded_at: string;
  ocr_status: string;
}

export interface EvidenceDetail extends EvidenceSummary {
  stored_path: string;
  signature: string;
  extracted_text: string | null;
  redacted_text: string | null;
}

export interface UploadResponse {
  id: number;
  case_id: string;
  filename: string;
  sha256_hash: string;
  signature: string;
  uploaded_by: string;
  uploaded_at: string;
  ocr_status: string;
  redacted_text: string;
}

export interface VerifyResponse {
  evidence_id: number;
  filename?: string;
  original_hash?: string;
  recomputed_hash?: string;
  hash_match?: boolean;
  signature_valid?: boolean;
  integrity: "VERIFIED" | "TAMPERED" | "FAILED";
  reason?: string;
}

function getToken(): string | null {
  if (typeof window === "undefined") return null;
  return localStorage.getItem("dms_token");
}

export function setToken(token: string) {
  localStorage.setItem("dms_token", token);
}

export function clearToken() {
  localStorage.removeItem("dms_token");
  localStorage.removeItem("dms_user");
}

async function authFetch(path: string, options: RequestInit = {}) {
  const token = getToken();
  const headers = new Headers(options.headers);
  if (token) headers.set("Authorization", `Bearer ${token}`);
  const res = await fetch(`${API_BASE}${path}`, { ...options, headers });
  if (res.status === 401) {
    clearToken();
    if (typeof window !== "undefined") window.location.href = "/login";
    throw new Error("Session expired");
  }
  return res;
}

export async function login(username: string, password: string): Promise<LoginResponse> {
  const body = new URLSearchParams();
  body.set("username", username);
  body.set("password", password);
  const res = await fetch(`${API_BASE}/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: "Login failed" }));
    throw new Error(err.detail || "Login failed");
  }
  return res.json();
}

export async function fetchEvidenceList(): Promise<EvidenceSummary[]> {
  const res = await authFetch("/evidence");
  if (!res.ok) throw new Error("Failed to load evidence list");
  return res.json();
}

export async function fetchEvidenceDetail(id: number): Promise<EvidenceDetail> {
  const res = await authFetch(`/evidence/${id}`);
  if (!res.ok) throw new Error("Failed to load evidence record");
  return res.json();
}

export async function uploadEvidence(caseId: string, file: File): Promise<UploadResponse> {
  const form = new FormData();
  form.set("case_id", caseId);
  form.set("file", file);
  const res = await authFetch("/evidence/upload", { method: "POST", body: form });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: "Upload failed" }));
    throw new Error(err.detail || "Upload failed");
  }
  return res.json();
}

export async function verifyEvidence(id: number): Promise<VerifyResponse> {
  const res = await authFetch(`/evidence/${id}/verify`, { method: "POST" });
  if (!res.ok) throw new Error("Verification request failed");
  return res.json();
}
