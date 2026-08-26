const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";
const API_V1 = `${API_BASE}/api/v1`;

const ACCESS_KEY = "dms_token";
const REFRESH_KEY = "dms_refresh_token";
const USER_KEY = "dms_user";

// ---------------------------------------------------------------- types ----

export interface LoginResponse {
  access_token: string;
  refresh_token: string;
  token_type: string;
  role: string;
  full_name: string;
  badge_number: string;
  mfa_enabled: boolean;
  mfa_enrollment_required: boolean;
  signing_key_registered: boolean;
}

export interface CurrentUser {
  id: string;
  badge_number: string;
  full_name: string;
  role: string;
  mfa_enabled: boolean;
  signing_key_fingerprint: string | null;
}

export interface CaseSummary {
  id: string;
  fir_number: string;
  title: string;
  status: string;
  acts_sections: string | null;
  created_by_id: string;
  created_at: string;
  updated_at: string;
}

export interface EvidenceSummary {
  id: string;
  case_id: string;
  filename: string;
  sha256_hash: string;
  uploaded_by: string;
  uploaded_at: string;
  ocr_status: string;
}

export interface EvidenceDetail extends EvidenceSummary {
  signature: string | null;
  classification: string;
  extracted_text: string | null;
  redacted_text: string | null;
}

export interface UploadResponse {
  id: string;
  case_id: string;
  filename: string;
  sha256_hash: string;
  signature: string;
  uploaded_by: string;
  uploaded_at: string;
  ocr_status: string;
  classification: string;
  redacted_text: string | null;
}

export interface VerifyResponse {
  evidence_id: string;
  filename?: string;
  original_hash?: string;
  recomputed_hash?: string;
  hash_match?: boolean;
  signature_valid?: boolean;
  signed_by?: string | null;
  signing_key_status?: string | null;
  integrity: "VERIFIED" | "TAMPERED" | "PENDING_REVIEW" | "FAILED";
  reason?: string;
}

export interface SearchResult {
  id: string;
  case_id: string;
  filename: string;
  uploaded_by: string;
  uploaded_at: string;
  ocr_status: string;
  snippet: string | null;
  score: number;
}

export interface AccessGrant {
  id: string;
  document_id: string;
  grantee_badge_number: string;
  granted_by_badge_number: string;
  reason: string;
  expires_at: string;
  revoked_at: string | null;
}

export interface AuditEntry {
  id: number;
  action_type: string;
  entity_type: string;
  entity_id: string;
  actor_id: string | null;
  payload: Record<string, unknown>;
  previous_entry_hash: string | null;
  entry_hash: string;
  chain_tx_hash: string | null;
  chain_block_number: number | null;
  chain_anchored_at: string | null;
  created_at: string;
}

export interface LedgerVerification {
  status: string;
  chain_status: string | null;
  entries_checked: number | null;
  broken_at_entry_id: number | null;
  reason: string | null;
  checkpoint_status: string | null;
  checkpoints_checked: number | null;
  entries_covered_by_checkpoints: number | null;
  broken_at_checkpoint_id: number | null;
  mirrored_to_write_once_store: number | null;
}

export interface Checkpoint {
  id: number;
  from_entry_id: number;
  to_entry_id: number;
  entry_count: number;
  checkpoint_hash: string;
  signing_key_version: number;
  object_key: string | null;
  created_at: string;
}

export interface OnchainVerification {
  entry_id: number;
  db_entry_hash: string;
  onchain_entry_hash: string | null;
  match: boolean | null;
  status: string;
}

export interface Asset {
  id: string;
  case_id: string;
  qr_uuid: string;
  item_name: string;
  category: string;
  custody_status: string;
  current_custodian_badge_number: string | null;
  created_at: string;
}

export interface TransferRecord {
  id: string;
  from_status: string;
  to_status: string;
  performed_by: string;
  received_by: string;
  signature_valid: boolean;
  signing_key_status: string;
  created_at: string;
}

export interface SigningKey {
  id: string;
  fingerprint: string;
  status: string;
  public_key_pem: string;
  created_at: string;
  retired_at: string | null;
  revoked_at: string | null;
}

export interface AdminUser {
  id: string;
  badge_number: string;
  full_name: string;
  role: string;
  is_active: boolean;
  mfa_enabled: boolean;
  created_at: string;
}

export interface EncryptionKeyInfo {
  purpose: string;
  version: number;
  is_active: boolean;
  created_at: string;
  rotated_at: string | null;
}

export interface RetentionPolicy {
  id: string;
  retention_minutes: number;
  updated_by_id: string | null;
  updated_at: string;
}

// ------------------------------------------------------------- plumbing ----

export function getToken(): string | null {
  if (typeof window === "undefined") return null;
  return localStorage.getItem(ACCESS_KEY);
}

function getRefreshToken(): string | null {
  if (typeof window === "undefined") return null;
  return localStorage.getItem(REFRESH_KEY);
}

export function setTokens(access: string, refresh: string) {
  localStorage.setItem(ACCESS_KEY, access);
  localStorage.setItem(REFRESH_KEY, refresh);
}

export function clearToken() {
  localStorage.removeItem(ACCESS_KEY);
  localStorage.removeItem(REFRESH_KEY);
  localStorage.removeItem(USER_KEY);
}

/**
 * Access tokens last 15 minutes by design, so a session that only tracked the
 * access token would drop the user at the login screen mid-task. One refresh
 * is attempted per 401, and concurrent callers share it rather than each
 * burning a single-use refresh token -- reuse would revoke the whole family.
 */
let refreshInFlight: Promise<boolean> | null = null;

async function refreshSession(): Promise<boolean> {
  const refreshToken = getRefreshToken();
  if (!refreshToken) return false;

  if (!refreshInFlight) {
    refreshInFlight = (async () => {
      try {
        const res = await fetch(`${API_V1}/auth/refresh`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ refresh_token: refreshToken }),
        });
        if (!res.ok) return false;
        const body: LoginResponse = await res.json();
        setTokens(body.access_token, body.refresh_token);
        return true;
      } catch {
        return false;
      } finally {
        // Cleared on the next tick so callers awaiting this attempt all see it.
        setTimeout(() => {
          refreshInFlight = null;
        }, 0);
      }
    })();
  }

  return refreshInFlight;
}

export class ApiError extends Error {
  status: number;

  constructor(status: number, message: string) {
    super(message);
    this.status = status;
    this.name = "ApiError";
  }
}

async function detailOf(res: Response, fallback: string): Promise<string> {
  try {
    const body = await res.json();
    if (typeof body?.detail === "string") return body.detail;
    if (Array.isArray(body?.detail)) return body.detail.map((d: { msg?: string }) => d.msg).join("; ");
    return fallback;
  } catch {
    return fallback;
  }
}

interface RequestOptions extends RequestInit {
  mfaCode?: string;
}

async function authFetch(path: string, options: RequestOptions = {}, retry = true): Promise<Response> {
  const { mfaCode, ...init } = options;
  const headers = new Headers(init.headers);

  const token = getToken();
  if (token) headers.set("Authorization", `Bearer ${token}`);
  if (mfaCode) headers.set("X-MFA-Code", mfaCode);

  const res = await fetch(`${API_V1}${path}`, { ...init, headers });

  if (res.status === 401 && retry) {
    // A body already consumed cannot be replayed, so only retry idempotent
    // shapes that carry no stream: JSON strings and bodiless requests.
    const replayable = !init.body || typeof init.body === "string";
    if (replayable && (await refreshSession())) {
      return authFetch(path, options, false);
    }
    clearToken();
    // A full navigation, not router.push: the session is gone, so every cached
    // client component holding user data should be discarded with it.
    // eslint-disable-next-line @next/next/no-location-assign-relative-destination
    if (typeof window !== "undefined") window.location.href = "/login";
    throw new ApiError(401, "Session expired");
  }

  return res;
}

async function getJson<T>(path: string, fallback: string): Promise<T> {
  const res = await authFetch(path);
  if (!res.ok) throw new ApiError(res.status, await detailOf(res, fallback));
  return res.json();
}

async function sendJson<T>(
  path: string,
  method: string,
  body: unknown,
  fallback: string,
  mfaCode?: string,
): Promise<T> {
  const res = await authFetch(path, {
    method,
    headers: { "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
    mfaCode,
  });
  if (!res.ok) throw new ApiError(res.status, await detailOf(res, fallback));
  if (res.status === 204) return undefined as T;
  return res.json();
}

// ------------------------------------------------------------------ auth ----

export async function login(
  username: string,
  password: string,
  totpCode?: string,
): Promise<LoginResponse> {
  const body = new URLSearchParams();
  body.set("username", username);
  body.set("password", password);
  if (totpCode) body.set("totp_code", totpCode);

  const res = await fetch(`${API_V1}/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });
  if (!res.ok) throw new ApiError(res.status, await detailOf(res, "Login failed"));
  return res.json();
}

export async function logout(): Promise<void> {
  try {
    await authFetch("/auth/logout", { method: "POST" }, false);
  } catch {
    // Signing out locally matters more than the server acknowledging it.
  }
}

export function logoutEverywhere(): Promise<void> {
  return sendJson("/auth/logout-everywhere", "POST", undefined, "Could not revoke sessions");
}

export function fetchMe(): Promise<CurrentUser> {
  return getJson("/auth/me", "Could not load your profile");
}

export function enrollMfa(): Promise<{ secret: string; provisioning_uri: string }> {
  return sendJson("/auth/mfa/enroll", "POST", undefined, "Could not start MFA enrollment");
}

/** Returns a fresh session: enrolling is a privilege change, so the old token is retired. */
export function activateMfa(code: string): Promise<LoginResponse> {
  return sendJson("/auth/mfa/activate", "POST", { code }, "Could not activate MFA");
}

export function registerSigningKey(publicKeyPem: string): Promise<SigningKey> {
  return sendJson("/auth/signing-keys", "POST", { public_key_pem: publicKeyPem }, "Could not register signing key");
}

export function fetchSigningKeys(): Promise<SigningKey[]> {
  return getJson("/auth/signing-keys", "Could not load signing keys");
}

// ----------------------------------------------------------------- cases ----

export function fetchCases(): Promise<CaseSummary[]> {
  return getJson("/cases", "Could not load cases");
}

export function createCase(payload: {
  fir_number: string;
  title: string;
  acts_sections?: string;
}): Promise<CaseSummary> {
  return sendJson("/cases", "POST", payload, "Could not create case");
}

export function assignToCase(caseId: string, userId: string): Promise<{ status: string }> {
  return sendJson(`/cases/${caseId}/assignments`, "POST", { user_id: userId }, "Could not assign user");
}

// ------------------------------------------------------------- documents ----

export function fetchEvidenceList(): Promise<EvidenceSummary[]> {
  return getJson("/documents", "Failed to load evidence list");
}

export function fetchEvidenceDetail(id: string): Promise<EvidenceDetail> {
  return getJson(`/documents/${id}`, "Failed to load evidence record");
}

export function searchDocuments(query: string): Promise<SearchResult[]> {
  return getJson(`/documents/search?q=${encodeURIComponent(query)}`, "Search failed");
}

export async function uploadEvidence(params: {
  caseId: string;
  file: File;
  classification: string;
  sha256: string;
  signature: string;
}): Promise<UploadResponse> {
  const form = new FormData();
  form.set("case_id", params.caseId);
  form.set("file", params.file);
  form.set("classification", params.classification);
  form.set("sha256_hash", params.sha256);
  form.set("client_signature", params.signature);

  const res = await authFetch("/documents/upload", { method: "POST", body: form });
  if (!res.ok) throw new ApiError(res.status, await detailOf(res, "Upload failed"));
  return res.json();
}

export function verifyEvidence(id: string): Promise<VerifyResponse> {
  return sendJson(`/documents/${id}/verify`, "POST", undefined, "Verification request failed");
}

export async function downloadEvidence(id: string, filename: string): Promise<void> {
  const res = await authFetch(`/documents/${id}/download`);
  if (!res.ok) throw new ApiError(res.status, await detailOf(res, "Download failed"));

  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}

export function reclassifyDocument(
  id: string,
  classification: string,
  mfaCode: string,
): Promise<EvidenceDetail> {
  return sendJson(
    `/documents/${id}/classification`,
    "PATCH",
    { classification },
    "Could not change classification",
    mfaCode,
  );
}

export function fetchAccessGrants(documentId: string): Promise<AccessGrant[]> {
  return getJson(`/documents/${documentId}/access-grants`, "Could not load access grants");
}

export function createAccessGrant(
  documentId: string,
  payload: { grantee_badge_number: string; reason: string; duration_hours: number },
  mfaCode: string,
): Promise<AccessGrant> {
  return sendJson(
    `/documents/${documentId}/access-grants`,
    "POST",
    payload,
    "Could not create access grant",
    mfaCode,
  );
}

export function revokeAccessGrant(
  documentId: string,
  grantId: string,
  mfaCode: string,
): Promise<AccessGrant> {
  return sendJson(
    `/documents/${documentId}/access-grants/${grantId}/revoke`,
    "POST",
    undefined,
    "Could not revoke access grant",
    mfaCode,
  );
}

// ----------------------------------------------------------------- audit ----

export function verifyLedger(): Promise<LedgerVerification> {
  return getJson("/audit/verify", "Could not verify the ledger");
}

export function fetchCheckpoints(): Promise<Checkpoint[]> {
  return getJson("/audit/checkpoints", "Could not load checkpoints");
}

export function createCheckpoint(): Promise<Checkpoint> {
  return sendJson("/audit/checkpoints", "POST", undefined, "Could not create a checkpoint");
}

export function fetchEntityAudit(entityType: string, entityId: string): Promise<AuditEntry[]> {
  return getJson(`/audit/entities/${entityType}/${entityId}`, "Could not load the audit trail");
}

export function verifyEntryOnchain(entryId: number): Promise<OnchainVerification> {
  return sendJson(`/audit/ledger/${entryId}/verify-onchain`, "POST", undefined, "On-chain check failed");
}

// ---------------------------------------------------------------- assets ----

export function fetchAssets(caseId: string): Promise<Asset[]> {
  return getJson(`/assets?case_id=${encodeURIComponent(caseId)}`, "Could not load physical evidence");
}

export function fetchAssetByQr(qrUuid: string): Promise<Asset> {
  return getJson(`/assets/by-qr/${qrUuid}`, "No asset carries that tag");
}

export function registerAsset(payload: {
  case_id: string;
  item_name: string;
  category: string;
}): Promise<Asset> {
  return sendJson("/assets", "POST", payload, "Could not register the item");
}

export function fetchTransfers(assetId: string): Promise<TransferRecord[]> {
  return getJson(`/assets/${assetId}/transfers`, "Could not load the custody history");
}

export function transferAsset(
  assetId: string,
  payload: {
    expected_prior_custody_status: string;
    new_custody_status: string;
    receiving_officer_badge_number: string;
    client_signature: string;
  },
  mfaCode: string,
): Promise<Asset> {
  return sendJson(`/assets/${assetId}/transfer`, "POST", payload, "Transfer failed", mfaCode);
}

// ----------------------------------------------------------------- admin ----

export function fetchUsers(): Promise<AdminUser[]> {
  return getJson("/admin/users", "Could not load users");
}

export function createUser(
  payload: { badge_number: string; full_name: string; role: string; password: string },
  mfaCode: string,
): Promise<AdminUser> {
  return sendJson("/admin/users", "POST", payload, "Could not create the user", mfaCode);
}

export function updateUser(
  userId: string,
  payload: { role?: string; is_active?: boolean },
  mfaCode: string,
): Promise<AdminUser> {
  return sendJson(`/admin/users/${userId}`, "PATCH", payload, "Could not update the user", mfaCode);
}

export function fetchUserSigningKeys(userId: string): Promise<
  { id: string; fingerprint: string; status: string; created_at: string; revoked_at: string | null }[]
> {
  return getJson(`/admin/users/${userId}/signing-keys`, "Could not load that officer's keys");
}

export function revokeUserSigningKey(keyId: string, mfaCode: string): Promise<{ id: string; status: string }> {
  return sendJson(`/admin/signing-keys/${keyId}/revoke`, "POST", undefined, "Could not revoke the key", mfaCode);
}

export function fetchEncryptionKeys(): Promise<EncryptionKeyInfo[]> {
  return getJson("/admin/keys", "Could not load encryption keys");
}

export function rotateEncryptionKey(
  purpose: string,
  mfaCode: string,
): Promise<{ purpose: string; active_version: number }> {
  return sendJson(`/admin/keys/${purpose}/rotate`, "POST", undefined, "Could not rotate the key", mfaCode);
}

// ------------------------------------------------------------- retention ----

export function fetchRetentionPolicy(): Promise<RetentionPolicy> {
  return getJson("/retention/policy", "Could not load the retention policy");
}

export function updateRetentionPolicy(retentionMinutes: number): Promise<RetentionPolicy> {
  return sendJson(
    "/retention/policy",
    "PUT",
    { retention_minutes: retentionMinutes },
    "Could not update the retention policy",
  );
}

export function purgeNow(): Promise<{ purged_count: number; retention_minutes: number }> {
  return sendJson("/retention/purge-now", "POST", undefined, "Could not run the purge");
}
