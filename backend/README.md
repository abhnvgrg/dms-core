# Digital Evidence Management System — Backend (MVP)

Built for SIH internal round. Scope is deliberately minimal — see "What's NOT here" below.

## Setup

```bash
# System dependency (Ubuntu/Debian) — needed for OCR
sudo apt install -y tesseract-ocr

# Python deps
pip install --break-system-packages -r requirements.txt
pip install --break-system-packages "bcrypt==4.0.1"   # avoids a known passlib/bcrypt bug
python3 -m spacy download en_core_web_sm

# Run
uvicorn app.main:app --reload --port 8000
```

Server runs at `http://localhost:8000`. Interactive API docs (auto-generated, great for
showing judges): `http://localhost:8000/docs`

## Demo users (hardcoded, no signup flow)

| username | password   | role    |
|----------|-----------|---------|
| officer1 | officer123 | officer |
| admin1   | admin123   | admin   |

## API contract (for frontend)

### POST /auth/login
Form-encoded (not JSON): `username`, `password`
```json
// Response
{
  "access_token": "eyJ...",
  "token_type": "bearer",
  "role": "officer",
  "full_name": "Investigating Officer Sharma"
}
```
Store `access_token`. Send as `Authorization: Bearer <token>` on every other request.

### GET /auth/me
Returns the logged-in user's info. Use to persist session on page reload.

### POST /evidence/upload
`multipart/form-data`: `case_id` (text), `file` (file, image works best for OCR demo)
```json
// Response
{
  "id": 1,
  "case_id": "2026/001",
  "filename": "evidence.png",
  "sha256_hash": "be677...",
  "signature": "7462...",
  "uploaded_by": "officer1",
  "uploaded_at": "2026-08-23T03:04:40+00:00",
  "ocr_status": "ok",          // "ok" | "unsupported" | "error"
  "redacted_text": "..."       // PII-masked extracted text
}
```

### GET /evidence
List all evidence (for dashboard table).
```json
[
  { "id": 1, "case_id": "2026/001", "filename": "...", "sha256_hash": "...",
    "uploaded_by": "officer1", "uploaded_at": "...", "ocr_status": "ok" }
]
```

### GET /evidence/{id}
Full record for one item, including `extracted_text` and `redacted_text`.

### POST /evidence/{id}/verify
**This is the headline demo feature.** Call this from an "Verify Integrity" button.
```json
// Untampered
{
  "evidence_id": 1, "filename": "...",
  "original_hash": "be677...", "recomputed_hash": "be677...",
  "hash_match": true, "signature_valid": true,
  "integrity": "VERIFIED"
}
// Tampered
{
  "evidence_id": 1, ...,
  "hash_match": false, "signature_valid": true,
  "integrity": "TAMPERED"
}
```
Frontend: show a big green "VERIFIED ✓" or red "TAMPERED ✗" badge based on `integrity`.

### GET /health
Basic liveness check, no auth needed.

## Suggested demo script

1. Login as `officer1`
2. Upload a scanned FIR/document image → show the hash + OCR text + redacted PII live
3. Click "Verify Integrity" → green VERIFIED badge
4. (Backstage, before the demo) manually edit the stored file on disk
5. Click "Verify Integrity" again → red TAMPERED badge
6. Close with: "the same tamper-detection engine sits under our full production
   architecture" and show the v3/v4 architecture doc as your roadmap slide

## What's NOT in this build (intentional — mention as roadmap)

- Real RBAC / document classification model
- Hash-chained audit ledger with external anchoring
- Per-officer key management, MFA
- Async task queue (Celery/Redis), cloud storage (MinIO/S3), backups
- Multi-user chain-of-custody transfer workflow

These are documented in architecture v3/v4 as the production hardening path.
