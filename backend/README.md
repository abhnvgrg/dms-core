# NyayVault — Backend

Secure evidence and document management for law enforcement and legal workflows.
Built for SIH (PS 26190). This file is setup plus API surface; the reasoning
behind the security model is in the root `README.md`.

## Setup

```bash
# System dependency — needed for OCR
sudo apt install -y tesseract-ocr   # or the Windows/macOS equivalent

# Python deps
python -m venv .venv && source .venv/Scripts/activate   # Windows
pip install -r requirements.txt
python -m spacy download en_core_web_sm

# Infra (Postgres+pgvector, Redis, MinIO, Ganache, ClamAV)
docker compose -f ../infrastructure/docker-compose.yml up -d postgres redis minio ganache clamav

# Copy backend/.env.example to backend/.env and fill it in, including a
# generated ROOT_ENCRYPTION_KEY:
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

# Apply the schema
alembic upgrade head

# One-time: deploy the audit-anchor smart contract, then paste the printed
# address into BLOCKCHAIN_CONTRACT_ADDRESS in .env
python scripts/deploy_contract.py

# Seed demo users (prompts for a shared dev password)
python scripts/seed_users.py

# Run — three processes
uvicorn app.main:app --port 8000
celery -A app.tasks.celery_app worker --pool=solo --loglevel=info
celery -A app.tasks.celery_app beat --loglevel=info
```

API docs (interactive, good for demos): `http://localhost:8000/docs`

The compose file also defines `celery-worker` and `celery-beat` services that
build this directory. Use those *or* the local processes above, not both — two
workers on one queue will fight over tasks. Local is easier to watch during a
demo; the containerised versions need `backend/.env` pointing at the compose
service names rather than `localhost`.

Two `.env` switches are worth knowing on a first run:
`MALWARE_SCANNING_ENABLED=false` skips ClamAV (whose signature database takes
several minutes to download, and which fails closed while unreachable), and
`BLOCKCHAIN_ANCHORING_ENABLED=false` skips the chain. Neither disables the
hash chain or the signed checkpoints.

## Demo users

Seeded by `scripts/seed_users.py` with whatever password you set when running it:

| badge number | role |
|---|---|
| IO-001 | Investigating Officer |
| FOR-001 | Forensics Officer |
| COURT-001 | Court Official |
| ADM-001 | Admin |

Every account's **first** sign-in gets an enrollment-only session: a login from
an unrecognised browser or IP range requires a second factor, and a first login
is by definition unfamiliar. Administrators are gated on every login until
enrolled, regardless of device. Enrollment issues a fresh session and retires
the token it was granted at the lower privilege level.

Officers who want to upload or transfer custody must also register a signing key
generated in their browser (the frontend does this under **Security**).

## Background jobs

Celery beat runs three schedules:

| Job | Interval | What it does |
|---|---|---|
| `purge_expired_documents` | 30s | Deletes evidence past the retention window, writing the purge to the ledger |
| `create_audit_checkpoint` | 60s | Signs the entries since the last checkpoint once 50 entries or 5 minutes have accumulated, whichever comes first, and mirrors it to write-once storage |
| `expire_access_grants` | 60s | Records lapsed access grants as `access_grant_expired` events |

Blockchain anchoring is not scheduled — it is queued per ledger entry by an
`after_commit` hook, so it never blocks a request.

## API surface

All routes are under `/api/v1`.

**Authentication and key custody**
- `POST /auth/login` — opaque access (15 min) + refresh (8h) tokens; accepts `totp_code`
- `POST /auth/refresh` — single-use rotation; reusing an old refresh token revokes the family
- `POST /auth/logout`, `POST /auth/logout-everywhere`, `GET /auth/me`
- `POST /auth/mfa/enroll`, `POST /auth/mfa/activate` — activation returns a new session; the pre-enrollment token is revoked
- `POST /auth/signing-keys`, `GET /auth/signing-keys` — register/rotate the public half of a browser-generated keypair

**Cases**
- `POST /cases`, `GET /cases`, `GET /cases/{id}`, `POST /cases/{id}/assignments`

**Documents**
- `POST /documents/upload` — requires `sha256_hash` and `client_signature` from the officer's device
- `GET /documents`, `GET /documents/search`, `GET /documents/{id}`, `GET /documents/{id}/status`
- `GET /documents/{id}/download` — streamed through the API, never a presigned URL
- `POST /documents/{id}/verify`
- `PATCH /documents/{id}/classification` *(MFA)*
- `POST /documents/{id}/access-grants` *(MFA)*, `GET .../access-grants`, `POST .../access-grants/{grant_id}/revoke` *(MFA)*

**Physical evidence**
- `POST /assets`, `GET /assets`, `GET /assets/by-qr/{qr_uuid}`, `GET /assets/{id}/transfers`
- `POST /assets/{id}/transfer` *(MFA)* — carries `expected_prior_custody_status`; a mismatch is a 409 plus an `asset_transfer_conflict` ledger entry

**Audit**
- `GET /audit/verify` — chain consistency *and* checkpoint verification
- `GET /audit/checkpoints`, `POST /audit/checkpoints`
- `GET /audit/entities/{type}/{id}`, `POST /audit/ledger/{id}/verify-onchain`

**Administration** *(admin only, all MFA-protected except the reads)*
- `GET /admin/users`, `POST /admin/users`, `PATCH /admin/users/{id}`
- `GET /admin/users/{id}/signing-keys`, `POST /admin/signing-keys/{key_id}/revoke`
- `GET /admin/keys`, `POST /admin/keys/{purpose}/rotate`

**Retention**
- `GET /retention/policy`, `PUT /retention/policy`, `POST /retention/purge-now`

**Health**
- `GET /health` — checks live DB connectivity, no auth needed

### The features worth demoing directly

**Tamper detection.** Three independent checks. `GET /audit/verify` recomputes
the hash chain *and* re-derives every signed checkpoint;
`POST /audit/ledger/{id}/verify-onchain` compares one entry against the chain.
Editing an `audit_ledger` row breaks the first. Repairing every downstream hash
to hide it — the thing a database administrator can actually do — still fails
the checkpoint check, because the checkpoint was signed with a key the database
never holds and a copy sits in an object-locked bucket.

**Officer-attributable signatures.** Uploads and custody transfers are signed in
the browser with a non-extractable key. The server verifies and cannot forge:
`POST /documents/{id}/verify` reports who signed and whether their key has since
been revoked.

**Configurable retention.** `PUT /retention/policy` with `{"retention_minutes": N}`
takes effect immediately — no restart. The sweep deletes file and row while
`document_purged` stays in the ledger permanently.

## What is not production-grade

- The chain is a local Ganache container, so the on-chain anchor demonstrates
  the mechanism without providing an independent ledger.
- `ROOT_ENCRYPTION_KEY` stands in for an HSM or KMS. It wraps the per-purpose
  data keys and the checkpoint signing key, but it is itself a value in `.env`.
- OCR is Tesseract on images only. PDFs are stored, hashed, signed and audited
  but never OCR'd, so they carry no extracted text and no embedding.
- There is no automated test suite.
