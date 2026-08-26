# NyayVault

**Tamper-evident evidence management for law enforcement.**

Built for Smart India Hackathon 2026, problem statement 26190 — *Secure Digital Document & Evidence Management System*.

Digital evidence is only as trustworthy as the chain of custody behind it. NyayVault treats the audit trail itself as the security boundary: every access, transfer, and deletion is hash-chained in PostgreSQL, signed into periodic checkpoints held in write-once storage, and anchored on-chain. A privileged actor with direct database access can rewrite the table — they cannot make the rewrite pass verification.

---

## The problem

Most document management systems log access to a database table. Anyone who can write to that database can rewrite the log. For legal evidence, where the question in court is *"can you prove this file wasn't altered after seizure?"*, an audit trail that the operator can edit is not an audit trail.

NyayVault is built around one guarantee:

> Any modification to the custody record — including one made directly against the database by an administrator — is detectable.

---

## How it works

### Hash-chained audit ledger

Each audit entry stores the hash of the previous entry, forming a chain. Rewriting entry *N* invalidates every hash from *N* onward, so a casual edit is caught immediately. Repairing the chain means rewriting every subsequent row — which is possible with database access, and is what the next two layers exist to catch.

### Signed checkpoints in write-once storage

A hash chain alone proves internal consistency, not tamper-evidence: whoever can rewrite a row can recompute every hash after it. Once 50 entries or five minutes have accumulated — whichever comes first — the entries since the last checkpoint are hashed together, signed with a dedicated key the database never holds, and mirrored to an object-locked bucket.

That is what makes a wholesale rewrite visible. A repaired chain still passes the chain check and still fails the checkpoint check.

### On-chain anchoring

Each ledger entry's hash is also committed to a Solidity contract via `web3.py`, queued asynchronously on commit so the chain never blocks a request. The blockchain holds no evidence and no personal data — only a hash.

Verification asks three separate questions: is the chain internally consistent, do the entries still hash to each signed checkpoint, and does an entry match its on-chain anchor.

```
Browser: hash + sign (private key never leaves the device)
      │
      ▼
┌──────────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  FastAPI             │────▶│  Celery workers  │────▶│  pgvector       │
│  • session + RBAC    │     │                  │     │  (semantic      │
│  • classification    │     │  • Tesseract OCR │     │   search)       │
│  • malware scan      │     │  • spaCy PII     │     └─────────────────┘
│  • structural check  │     │    redaction     │
│  • signature verify  │     │  • embeddings    │
└──────────────────────┘     └──────────────────┘
      │                               │
      ▼                               │
┌─────────────────┐                   │
│  MinIO / S3     │◀──────────────────┘
│  (Fernet        │
│   encrypted)    │
└─────────────────┘
      │
      ▼
┌─────────────────────────┐     ┌──────────────────────┐
│  PostgreSQL             │────▶│  Solidity contract   │
│  hash-chained ledger    │     │  (per-entry anchor)  │
│                         │     └──────────────────────┘
│                         │     ┌──────────────────────┐
│                         │────▶│  Signed checkpoints  │
│                         │     │  (object-locked)     │
└─────────────────────────┘     └──────────────────────┘
```

### Classification-based access, not role-based

Role-based access control was insufficient here. Holding the *Court Official* role does not, on its own, grant access to unredacted evidence.

Access is governed by a **4 roles × 4 classification levels** matrix. Reaching a document above your level requires an explicit grant that is:

- **time-bound** — carries an expiry, not indefinite
- **auto-expiring** — revoked by the system, not by someone remembering
- **individually audited** — the grant itself is a ledger entry

### Officer-held signing keys

The server never holds an officer's private key. Each officer generates an RSA keypair in their browser with WebCrypto; the private half is created non-extractable and stored in IndexedDB, and only the public half is ever sent.

This is the difference between proving an officer signed something and proving the server says they did. Rotation retires the old public key rather than deleting it, so historical signatures still verify, and an administrator can revoke a compromised key — signatures made before the revocation stay valid, later ones are reported as pending review.

### Ingestion pipeline

The officer's browser hashes the file and signs the hash before the bytes leave the device, so the upload is attributable to them rather than to the server. The request is then gated in order:

1. **Malware scan** (ClamAV) before anything else touches the file — unreachable scanner means rejected upload, not skipped scan
2. **Structural check** — a PDF carrying JavaScript, a launch action or an embedded file is refused before any parser sees it
3. **Signature check** — the bytes must hash to the value the officer signed, and that signature must verify against their registered public key

Only then is the file stored and queued for processing in Celery:

4. **Tesseract OCR** to extract text from scans and photographed documents
5. **spaCy PII redaction** to produce a redacted variant for lower-clearance viewers
6. **Sentence-transformer embeddings** written to `pgvector` for semantic search across the corpus
7. **Fernet encryption at rest** in MinIO, under a data key wrapped by the root key

### Retention

Retention windows are runtime-configurable — no redeploy, no restart. A Celery beat task sweeps every 30 seconds, purges evidence past its window, and writes the purge itself to the audit ledger. Deletion is an audited event, not an absence of one.

---

## Stack

| Layer | Technology |
|---|---|
| API | FastAPI |
| Sessions | Opaque server-validated tokens, Argon2id password hashing, TOTP step-up |
| Client crypto | WebCrypto RSA-PSS, non-extractable keys in IndexedDB |
| Database | PostgreSQL + pgvector |
| Async processing | Celery + Redis (broker and result backend), Celery beat for scheduled sweeps |
| Object storage | MinIO (S3-compatible), plus an object-locked bucket for checkpoints |
| Malware scanning | ClamAV, fail-closed on the upload path |
| Migrations | Alembic |
| On-chain anchoring | Solidity, web3.py |
| OCR / NLP | Tesseract, spaCy, sentence-transformers |
| Frontend | Next.js, WebCrypto, browser BarcodeDetector for QR tags |

---

## What you can do in it

| Role | Can |
|---|---|
| Investigating Officer | Register cases, assign officers, upload evidence, register and transfer physical items, grant document access |
| Forensics Officer | Upload evidence and take custody of physical items on cases they are assigned to |
| Court Official | Read cases they are assigned to; unredacted content only through an explicit, time-bound grant; search returns metadata, not content |
| Administrator | Everything above, plus user and role management, signing-key revocation, encryption-key rotation, retention policy, and ledger verification |

The frontend covers all of it — evidence, cases, physical evidence with QR
scanning, the audit ledger, administration, and a Security page for the second
factor and signing keys. See `frontend/README.md` for the page-by-page tour and
`backend/README.md` for the API surface.

---

## Repository layout

```
backend/          FastAPI service
  app/api/v1/     route modules, one per resource
  app/services/   the security model: audit, checkpoints, officer_keys,
                  encryption, key_management, malware_scan, file_inspection,
                  devices, sessions, mfa, rate_limit, blockchain
  app/tasks/      Celery workers and the beat schedule
  app/models/     SQLAlchemy entities
  alembic/        migrations
  scripts/        contract deployment, user seeding
frontend/         Next.js app (see frontend/README.md)
infrastructure/   docker-compose for Postgres, Redis, MinIO, Ganache, ClamAV
```

---

## Running locally

Requires Docker, Python 3.11+, Node 20+, and Tesseract on the host
(`sudo apt install -y tesseract-ocr`, `brew install tesseract`, or the
[Windows installer](https://github.com/UB-Mannheim/tesseract/wiki)) — OCR runs in the
Celery worker process, not in a container.

**1. Infrastructure.** Compose reads its credentials from `infrastructure/.env`, which is
gitignored and has no committed template — create it first:

```bash
git clone https://github.com/abhnvgrg/dms-core
cd dms-core

cat > infrastructure/.env <<'EOF'
POSTGRES_DB=nyayvault
POSTGRES_USER=nyayvault
POSTGRES_PASSWORD=nyayvault-dev-password
MINIO_ROOT_USER=nyayvault
MINIO_ROOT_PASSWORD=nyayvault-dev-password
EOF

docker compose -f infrastructure/docker-compose.yml up -d postgres redis minio ganache
```

Add `clamav` to that list if you intend to leave malware scanning on — see
[What can be skipped](#what-can-be-skipped) below.

**2. Backend.**

```bash
cd backend
python -m venv .venv
source .venv/Scripts/activate          # Windows (Git Bash); macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
python -m spacy download en_core_web_sm

cp .env.example .env
```

Then fill in `backend/.env`:

- `DATABASE_URL` / `MINIO_ACCESS_KEY` / `MINIO_SECRET_KEY` — match the values in
  `infrastructure/.env`
- `ROOT_ENCRYPTION_KEY` — wraps every data encryption key and the checkpoint signing key:
  `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`
- `BLOCKCHAIN_DEPLOYER_PRIVATE_KEY` — Ganache runs with `--wallet.deterministic`, so use
  account 0's private key printed in `docker compose logs ganache`

```bash
alembic upgrade head              # schema
python scripts/deploy_contract.py # deploy AuditAnchor.sol — paste the printed address
                                  # into BLOCKCHAIN_CONTRACT_ADDRESS in .env
python scripts/seed_users.py      # prompts for one dev password (12+ chars) for
                                  # IO-001 / FOR-001 / COURT-001 / ADM-001
```

Three processes, one per terminal:

```bash
uvicorn app.main:app --port 8000 --reload
celery -A app.tasks.celery_app worker --pool=solo --loglevel=info
celery -A app.tasks.celery_app beat --loglevel=info
```

Interactive API docs — the fastest way to poke at the system — are at
`http://localhost:8000/docs`.

The worker and beat processes are not optional decoration. Beat drives three
schedules, and without them evidence is never OCR'd, never anchored, never
checkpointed and never purged:

| Job | Runs | Does |
|---|---|---|
| `purge_expired_documents` | every 30s | Deletes evidence past the retention window, writing the purge to the ledger |
| `create_audit_checkpoint` | every 60s | Signs a checkpoint once 50 entries or 5 minutes have accumulated |
| `expire_access_grants` | every 60s | Records lapsed grants as `access_grant_expired` |

Blockchain anchoring is queued per ledger entry on commit rather than scheduled,
so a chain outage degrades to "not yet anchored" instead of blocking writes.

**3. Frontend.**

```bash
cd frontend
npm install
npm run dev
```

Serves on `http://localhost:3000` and talks to `http://localhost:8000` unless
`NEXT_PUBLIC_API_URL` says otherwise.

**First sign-in.** Two things are deliberately gated:

- **Every account's first sign-in** gets an enrollment-only session, because a login from
  an unrecognised browser or network requires a second factor and a first login is by
  definition unfamiliar. Administrators stay gated on every login until enrolled.
  Nothing else opens until that is done — the page it lands on is the one that does it.
- **Uploading or transferring custody** requires a signing key. Generate one under
  **Security**; it is created in the browser and the private half stays there, so each
  officer does this once per device.

### What can be skipped

**No testnet, no faucet, no public RPC.** Anchoring targets a local Ganache container on
`http://localhost:8545`. There is nothing external to sign up for.

Two controls are togglable in `backend/.env` when you want a faster first run:

| Flag | Effect when off |
|---|---|
| `BLOCKCHAIN_ANCHORING_ENABLED=false` | Skips the chain entirely. `POST /audit/ledger/{id}/verify-onchain` returns `NOT_YET_ANCHORED`; the Postgres hash chain and `GET /audit/verify` still work. Leaving `BLOCKCHAIN_CONTRACT_ADDRESS` empty has the same effect, so you can defer `deploy_contract.py`. |
| `MALWARE_SCANNING_ENABLED=false` | Skips ClamAV. Worth doing on a first run — the `clamav` service downloads its signature database for several minutes on first start, and while it is unreachable scanning **fails closed**: every upload is rejected with `503`. |

Postgres, Redis, and MinIO are not optional. Tesseract and spaCy failures degrade
gracefully — the document still uploads, hashes, and audits, it just carries no extracted
text.

---

## Demonstrating tamper detection

About two minutes, playing the part of a database administrator trying to erase a
custody record. Uses the seeded `ADM-001` account — audit verification is admin-only —
and `jq` to keep the output readable.

```bash
# 0. Shell aliases for the two things we keep reaching for
API=http://localhost:8000/api/v1
PSQL="docker compose -f infrastructure/docker-compose.yml exec -T postgres psql -U nyayvault -d nyayvault"

TOKEN=$(curl -s -X POST $API/auth/login -d "username=ADM-001&password=<seeded password>" | jq -r .access_token)
```

**1. Establish the baseline.** Sign in at `http://localhost:3000`, generate a signing key
under Security, and upload a document. Give the Celery worker a second to anchor it and
the checkpoint job a moment to sign it (or force one from the Audit Ledger page), then
verify:

```bash
curl -s -H "Authorization: Bearer $TOKEN" $API/audit/verify
# {"status":"VERIFIED","chain_status":"VERIFIED","entries_checked":90,
#  "checkpoint_status":"VERIFIED","checkpoints_checked":1,
#  "entries_covered_by_checkpoints":90,"mirrored_to_write_once_store":1}
```

Pick the newest entry that has actually made it on-chain, and confirm it independently:

```bash
$PSQL -c "select id, action_type from audit_ledger where chain_tx_hash is not null order by id desc limit 1;"

curl -s -X POST -H "Authorization: Bearer $TOKEN" $API/audit/ledger/7/verify-onchain
# {"entry_id":7,...,"match":true,"status":"VERIFIED"}
```

**2. Rewrite history directly in the database** — no API, no credentials, straight
`UPDATE`:

```bash
$PSQL -c "update audit_ledger set payload = payload || '{\"document_id\": \"00000000-0000-0000-0000-000000000000\"}'::jsonb where id = 7;"

curl -s -H "Authorization: Bearer $TOKEN" $API/audit/verify
# {"status":"TAMPERED","chain_status":"TAMPERED","broken_at_entry_id":7,
#  "reason":"entry_hash mismatch"}
```

The chain recompute catches it: entry 7's stored hash no longer matches its payload.

**3. Try to cover it up.** Repairing the hashes is what someone with write access would
actually do — recompute entry 7 and every entry after it, so the chain is internally
consistent again. Now the chain check passes and the checkpoint check does not:

```bash
curl -s -H "Authorization: Bearer $TOKEN" $API/audit/verify
# {"status":"TAMPERED","chain_status":"VERIFIED","checkpoint_status":"TAMPERED",
#  "broken_at_checkpoint_id":1,
#  "reason":"ledger entries no longer hash to the recorded checkpoint value"}
```

The checkpoint was signed with a key the database never holds, and a copy of it sits in
an object-locked bucket. Repairing the chain is exactly what makes it disagree with the
checkpoint.

**4. And the on-chain copy, independently:**

```bash
curl -s -X POST -H "Authorization: Bearer $TOKEN" $API/audit/ledger/7/verify-onchain
# {"entry_id":7,"db_entry_hash":"...","onchain_entry_hash":"...","match":false,"status":"TAMPERED"}
```

Three checks, one database. Editing a payload breaks the chain; repairing the chain
breaks the checkpoint; and neither touches what is already on-chain.

The same holds for the files themselves — mutate an object in MinIO and
`POST /documents/{id}/verify` returns `TAMPERED`, because it re-reads the stored bytes,
recomputes the SHA-256, and re-checks the RSA-PSS signature over that hash.

---

## Design notes

This is the fourth revision of the architecture. Each revision exists because the previous
one left something under-specified, and the changes worth knowing about are these:

- **v1 → v2** moved integrity from a feature to a structural property: hash-chained audit
  ledger, digital signatures wired into the actual workflows rather than mentioned, an
  async task queue so cryptographic work never blocks the request, and a named storage
  backend with encryption at rest.
- **v2 → v3** specified the things v2 assumed: login flow, password hashing, token
  lifecycle and revocation, an explicit RBAC permission matrix, officer signing-key
  custody, upload validation and rate limiting, transactional evidence transfers.
- **v3 → v4** is the largest jump: every change in it closes something v3 left ambiguous.
  "Who can see the unredacted document" was a fuzzy RBAC cell that never said who
  elevates, for how long, or whether it was logged — replaced by first-class classification
  levels plus time-bound, audited, revocable grants. The audit ledger had no external
  anchor, so a rewrite by anyone with database access was undetectable — anchoring added.
  Stateless JWTs meant revocation and classification changes did not take effect until
  expiry — replaced by opaque, server-validated session tokens. MFA and malware scanning
  moved from "optional, phase 2" to mandatory.

---

## Limitations

Stated plainly, because these are the questions worth asking about the system:

- **The checkpoint thresholds are the detection window.** A checkpoint is signed once 50
  entries or five minutes have accumulated, so entries written since the last one are
  covered by the hash chain and the on-chain anchor but not yet by a signed checkpoint.
  Anchoring is likewise queued on commit rather than written inside the request, so an
  entry created during a chain outage sits at `NOT_YET_ANCHORED` until the worker catches
  up. Writes are never blocked on either — the right trade for availability, the wrong one
  for instant coverage.
- **The chain is a local dev chain, not a public network.** Anchoring targets Ganache. An
  anchor is only as independent as the ledger holding it, and a Ganache container on the
  same host is not independent of the operator — it demonstrates the mechanism, it does not
  provide the guarantee. A real deployment needs a network the operator cannot rewrite.
  The signed checkpoints carry more weight here, since their key is genuinely outside the
  database.
- **The root key is the remaining single point of trust.** `ROOT_ENCRYPTION_KEY` stands in
  for an HSM or KMS. It wraps the per-purpose data keys and the checkpoint signing key,
  all of which rotate without re-encrypting history — but the root itself is a value in
  `.env`. Officer signing keys are not affected: those are generated in the browser and
  the server never holds them.
- **Object lock depends on the deployment.** The checkpoint bucket is created with object
  lock where MinIO supports it, and falls back to a plain bucket where it does not, which
  weakens "write-once" to "separate". The checkpoint row records whether the mirror
  succeeded.
- **OCR is English, and images only.** Tesseract runs on `image/jpeg` and `image/png` with
  no language hint. PDFs are accepted, hashed, encrypted, and audited, but never OCR'd —
  which means no extracted text, no PII redaction, and no embedding, so they are silently
  absent from semantic search results. Handwriting and Devanagari/regional scripts are
  untested; the Hindi/English OCR the original design called for was never built. spaCy's `en_core_web_sm`
  catches names, places, and organisations but not phone numbers, emails, or ID numbers —
  redacted output is a lower-clearance view, not a compliance guarantee.
- **A browser is a device, not an identity.** A signing key lives in one browser profile.
  An officer on a second machine registers a second key — normal, and the old one is
  retired — but losing the device means losing the ability to make new signatures with
  that key, and there is no hardware-backed or enclave-held option.
- **There is no automated test suite.** The behaviour above has been exercised end to end
  by hand, but nothing guards it against regression.
- **Scale is untested beyond demo volume.** Single-node Postgres, Redis, and MinIO; the
  Celery worker runs `--pool=solo`, one task at a time, since prefork isn't usable on the
  Windows dev machine this was built on. Semantic search is an unindexed exact scan over pgvector
  (no IVFFlat/HNSW index), and the retention sweep re-queries every document every 30
  seconds. Nothing here has been load-tested; the ceiling is unknown rather than high.

---

## Not deployed

NyayVault runs stateful background workers, a Postgres instance with `pgvector`, object
storage, and a chain RPC connection. There is no live hosted demo — the architecture
doesn't fit a serverless frontend host, and a partially-working demo would misrepresent
the system.

To evaluate it, run it locally with the steps above and walk through
[Demonstrating tamper detection](#demonstrating-tamper-detection) — that sequence is the
whole claim, and it takes about two minutes against a fresh install.