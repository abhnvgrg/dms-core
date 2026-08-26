# NyayVault — Frontend

Next.js + TypeScript frontend for NyayVault. Built against the "Operational
Efficiency System" design tokens — sharp corners, heavy borders, oversized
readable type, zero decoration.

Two things make this more than a thin client over the API: **officer signing
keys are generated and held here**, so the server can only ever verify a
signature; and **custody transfers survive going offline**, queued signed and
replayed on reconnect.

## Setup

```bash
npm install
```

Point `.env.local` at your running backend (this is the default, so the file is
optional):

```
NEXT_PUBLIC_API_URL=http://localhost:8000
```

Start the backend first (see `../backend/README.md`), then:

```bash
npm run dev
```

Visit `http://localhost:3000`. It redirects to `/login` when signed out and
`/dashboard` when signed in.

Sign in with a badge number seeded by `backend/scripts/seed_users.py`
(`IO-001`, `FOR-001`, `COURT-001`, `ADM-001`) and the password set at seed time.

### First sign-in takes two extra steps

Both are deliberate, and the UI walks you through them:

1. **Enrol a second factor.** A first login always comes from an unrecognised
   browser, and the backend requires MFA for those, so the session that lands
   can only reach `/security` until enrollment completes. The page shows the
   TOTP secret and its provisioning URI as text — paste either into an
   authenticator app, then confirm with the current code. Activating issues a
   fresh session and retires the one you enrolled with.
2. **Generate a signing key** (also on `/security`) if you intend to upload
   evidence or move custody. It is created in the browser, and the private half
   never leaves it — so this is per person *per device*.

## Pages

| Route | What it does |
|---|---|
| `/login` | Badge number, password, and the TOTP field once a second factor is enrolled |
| `/dashboard` | Evidence for your assigned cases, plus semantic search |
| `/cases` | Register a case, see the ones you are on, assign officers |
| `/upload` | Hashes and signs the file in the browser, then uploads |
| `/evidence/[id]` | Verify integrity, download, reclassify, manage access grants, read the custody record |
| `/assets` | Register tagged items, scan a QR tag, transfer custody, review the queue |
| `/audit` | Chain verification, signed checkpoints, on-chain comparison *(admin)* |
| `/admin` | Officers, roles, signing-key revocation, encryption keys, retention *(admin)* |
| `/security` | MFA enrollment, signing keys, sign out everywhere |

Actions with legal consequence — access grants, reclassification, custody
transfers, user management, key rotation — ask for a current authenticator code
inline and send it as `X-MFA-Code`. A code is single-use.

## How the client-side crypto works

`lib/crypto.ts` is the whole of it:

- `generateKeypair` creates an RSA-PSS keypair through WebCrypto with
  `extractable: false`, stores the private `CryptoKey` in IndexedDB, and returns
  the public half as PEM for registration. Page script can use the key but
  cannot read it.
- `sha256Hex` + `signMessage` produce what `/documents/upload` expects: the
  hash of the bytes and a base64 signature over that hash.
- `transferMessage` builds the exact string the backend reconstructs for a
  custody handover. **Key order and separators must stay byte-identical to
  `transfer_message` in `backend/app/api/v1/assets.py`** — the keys are listed
  alphabetically because Python serialises with `sort_keys=True`.

Losing the browser profile means losing the ability to sign with that key.
Generating a new one retires the old public key rather than deleting it, so
everything signed earlier still verifies.

## Offline custody transfers

`lib/offline-queue.ts` holds handovers prepared without a connection. Each entry
is already signed and carries the custody status the officer believed the item
was in.

That expected status is what makes a late sync safe. If someone else moved the
item first, the backend answers 409 and records a conflict rather than applying
a second handover; the queue marks that entry and surfaces it for a human. The
queue drains automatically when the browser comes back online, and `/assets`
also offers a manual **Sync now**.

## Sessions

Access tokens last 15 minutes and refresh tokens 8 hours, single-use. `authFetch`
in `lib/api.ts` retries a 401 once behind a shared refresh promise — concurrent
callers must not each spend the refresh token, because reusing a spent one is
treated as theft and revokes the whole session family.

Tokens live in `localStorage` (`dms_token`, `dms_refresh_token`, `dms_user`).
That is a demo-grade choice; httpOnly cookies would be the production answer.
The stored session is read through `useSyncExternalStore`, so signing in or out
in one tab is picked up by the others.

## Demoing tamper detection

1. Upload a file from `/upload`.
2. Open its record and click **Verify integrity** → `VERIFIED`, naming the
   officer who signed it.
3. Edit the stored object in MinIO, or the matching `audit_ledger` row in
   Postgres, to play the part of someone with direct database access.
4. Verify again → `TAMPERED`, with the two hashes side by side. For the ledger,
   `/audit` shows the same thing three ways: chain, signed checkpoints, and the
   on-chain anchor. Repairing the chain to hide an edit is exactly what makes
   the checkpoint disagree.

## Structure

```
app/
  login/          admin/         security/      cases/
  dashboard/      assets/        audit/         upload/
  evidence/[id]/  layout.tsx     globals.css    page.tsx
components/
  AppShell.tsx    header, role-aware nav, signing-key reminder
  QrScanner.tsx   camera scanning via the browser BarcodeDetector, manual fallback
  ui.tsx          shared primitives (Card, Table, Badge, Field, Alert, Mono)
lib/
  api.ts          typed client for every backend endpoint, refresh handling
  auth-context.tsx  session state over localStorage as an external store
  crypto.ts       keypair generation, signing, canonical transfer message
  offline-queue.ts  queued signed handovers and their conflict states
```

## Notes

- QR scanning uses the browser's own `BarcodeDetector` where available, with
  manual tag entry as the fallback. No scanner library, and no frame leaves the
  device.
- `app/globals.css` strips Tailwind's rounded corners and shadows globally to
  match the institutional look in the design brief.
- If the backend contract changes, `lib/api.ts` is the only file that needs to
  follow it.
