# DMS Frontend

Next.js + TypeScript + Tailwind frontend for the Digital Evidence Management
System. Built against the "Operational Efficiency System" design tokens —
sharp corners, heavy borders, oversized readable type, zero decoration.

## Setup

```bash
npm install
```

Confirm `.env.local` points at your running backend (defaults to
`http://localhost:8000`):
```
NEXT_PUBLIC_API_URL=http://localhost:8000
```

Start the backend first (see `evidence-backend/README.md`), then run the
frontend:

```bash
npm run dev
```

Visit `http://localhost:3000` — it redirects to `/login` if you're signed
out, or `/dashboard` if you're already signed in.

Demo login: `officer1` / `officer123` (or `admin1` / `admin123`)

## Pages

- `/login` — sign in, stores JWT + user info in localStorage
- `/dashboard` — table of all evidence, filterable by case ID
- `/upload` — upload a file under a case ID, shows hash/signature/redacted
  text immediately after upload
- `/evidence/[id]` — full record for one item, with the **Verify Integrity**
  button — the core demo feature. Click it to recompute the file's hash and
  check it against what was recorded at upload time.

## Demoing the tamper-detection flow

1. Upload a file via `/upload`
2. Go to its detail page, click "Verify Integrity" -> green VERIFIED badge
3. On the backend machine, manually edit the stored file:
   ```bash
   echo "tampered" >> evidence-backend/storage/files/<hash>_<filename>
   ```
4. Click "Verify Integrity" again on the same page -> red TAMPERED badge,
   with the mismatched hash values shown side by side

## Structure

```
app/
  login/page.tsx          - sign-in screen
  dashboard/page.tsx       - evidence list + case filter
  upload/page.tsx          - upload form + result summary
  evidence/[id]/page.tsx   - record detail + verify integrity
  layout.tsx               - root layout, wraps app in AuthProvider
  globals.css              - design system tokens and component classes
components/
  AppShell.tsx             - shared header + sidebar nav for authenticated pages
lib/
  api.ts                   - typed API client for every backend endpoint
  auth-context.tsx         - React context for auth state (token, user, sign in/out)
```

## Notes

- Auth state lives in localStorage (dms_token, dms_user) - no cookies,
  no server-side session. Fine for a demo; would move to httpOnly cookies
  for anything real.
- All API calls go through lib/api.ts - if the backend contract changes,
  that's the only file that needs updating.
- Design tokens (app/globals.css) intentionally strip Tailwind's default
  rounded corners and shadows globally to match the sharp, institutional
  look specified in the design brief.
