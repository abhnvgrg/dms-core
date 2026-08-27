# Access control: sessions, roles, and step-up

This document covers `app/api/deps.py` and `app/services/sessions.py` — who the
caller is, and what they are allowed to do. The code carries no commentary, so
the reasoning lives here. For the tamper-evidence side, see
[audit-integrity.md](audit-integrity.md).

---

## Why this layer matters more than the hash chain

The ledger proves nobody altered the record of what happened. Access control
decides what is allowed to happen in the first place, and who can read evidence
belonging to a case they are not on. A flawless audit trail of an unauthorised
download is still an unauthorised download.

---

## Sessions

Access and refresh tokens are separate 32-byte random strings, and the database
stores only their SHA-256 fingerprints. Same reasoning as everywhere else here:
a leaked database file, backup, or volume snapshot must not hand over live
sessions.

**Two lifetimes, deliberately.** The access token lives 15 minutes, the refresh
token 8 hours. A stolen access token is useful for a short window; the refresh
token is presented rarely, so it spends most of its life not crossing the wire.

**Rotation with reuse detection.** Every refresh mints a new pair and stores
the old refresh hash in `previous_refresh_token_hash`. If a token that has
already been rotated is presented again, that means two parties hold it — the
legitimate user and a thief — and there is no way to tell which one is asking.
So the session is revoked outright and `RefreshRejected(reused=True)` carries
the user id up to the caller, which logs it to the ledger. Refusing the request
without killing the session would leave the thief holding a working token.

This is why `test_rotation_twice_over_keeps_only_the_newest_token_live` matters:
only the most recent refresh token works, and presenting the one before it is
treated as compromise, not as a mistake.

**Tokens are not interchangeable.** An access token cannot rotate a session and
a refresh token cannot authenticate a request, because each is looked up
against its own column. Both directions are tested.

---

## Identity resolution

`get_current_user` re-reads the user row on every request. Nothing about the
caller is carried in the token itself.

Three things fall out of that, all tested:

- **Deactivation is immediate.** Setting `is_active = False` closes an already
  open session on the next request.
- **Role changes are immediate**, in both directions. A demotion applies to a
  session opened while the user was still an admin; a promotion applies without
  re-login.
- **A deleted user cannot act**, even holding a live session token.

A role embedded in the token would outlive every one of those changes.

---

## The MFA enrolment gate

A privileged account that has not yet enrolled MFA gets a session flagged
`mfa_pending`. That session can do exactly one thing: enrol.

`get_current_user` rejects it with 403; `get_enrolling_user` accepts it. The two
dependencies are otherwise identical, and the split is what stops the enrolment
endpoint from becoming a hole — a caller cannot use an enrolment-only session
to reach the application, and cannot use the enrolment route to skip being
active either, since `get_enrolling_user` still checks `is_active`.

---

## Step-up authentication

`require_fresh_mfa` guards actions with legal consequences. A valid session is
not enough; the caller must also present a current TOTP code in `X-MFA-Code`.

**It fails closed.** A user who never enrolled cannot perform these actions at
all — 403, not a bypass. This is the property worth stating explicitly, because
the naive implementation ("if the user has MFA, check it") turns not enrolling
into a way to skip the check entirely.

**Codes are single-use.** TOTP codes stay valid for a window of up to 90
seconds with `valid_window=1`, so a code captured in transit can be replayed
inside that window. Used codes are recorded in Redis with a 180-second TTL,
covering the whole validity window plus clock skew.

---

## Case-level authorisation

Role checks answer "is this caller an admin". They do not answer "is this
officer on this case", which is the question that actually protects evidence.
Two functions carry that:

**`_get_case_if_authorized`** — an admin reaches any case; anyone else needs a
row in `case_assignments`. A missing case is 404, an unassigned one is 403.
Being assigned to one case grants nothing on another, and a court official
needs an assignment like everyone else.

**`_enforce_classification`** — layered on top, because assignment alone is not
enough for the most sensitive material:

| Classification | Officer / forensics | Court official | Admin |
|---|---|---|---|
| `public_redacted` | read | read | read |
| `case_restricted` | read | **403** | read |
| `court_elevated` | read | needs a live grant | read |
| `admin_only` | **404** | **404** | read |

Two deliberate choices in that table are worth stating.

**`admin_only` returns 404, not 403.** A 403 confirms the document exists,
which is itself a disclosure — knowing that a sealed document exists on a case
can be as informative as reading it. The listing queries filter `admin_only`
out for non-admins for the same reason, so the two paths agree.

**`court_elevated` is only elevated for court officials.** Investigating and
forensics officers assigned to the case read it without a grant. The
classification gates the court's access, not the investigation's. That is not
obvious from the name, so `test_a_court_official_needs_a_grant_for_elevated_documents`
and the officer-side test sit next to each other to make the asymmetry legible.

Grants are checked four ways, each with a test: expired grants do not open a
document, revoked grants do not, a grant issued to a different person does not,
and a grant on a different document does not carry over.

The listing endpoints scope identically to the single-document path — an
officer sees only documents on cases they are assigned to, and never
`admin_only`. `search_documents` applies the same two filters, and additionally
returns metadata without content snippets to court officials.

---

## Test approach

`tests/test_rbac.py` builds a small FastAPI app whose endpoints depend on the
real `deps.py` guards, then overrides only `get_db` to point at the test
session. The guards themselves run exactly as they do in production — this is
not a reimplementation of the rules.

Two external services are controlled rather than stubbed away:

- **Redis** backs the MFA replay cache. An autouse fixture swaps
  `is_code_used` / `mark_code_used` for an in-memory set, so replay is still
  genuinely tested, without requiring Redis to run.
- **Object storage**, as described in [audit-integrity.md](audit-integrity.md).

`tests/test_case_access.py` calls the authorisation functions and the listing
endpoints directly against real rows, rather than through HTTP. Upload and
download need object storage and the Celery pipeline; the authorisation
decision does not, and that decision is what is under test.

The suite was mutation-checked rather than trusted for being green:

| Guard disabled | Tests that failed |
|---|---|
| role comparison in `require_roles` | 4 |
| `mfa_enabled` check in `require_fresh_mfa` | 1 |
| `mfa_pending` gate in `get_current_user` | 1 |
| case assignment check | 4 |
| access grant check | 5 |
| `admin_only` filter on the listing query | 1 |

A guard that can be removed without a test noticing is not a tested guard.

---

## The route-guard audit

`tests/test_case_access.py` proves the guards work. It does not prove they are
*attached* — a route shipped with no decorator at all would pass every test in
this document. `tests/test_route_guards.py` closes that.

It walks every route in all seven routers, recursively resolves each one's
FastAPI dependency tree, and asserts:

- **Every route is authenticated** unless it is on an explicit `PUBLIC_ROUTES`
  list. Adding an unguarded route fails the suite by name, and the failure
  message says to either guard it or add it to the list with a reason.
- **The public list is honest in both directions.** A route on the list that
  turns out to be guarded also fails, so the list cannot rot into a lie about
  what is exposed.
- **Every admin route requires an administrator**, allowing either form (see
  below).
- **Only the enrolment routes accept an MFA-pending session.** Any other route
  reaching for `get_enrolling_user` fails.
- **A role check never appears without authentication**, and step-up never
  appears without ordinary authentication.
- **Guards are the ones `deps.py` exports**, not a shadowed local copy with the
  same name.

The role a guard permits is read out of the `role_guard` closure, so the audit
compares against the actual `Role` enum rather than a string.

Mutation-checked: replacing one route's `Depends(get_current_user)` with a
no-op dependency fails the audit, naming that exact route.

### Two forms of admin enforcement

The audit found that four routes in `admin.py` — `POST /admin/users`,
`PATCH /admin/users/{user_id}`, `POST /admin/signing-keys/{key_id}/revoke`, and
`POST /admin/keys/{purpose}/rotate` — have **no** `require_roles(Role.ADMIN)`
dependency. They use `require_fresh_mfa` and then check the role inline:

```python
if current_user.role != Role.ADMIN:
    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, ...)
```

That is a real check and it does deny non-admins, so this is not a hole. It is
an inconsistency: two ways of expressing the same rule, one of which is
invisible to any dependency-level audit or to `/docs`.

The audit therefore accepts either form, but requires *one* of them: a route
with neither a role dependency nor an inline check that raises 403 fails. It
additionally requires that any route relying on the inline form at least
carries step-up authentication, which all four do.

Worth converting to `Depends(require_roles(Role.ADMIN))` when convenient — the
declarative form is visible in the OpenAPI schema and cannot be skipped by an
early return added later in the body.

---

## Known limits
- `search_documents` is untested: it needs a real embedding vector, which means
  the spaCy model and the AI pipeline. The metadata-only behaviour for court
  officials is therefore asserted by reading, not by a test.
- Upload, download, and classification changes are untested — they need object
  storage and the Celery pipeline.
- Session records are never pruned; revoked and expired rows accumulate.
- The replay cache is Redis-only. If Redis is unavailable, `is_code_used`
  raises rather than failing closed, so step-up breaks rather than degrading.
