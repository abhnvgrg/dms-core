# Audit integrity: what the ledger proves, and what it does not

This document covers `app/services/audit.py`, `app/services/checkpoints.py`, and
`app/services/officer_keys.py` — the tamper-evidence machinery that is the
project's central claim. The code carries no commentary, so the reasoning lives
here.

---

## The three layers, and why there are three

Tamper-evidence here is not one mechanism. It is three, each closing a gap the
one below it leaves open.

### Layer 1 — the in-database hash chain

Every ledger entry stores `sha256(previous_entry_hash + canonical_json(event))`.
`verify_ledger` walks the table in id order and recomputes each link.

**What it proves:** no row was edited, deleted from the middle, or reordered.
Changing any byte of any payload changes that entry's hash, which breaks the
`previous_entry_hash` of everything after it.

**What it does not prove:** that the ledger was not rewritten wholesale.
Whoever can edit rows can also recompute every hash from the edit forward, and
the recomputed chain verifies perfectly. The chain is only as trustworthy as
the database's own write controls.

There is a second, narrower gap: **truncation from the tail**. Deleting the
most recent N entries leaves a shorter but internally consistent chain, and
`verify_ledger` returns `VERIFIED`. Deleting from the *front* is caught,
because the new first entry no longer links to `GENESIS`.

Both gaps are covered by tests that assert the current, honest behaviour —
`test_truncating_the_tail_is_not_detected_by_the_chain_alone` and
`test_a_fully_recomputed_chain_is_not_detected_by_the_chain_alone`. They are
not bugs; they are the reason layer 2 exists. If someone later "fixes"
`verify_ledger` to catch these, those tests should fail loudly rather than
letting the change pass unnoticed.

### Layer 2 — signed checkpoints

Periodically, every entry since the last checkpoint is summarised as
`sha256(concatenated entry hashes)` and signed with an RSA key.

This closes the wholesale-rewrite gap, because the signature cannot be
regenerated from the database alone. `verify_checkpoints` asks three separate
questions per checkpoint:

1. Are the covered entries still *present* in the expected number? Catches
   deletion and insertion, including tail truncation inside a checkpointed
   range.
2. Do those entries still hash to the recorded `checkpoint_hash`? Catches
   edits, including a chain that was recomputed to look consistent.
3. Does the signature over that hash still verify? Catches an attacker who
   rewrote the entries *and* the checkpoint row to match.

An attacker would need the signing key to defeat all three.

**Remaining gap:** entries written *after* the most recent checkpoint are
protected by layer 1 only. Shrinking that window is what
`CHECKPOINT_AFTER_ENTRIES` (50) and `CHECKPOINT_AFTER_SECONDS` (300) are for —
whichever comes first, so a busy period is bounded by volume and a quiet one
by the clock.

One asymmetry is worth knowing: when no checkpoint exists yet, `age_seconds`
defaults to `CHECKPOINT_AFTER_SECONDS`, so the threshold comparison is false
and the **first** scheduled checkpoint is always taken regardless of how few
entries are pending. That is the behaviour you want, since a fresh ledger
should not sit unsigned waiting to accumulate 50 entries, but it falls out of
a default value rather than an explicit branch, so
`test_the_first_checkpoint_is_always_due` pins it.

### Layer 3 — write-once mirror and chain anchoring

Each checkpoint is also written to an object-lock bucket, and ledger entries
are queued for anchoring on-chain. These put a copy somewhere the database
administrator cannot reach.

The mirror is deliberately best-effort: if object storage is down, the
checkpoint row is still committed and `object_key` stays null. Losing the
mirror is worse than losing nothing, but losing the checkpoint *because* the
mirror failed would be worse still.

---

## Why the checkpoint key is asymmetric

`get_or_create_pem_key(CHECKPOINT_SIGNING)` mints an RSA private key wrapped
under the root key, distinct from both document-encryption keys and from
officer keys.

It has to be asymmetric so that verifying a checkpoint never requires the
ability to forge one. With an HMAC, any party who can verify can also sign,
which would mean the API server — the thing under suspicion during an
investigation — could produce a checkpoint for any ledger it liked.

A missing or unreadable key returns `UNVERIFIABLE`, deliberately not
`TAMPERED` and never `VERIFIED`. "I cannot check this" and "this is forged"
are different findings, and collapsing them in either direction misleads.

---

## Officer signing keys

The private half is generated in the officer's browser and never transmitted.
The server stores only the public key and can therefore only ever verify — it
cannot sign on an officer's behalf, which is the property that makes an
officer's signature mean anything.

**Rotation retires, it does not delete.** A retired key stays in the table so
signatures made before the rotation remain verifiable. Deleting it would
silently invalidate every historical signature.

**PSS salt length is pinned to 32**, matching what WebCrypto produces.
Python's `AUTO` would also verify, but pinning keeps both halves of the
contract explicit and stops a future change on either side going unnoticed.

**Revocation is time-aware.** `signature_status` returns `valid` for
signatures made before `revoked_at` and `pending_review` for anything after.
Treating every signature from a revoked key as invalid would destroy good
evidence; treating them all as valid would ignore the revocation entirely. The
middle answer is the honest one, and it puts the decision in front of a human.

Registration rejects non-RSA keys and anything under 2048 bits, and refuses a
fingerprint that is already registered — including one already claimed by a
different officer, which would otherwise let someone register a colleague's
public key and muddy attribution.

---

## Canonical JSON

Hashes are computed over `json.dumps(sort_keys=True, separators=(",", ":"))`.
Key order and incidental whitespace must not affect the digest, or an entry
would fail verification after an innocuous round-trip through the database or
a different serialiser version.

---

## Test approach

Tests run against **PostgreSQL**, not SQLite. The models use `JSONB`, native
`UUID`, and a Postgres enum type; a SQLite harness would need type shims, and
would then be verifying behaviour that production never executes. For integrity
code, the storage layer's actual semantics are part of what is under test.

`tests/conftest.py` creates a `nyayvault_test` database if it is absent, builds
the schema once per session, and gives each test a connection inside a
transaction that is rolled back afterwards, so tests share a schema without
sharing state.

Running them:

```
docker compose -f infrastructure/docker-compose.yml up -d postgres
cd backend && pytest
```

Point `NYAYVAULT_TEST_DATABASE_URL` elsewhere to use a different instance. If
Postgres is unreachable the suite exits immediately with that instruction
rather than erroring test by test.

Blockchain anchoring is not stubbed: it is enqueued on `after_commit`, and
these tests roll back rather than commit, so it never fires.

The object-storage mirror is controlled rather than stubbed away. By default an
autouse fixture makes `put_checkpoint` raise, driving the code down the same
path a real MinIO outage takes, and asserts the checkpoint survives with a null
`object_key`. The `working_object_storage` fixture captures what would have
been written instead, so the success path is covered too, including a check
that the mirrored JSON document matches the database row field for field.

Without that control the suite reaches for a live MinIO and every checkpoint
blocks for roughly 25 seconds on connection retries.

---

## Known limits

- Entries after the newest checkpoint have hash-chain protection only.
- Checkpoint thresholds are checked when `create_checkpoint(force=False)` is
  called, so the 300-second bound is only as tight as the scheduler calling it.
- `verify_ledger` loads the whole ledger into memory. Fine at present volumes;
  it needs batching before it is not.
- Nothing verifies the write-once mirror's contents against the database row.
  A checkpoint whose `object_key` is set is counted as mirrored without the
  stored document being re-read and compared. The tests assert the document is
  written correctly; production never reads it back to confirm.
- Coverage stops at the service layer. The `/api/v1/audit` endpoints, RBAC on
  who may force a checkpoint, and the Celery anchoring task are untested.
