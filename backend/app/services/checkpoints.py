"""Signed audit checkpoints, mirrored to write-once object storage.

The in-database hash chain proves the ledger is internally consistent. It does
not prove the ledger was not regenerated from scratch, because whoever can
rewrite rows can also recompute every hash. A checkpoint closes that: it is
signed with a key the database never holds, and a copy is written to a bucket
under object lock, so verification can ask three questions instead of one --
is the chain consistent, do the entries still hash to the recorded checkpoint,
and is the checkpoint's signature intact.
"""
import base64
import hashlib
import json
from datetime import datetime, timezone

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.entities import AuditCheckpoint, AuditLedger, EncryptionKeyPurpose
from app.services import key_management, storage

_PADDING = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)


async def _load_signing_key(session: AsyncSession) -> tuple[int, rsa.RSAPrivateKey]:
    """Fetch (or mint) the checkpoint signing key, wrapped under the root key.

    Distinct from the officer keys and from both data encryption keys: this one
    signs checkpoints and nothing else.
    """
    version, raw = await key_management.get_or_create_pem_key(
        session, EncryptionKeyPurpose.CHECKPOINT_SIGNING
    )
    private_key = serialization.load_pem_private_key(raw, password=None)
    return version, private_key


async def _public_key_pem(session: AsyncSession, version: int) -> bytes:
    raw = await key_management.get_key_version(
        session, EncryptionKeyPurpose.CHECKPOINT_SIGNING, version
    )
    private_key = serialization.load_pem_private_key(raw, password=None)
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def compute_checkpoint_hash(entry_hashes: list[str]) -> str:
    return hashlib.sha256("".join(entry_hashes).encode("utf-8")).hexdigest()


async def get_latest(session: AsyncSession) -> AuditCheckpoint | None:
    return await session.scalar(
        select(AuditCheckpoint).order_by(AuditCheckpoint.to_entry_id.desc()).limit(1)
    )


# A checkpoint is due once either threshold is reached, so a busy period is
# covered by volume and a quiet one by the clock.
CHECKPOINT_AFTER_ENTRIES = 50
CHECKPOINT_AFTER_SECONDS = 300


async def create_checkpoint(
    session: AsyncSession, force: bool = True
) -> AuditCheckpoint | None:
    """Checkpoint every ledger entry written since the last one.

    With `force=False` the thresholds decide, which is how the scheduled job
    calls it; the admin endpoint forces one regardless. Returns None when there
    is nothing to sign, or nothing due yet.
    """
    latest = await get_latest(session)
    start_after = latest.to_entry_id if latest else 0

    result = await session.execute(
        select(AuditLedger)
        .where(AuditLedger.id > start_after)
        .order_by(AuditLedger.id.asc())
    )
    entries = list(result.scalars().all())
    if not entries:
        return None

    if not force:
        age_seconds = CHECKPOINT_AFTER_SECONDS
        if latest is not None:
            created_at = latest.created_at
            if created_at.tzinfo is None:
                created_at = created_at.replace(tzinfo=timezone.utc)
            age_seconds = (datetime.now(timezone.utc) - created_at).total_seconds()

        if len(entries) < CHECKPOINT_AFTER_ENTRIES and age_seconds < CHECKPOINT_AFTER_SECONDS:
            return None

    entry_hashes = [entry.entry_hash for entry in entries]
    checkpoint_hash = compute_checkpoint_hash(entry_hashes)

    version, private_key = await _load_signing_key(session)
    signature = base64.b64encode(
        private_key.sign(checkpoint_hash.encode("utf-8"), _PADDING, hashes.SHA256())
    ).decode("utf-8")

    checkpoint = AuditCheckpoint(
        from_entry_id=entries[0].id,
        to_entry_id=entries[-1].id,
        entry_count=len(entries),
        checkpoint_hash=checkpoint_hash,
        signature=signature,
        signing_key_version=version,
    )
    session.add(checkpoint)
    await session.flush()

    # Mirror to the write-once bucket. A storage outage must not lose the
    # checkpoint itself, so the row is kept either way and object_key stays null.
    document = {
        "checkpoint_id": checkpoint.id,
        "from_entry_id": checkpoint.from_entry_id,
        "to_entry_id": checkpoint.to_entry_id,
        "entry_count": checkpoint.entry_count,
        "checkpoint_hash": checkpoint_hash,
        "signature": signature,
        "signing_key_version": version,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    try:
        object_key = storage.put_checkpoint(checkpoint.id, json.dumps(document, indent=2).encode("utf-8"))
        checkpoint.object_key = object_key
        await session.flush()
    except Exception:
        pass

    return checkpoint


async def verify_checkpoints(session: AsyncSession) -> dict:
    """Re-derive every checkpoint from the ledger and re-check its signature."""
    result = await session.execute(select(AuditCheckpoint).order_by(AuditCheckpoint.id.asc()))
    checkpoints = list(result.scalars().all())

    if not checkpoints:
        return {
            "status": "NO_CHECKPOINTS",
            "checkpoints_checked": 0,
            "entries_covered": 0,
            "mirrored_to_write_once_store": 0,
        }

    public_keys: dict[int, object] = {}
    entries_covered = 0
    mirrored = 0

    for checkpoint in checkpoints:
        result = await session.execute(
            select(AuditLedger)
            .where(
                AuditLedger.id >= checkpoint.from_entry_id,
                AuditLedger.id <= checkpoint.to_entry_id,
            )
            .order_by(AuditLedger.id.asc())
        )
        entries = list(result.scalars().all())

        if len(entries) != checkpoint.entry_count:
            return {
                "status": "TAMPERED",
                "broken_at_checkpoint_id": checkpoint.id,
                "reason": (
                    f"checkpoint covers {checkpoint.entry_count} entries but "
                    f"{len(entries)} are present -- entries were deleted or inserted"
                ),
                "checkpoints_checked": len(checkpoints),
            }

        recomputed = compute_checkpoint_hash([entry.entry_hash for entry in entries])
        if recomputed != checkpoint.checkpoint_hash:
            return {
                "status": "TAMPERED",
                "broken_at_checkpoint_id": checkpoint.id,
                "reason": "ledger entries no longer hash to the recorded checkpoint value",
                "checkpoints_checked": len(checkpoints),
            }

        if checkpoint.signing_key_version not in public_keys:
            try:
                public_keys[checkpoint.signing_key_version] = serialization.load_pem_public_key(
                    await _public_key_pem(session, checkpoint.signing_key_version)
                )
            except Exception:
                return {
                    "status": "UNVERIFIABLE",
                    "broken_at_checkpoint_id": checkpoint.id,
                    "reason": f"checkpoint signing key v{checkpoint.signing_key_version} is unavailable",
                    "checkpoints_checked": len(checkpoints),
                }

        try:
            public_keys[checkpoint.signing_key_version].verify(
                base64.b64decode(checkpoint.signature),
                checkpoint.checkpoint_hash.encode("utf-8"),
                _PADDING,
                hashes.SHA256(),
            )
        except Exception:
            return {
                "status": "TAMPERED",
                "broken_at_checkpoint_id": checkpoint.id,
                "reason": "checkpoint signature does not verify",
                "checkpoints_checked": len(checkpoints),
            }

        entries_covered += checkpoint.entry_count
        if checkpoint.object_key:
            mirrored += 1

    return {
        "status": "VERIFIED",
        "checkpoints_checked": len(checkpoints),
        "entries_covered": entries_covered,
        "mirrored_to_write_once_store": mirrored,
    }
