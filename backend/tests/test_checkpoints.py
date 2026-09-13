from __future__ import annotations

import base64
import hashlib
import uuid

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from sqlalchemy import delete

from app.models.entities import AuditAction, AuditLedger, EncryptionKeyPurpose
from app.services import audit, checkpoints, key_management

pytestmark = pytest.mark.asyncio

_PADDING = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)


async def _append(session, officer) -> AuditLedger:
    return await audit.append_entry(
        session,
        AuditAction.DOCUMENT_UPLOADED,
        officer.id,
        {"document_id": str(uuid.uuid4())},
    )


async def _chain(session, officer, count: int) -> list[AuditLedger]:
    return [await _append(session, officer) for _ in range(count)]


async def _public_key(session, version: int):
    raw = await key_management.get_key_version(
        session, EncryptionKeyPurpose.CHECKPOINT_SIGNING, version
    )
    return serialization.load_pem_private_key(raw, password=None).public_key()


async def test_no_entries_produces_no_checkpoint(session):
    assert await checkpoints.create_checkpoint(session) is None


async def test_checkpoint_covers_every_entry_since_the_last(session, officer):
    entries = await _chain(session, officer, 4)
    checkpoint = await checkpoints.create_checkpoint(session)

    assert checkpoint is not None
    assert checkpoint.from_entry_id == entries[0].id
    assert checkpoint.to_entry_id == entries[-1].id
    assert checkpoint.entry_count == 4


async def test_checkpoint_hash_is_the_digest_of_the_entry_hashes(session, officer):
    entries = await _chain(session, officer, 3)
    checkpoint = await checkpoints.create_checkpoint(session)

    expected = hashlib.sha256(
        "".join(entry.entry_hash for entry in entries).encode("utf-8")
    ).hexdigest()
    assert checkpoint.checkpoint_hash == expected


async def test_checkpoint_signature_verifies_against_the_stored_key(session, officer):
    await _chain(session, officer, 2)
    checkpoint = await checkpoints.create_checkpoint(session)
    public_key = await _public_key(session, checkpoint.signing_key_version)

    public_key.verify(
        base64.b64decode(checkpoint.signature),
        checkpoint.checkpoint_hash.encode("utf-8"),
        _PADDING,
        hashes.SHA256(),
    )


async def test_a_second_checkpoint_starts_after_the_first(session, officer):
    await _chain(session, officer, 2)
    first = await checkpoints.create_checkpoint(session)

    later = await _chain(session, officer, 3)
    second = await checkpoints.create_checkpoint(session)

    assert second.from_entry_id == later[0].id
    assert second.from_entry_id > first.to_entry_id
    assert second.entry_count == 3


async def test_checkpointing_twice_with_no_new_entries_returns_none(session, officer):
    await _chain(session, officer, 2)
    assert await checkpoints.create_checkpoint(session) is not None
    assert await checkpoints.create_checkpoint(session) is None


async def test_verification_reports_when_nothing_is_checkpointed(session, officer):
    await _chain(session, officer, 2)
    result = await checkpoints.verify_checkpoints(session)
    assert result["status"] == "NO_CHECKPOINTS"
    assert result["checkpoints_checked"] == 0


async def test_clean_checkpoints_verify(session, officer):
    await _chain(session, officer, 3)
    await checkpoints.create_checkpoint(session)
    await _chain(session, officer, 2)
    await checkpoints.create_checkpoint(session)

    result = await checkpoints.verify_checkpoints(session)
    assert result["status"] == "VERIFIED"
    assert result["checkpoints_checked"] == 2
    assert result["entries_covered"] == 5


async def test_editing_a_checkpointed_entry_is_detected(session, officer):
    entries = await _chain(session, officer, 3)
    checkpoint = await checkpoints.create_checkpoint(session)

    entries[1].entry_hash = "f" * 64
    await session.flush()

    result = await checkpoints.verify_checkpoints(session)
    assert result["status"] == "TAMPERED"
    assert result["broken_at_checkpoint_id"] == checkpoint.id
    assert "no longer hash to the recorded checkpoint" in result["reason"]


async def test_deleting_a_checkpointed_entry_is_detected(session, officer):
    entries = await _chain(session, officer, 4)
    checkpoint = await checkpoints.create_checkpoint(session)

    await session.execute(delete(AuditLedger).where(AuditLedger.id == entries[2].id))
    await session.flush()

    result = await checkpoints.verify_checkpoints(session)
    assert result["status"] == "TAMPERED"
    assert result["broken_at_checkpoint_id"] == checkpoint.id
    assert "entries were deleted or inserted" in result["reason"]


async def test_tail_truncation_inside_a_checkpoint_is_detected(session, officer):
    entries = await _chain(session, officer, 5)
    await checkpoints.create_checkpoint(session)

    await session.execute(delete(AuditLedger).where(AuditLedger.id > entries[1].id))
    await session.flush()

    ledger = await audit.verify_ledger(session)
    assert ledger["status"] == "VERIFIED"

    result = await checkpoints.verify_checkpoints(session)
    assert result["status"] == "TAMPERED"


async def test_a_recomputed_chain_is_still_caught_by_the_checkpoint(session, officer):
    entries = await _chain(session, officer, 3)
    checkpoint = await checkpoints.create_checkpoint(session)

    import json

    forged = dict(entries[1].payload)
    forged["payload"] = {"document_id": str(uuid.uuid4())}
    canonical = json.dumps(forged, sort_keys=True, separators=(",", ":"))
    entries[1].payload = forged
    entries[1].entry_hash = hashlib.sha256(
        (entries[0].entry_hash + canonical).encode()
    ).hexdigest()
    entries[2].previous_entry_hash = entries[1].entry_hash
    entries[2].entry_hash = hashlib.sha256(
        (
            entries[1].entry_hash
            + json.dumps(entries[2].payload, sort_keys=True, separators=(",", ":"))
        ).encode()
    ).hexdigest()
    await session.flush()

    assert (await audit.verify_ledger(session))["status"] == "VERIFIED"

    result = await checkpoints.verify_checkpoints(session)
    assert result["status"] == "TAMPERED"
    assert result["broken_at_checkpoint_id"] == checkpoint.id


async def test_a_forged_signature_is_rejected(session, officer):
    await _chain(session, officer, 2)
    checkpoint = await checkpoints.create_checkpoint(session)

    attacker_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    checkpoint.signature = base64.b64encode(
        attacker_key.sign(
            checkpoint.checkpoint_hash.encode("utf-8"), _PADDING, hashes.SHA256()
        )
    ).decode("utf-8")
    await session.flush()

    result = await checkpoints.verify_checkpoints(session)
    assert result["status"] == "TAMPERED"
    assert result["reason"] == "checkpoint signature does not verify"


async def test_a_corrupted_signature_is_rejected(session, officer):
    await _chain(session, officer, 2)
    checkpoint = await checkpoints.create_checkpoint(session)
    checkpoint.signature = base64.b64encode(b"not-a-signature").decode("utf-8")
    await session.flush()

    result = await checkpoints.verify_checkpoints(session)
    assert result["status"] == "TAMPERED"


async def test_a_missing_signing_key_is_unverifiable_not_verified(session, officer):
    await _chain(session, officer, 2)
    checkpoint = await checkpoints.create_checkpoint(session)
    checkpoint.signing_key_version = 999
    await session.flush()

    result = await checkpoints.verify_checkpoints(session)
    assert result["status"] == "UNVERIFIABLE"
    assert result["broken_at_checkpoint_id"] == checkpoint.id


async def test_signing_key_is_separate_from_the_document_encryption_key(session, officer):
    await _chain(session, officer, 1)
    checkpoint = await checkpoints.create_checkpoint(session)

    signing = await key_management.get_key_version(
        session, EncryptionKeyPurpose.CHECKPOINT_SIGNING, checkpoint.signing_key_version
    )
    assert b"PRIVATE KEY" in signing


async def test_the_first_checkpoint_is_always_due(session, officer):
    await _chain(session, officer, 3)
    assert await checkpoints.create_checkpoint(session, force=False) is not None


async def test_thresholds_hold_back_an_undue_checkpoint(session, officer):
    await _chain(session, officer, 1)
    await checkpoints.create_checkpoint(session)

    await _chain(session, officer, 3)
    assert await checkpoints.create_checkpoint(session, force=False) is None


async def test_entry_volume_triggers_a_due_checkpoint(session, officer):
    await _chain(session, officer, 1)
    await checkpoints.create_checkpoint(session)

    await _chain(session, officer, checkpoints.CHECKPOINT_AFTER_ENTRIES)
    checkpoint = await checkpoints.create_checkpoint(session, force=False)

    assert checkpoint is not None
    assert checkpoint.entry_count == checkpoints.CHECKPOINT_AFTER_ENTRIES


async def test_forcing_overrides_the_thresholds(session, officer):
    await _chain(session, officer, 1)
    assert await checkpoints.create_checkpoint(session, force=True) is not None


async def test_a_failed_mirror_still_keeps_the_checkpoint(session, officer):
    await _chain(session, officer, 2)
    checkpoint = await checkpoints.create_checkpoint(session)

    assert checkpoint is not None
    assert checkpoint.object_key is None

    result = await checkpoints.verify_checkpoints(session)
    assert result["status"] == "VERIFIED"
    assert result["mirrored_to_write_once_store"] == 0


async def test_a_successful_mirror_is_recorded(session, officer, working_object_storage):
    await _chain(session, officer, 2)
    checkpoint = await checkpoints.create_checkpoint(session)

    assert checkpoint.object_key == f"checkpoints/{checkpoint.id:012d}.json"
    assert checkpoint.id in working_object_storage

    result = await checkpoints.verify_checkpoints(session)
    assert result["mirrored_to_write_once_store"] == 1


async def test_the_mirrored_document_matches_the_checkpoint_row(
    session, officer, working_object_storage
):
    import json

    await _chain(session, officer, 2)
    checkpoint = await checkpoints.create_checkpoint(session)
    document = json.loads(working_object_storage[checkpoint.id])

    assert document["checkpoint_hash"] == checkpoint.checkpoint_hash
    assert document["signature"] == checkpoint.signature
    assert document["entry_count"] == checkpoint.entry_count
    assert document["from_entry_id"] == checkpoint.from_entry_id
    assert document["to_entry_id"] == checkpoint.to_entry_id


async def test_checkpoint_hash_is_order_sensitive():
    first = checkpoints.compute_checkpoint_hash(["aa", "bb"])
    second = checkpoints.compute_checkpoint_hash(["bb", "aa"])
    assert first != second


async def test_checkpoint_hash_of_nothing_is_stable():
    assert checkpoints.compute_checkpoint_hash([]) == hashlib.sha256(b"").hexdigest()
