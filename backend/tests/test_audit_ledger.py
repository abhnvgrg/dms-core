from __future__ import annotations

import hashlib
import json
import uuid

import pytest
from sqlalchemy import delete, select

from app.models.entities import AuditAction, AuditLedger
from app.services import audit

pytestmark = pytest.mark.asyncio


def _rehash(previous_hash: str, payload: dict) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256((previous_hash + canonical).encode()).hexdigest()


async def _append(session, officer, **payload) -> AuditLedger:
    if not payload:
        payload = {"document_id": str(uuid.uuid4())}
    return await audit.append_entry(
        session, AuditAction.DOCUMENT_UPLOADED, officer.id, payload
    )


async def _chain(session, officer, count: int) -> list[AuditLedger]:
    return [await _append(session, officer) for _ in range(count)]


async def test_first_entry_links_to_genesis(session, officer):
    entry = await _append(session, officer)
    assert entry.previous_entry_hash == "GENESIS"


async def test_each_entry_links_to_its_predecessor(session, officer):
    entries = await _chain(session, officer, 4)
    for previous, current in zip(entries, entries[1:]):
        assert current.previous_entry_hash == previous.entry_hash


async def test_entry_hash_is_reproducible_from_stored_payload(session, officer):
    entry = await _append(session, officer)
    assert entry.entry_hash == _rehash("GENESIS", entry.payload)


async def test_entry_hash_covers_the_previous_hash(session, officer):
    first, second = await _chain(session, officer, 2)
    assert second.entry_hash == _rehash(first.entry_hash, second.payload)
    assert second.entry_hash != _rehash("GENESIS", second.payload)


async def test_clean_chain_verifies(session, officer):
    await _chain(session, officer, 5)
    result = await audit.verify_ledger(session)
    assert result["status"] == "VERIFIED"
    assert result["entries_checked"] == 5


async def test_editing_a_payload_breaks_verification(session, officer):
    entries = await _chain(session, officer, 3)
    target = entries[1]

    tampered = dict(target.payload)
    tampered["payload"] = {"document_id": str(uuid.uuid4())}
    target.payload = tampered
    await session.flush()

    result = await audit.verify_ledger(session)
    assert result["status"] == "TAMPERED"
    assert result["broken_at_entry_id"] == target.id
    assert result["reason"] == "entry_hash mismatch"


async def test_editing_an_actor_breaks_verification(session, officer, admin):
    entries = await _chain(session, officer, 3)
    target = entries[2]

    tampered = dict(target.payload)
    tampered["actor_id"] = str(admin.id)
    target.payload = tampered
    await session.flush()

    result = await audit.verify_ledger(session)
    assert result["status"] == "TAMPERED"
    assert result["broken_at_entry_id"] == target.id


async def test_relinking_an_entry_breaks_verification(session, officer):
    entries = await _chain(session, officer, 3)
    target = entries[1]
    target.previous_entry_hash = "0" * 64
    await session.flush()

    result = await audit.verify_ledger(session)
    assert result["status"] == "TAMPERED"
    assert result["broken_at_entry_id"] == target.id
    assert result["reason"] == "previous_hash mismatch"


async def test_deleting_a_middle_entry_breaks_the_chain(session, officer):
    entries = await _chain(session, officer, 4)
    removed = entries[1]

    await session.execute(delete(AuditLedger).where(AuditLedger.id == removed.id))
    await session.flush()

    result = await audit.verify_ledger(session)
    assert result["status"] == "TAMPERED"
    assert result["broken_at_entry_id"] == entries[2].id
    assert result["reason"] == "previous_hash mismatch"


async def test_deleting_the_first_entry_breaks_the_chain(session, officer):
    entries = await _chain(session, officer, 3)

    await session.execute(delete(AuditLedger).where(AuditLedger.id == entries[0].id))
    await session.flush()

    result = await audit.verify_ledger(session)
    assert result["status"] == "TAMPERED"
    assert result["reason"] == "previous_hash mismatch"


async def test_truncating_the_tail_is_not_detected_by_the_chain_alone(session, officer):
    entries = await _chain(session, officer, 5)
    survivors = entries[:2]

    await session.execute(
        delete(AuditLedger).where(AuditLedger.id > survivors[-1].id)
    )
    await session.flush()

    result = await audit.verify_ledger(session)
    assert result["status"] == "VERIFIED"
    assert result["entries_checked"] == 2


async def test_a_fully_recomputed_chain_is_not_detected_by_the_chain_alone(
    session, officer
):
    entries = await _chain(session, officer, 3)

    forged_payload = dict(entries[1].payload)
    forged_payload["payload"] = {"document_id": str(uuid.uuid4())}
    entries[1].payload = forged_payload
    entries[1].entry_hash = _rehash(entries[0].entry_hash, forged_payload)

    entries[2].previous_entry_hash = entries[1].entry_hash
    entries[2].entry_hash = _rehash(entries[1].entry_hash, entries[2].payload)
    await session.flush()

    result = await audit.verify_ledger(session)
    assert result["status"] == "VERIFIED"


async def test_payload_without_an_entity_id_is_rejected(session, officer):
    with pytest.raises(ValueError):
        await audit.append_entry(
            session, AuditAction.DOCUMENT_UPLOADED, officer.id, {"note": "no entity"}
        )


@pytest.mark.parametrize(
    "key,expected",
    [
        ("document_id", "document"),
        ("case_id", "case"),
        ("asset_id", "physical_asset"),
        ("retention_policy_id", "retention_policy"),
        ("user_id", "user"),
        ("encryption_key_id", "encryption_key"),
    ],
)
async def test_entity_type_is_derived_from_the_payload(session, officer, key, expected):
    entity_id = uuid.uuid4()
    entry = await audit.append_entry(
        session, AuditAction.DOCUMENT_UPLOADED, officer.id, {key: str(entity_id)}
    )
    assert entry.entity_type == expected
    assert str(entry.entity_id) == str(entity_id)


async def test_key_order_in_the_payload_does_not_change_the_hash(session, officer):
    case_id = str(uuid.uuid4())
    first = await audit.append_entry(
        session, AuditAction.CASE_CREATED, officer.id, {"case_id": case_id, "a": 1}
    )
    second = await audit.append_entry(
        session, AuditAction.CASE_CREATED, officer.id, {"a": 1, "case_id": case_id}
    )

    assert _rehash(first.entry_hash, second.payload) == second.entry_hash


async def test_entry_hashes_are_unique_across_identical_payloads(session, officer):
    case_id = str(uuid.uuid4())
    first = await audit.append_entry(
        session, AuditAction.CASE_CREATED, officer.id, {"case_id": case_id}
    )
    second = await audit.append_entry(
        session, AuditAction.CASE_CREATED, officer.id, {"case_id": case_id}
    )
    assert first.entry_hash != second.entry_hash


async def test_entries_are_verified_in_insertion_order(session, officer):
    await _chain(session, officer, 3)
    result = await session.execute(select(AuditLedger).order_by(AuditLedger.id.asc()))
    ids = [entry.id for entry in result.scalars().all()]
    assert ids == sorted(ids)


async def test_empty_ledger_verifies(session):
    result = await audit.verify_ledger(session)
    assert result["status"] == "VERIFIED"
    assert result["entries_checked"] == 0
