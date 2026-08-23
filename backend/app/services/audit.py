import json
import hashlib
from datetime import datetime, timezone
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.entities import AuditLedger, AuditAction


def _canonical_json(data: dict) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


async def get_last_entry(session: AsyncSession) -> AuditLedger | None:
    result = await session.execute(
        select(AuditLedger).order_by(AuditLedger.id.desc()).limit(1)
    )
    return result.scalar_one_or_none()


async def append_entry(
    session: AsyncSession,
    action: AuditAction,
    actor_id,
    payload: dict,
) -> AuditLedger:
    previous = await get_last_entry(session)
    previous_hash = previous.entry_hash if previous else "GENESIS"

    event_data = {
        "action": action.value,
        "actor_id": str(actor_id),
        "payload": payload,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    canonical = _canonical_json(event_data)
    entry_hash = hashlib.sha256(
        (previous_hash + canonical).encode()
    ).hexdigest()

    # Determine what entity this audit event belongs to
    if "case_id" in payload:
        entity_type = "case"
        entity_id = payload["case_id"]
    elif "document_id" in payload:
        entity_type = "document"
        entity_id = payload["document_id"]
    elif "asset_id" in payload:
        entity_type = "physical_asset"
        entity_id = payload["asset_id"]
    else:
        raise ValueError("Audit payload must contain an entity ID")

    entry = AuditLedger(
        action_type=action,
        entity_type=entity_type,
        entity_id=entity_id,
        actor_id=actor_id,
        payload=event_data,
        previous_entry_hash=previous_hash,
        entry_hash=entry_hash,
    )

    session.add(entry)
    await session.flush()

    return entry


async def verify_ledger(session: AsyncSession) -> dict:
    result = await session.execute(select(AuditLedger).order_by(AuditLedger.id.asc()))
    entries = result.scalars().all()

    previous_hash = "GENESIS"
    for entry in entries:
        if entry.previous_entry_hash != previous_hash:
            return {"status": "TAMPERED", "broken_at_entry_id": entry.id, "reason": "previous_hash mismatch"}
        canonical = _canonical_json(entry.payload)
        recomputed = hashlib.sha256((previous_hash + canonical).encode()).hexdigest()
        if recomputed != entry.entry_hash:
            return {"status": "TAMPERED", "broken_at_entry_id": entry.id, "reason": "entry_hash mismatch"}
        previous_hash = entry.entry_hash

    return {"status": "VERIFIED", "entries_checked": len(entries)}