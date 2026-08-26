import json
import hashlib
import logging
from datetime import datetime, timezone
from sqlalchemy import event, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session

from app.models.entities import AuditLedger, AuditAction

logger = logging.getLogger(__name__)


@event.listens_for(Session, "after_commit")
def _enqueue_pending_anchors(session: Session) -> None:
    pending = session.info.pop("pending_anchor_ids", None)
    if not pending:
        return
    try:
        from app.tasks.blockchain_anchor import anchor_ledger_entry

        for entry_id in pending:
            anchor_ledger_entry.delay(entry_id)
    except Exception:
        logger.exception("Failed to enqueue blockchain anchoring for ledger entries %s", pending)


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

    if "document_id" in payload:
        entity_type = "document"
        entity_id = payload["document_id"]
    elif "case_id" in payload:
        entity_type = "case"
        entity_id = payload["case_id"]
    elif "asset_id" in payload:
        entity_type = "physical_asset"
        entity_id = payload["asset_id"]
    elif "retention_policy_id" in payload:
        entity_type = "retention_policy"
        entity_id = payload["retention_policy_id"]
    elif "user_id" in payload:
        entity_type = "user"
        entity_id = payload["user_id"]
    elif "encryption_key_id" in payload:
        entity_type = "encryption_key"
        entity_id = payload["encryption_key_id"]
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

    session.sync_session.info.setdefault("pending_anchor_ids", []).append(entry.id)

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