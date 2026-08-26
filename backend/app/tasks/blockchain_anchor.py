import asyncio
from datetime import datetime, timezone

from app.core.config import get_settings
from app.database import AsyncSessionLocal, engine
from app.models.entities import AuditLedger
from app.services import blockchain
from app.tasks.celery_app import celery_app


async def _anchor_ledger_entry_async(ledger_entry_id: int) -> None:
    settings = get_settings()

    if not settings.blockchain_anchoring_enabled or not settings.blockchain_contract_address:
        return

    async with AsyncSessionLocal() as session:
        entry = await session.get(AuditLedger, ledger_entry_id)
        if entry is None or entry.chain_tx_hash is not None:
            return

        try:
            result = blockchain.anchor_entry_onchain(
                entry.id, entry.entity_type, str(entry.entity_id), entry.entry_hash
            )
        except Exception:
            return

        entry.chain_tx_hash = result["tx_hash"]
        entry.chain_block_number = result["block_number"]
        entry.chain_anchored_at = datetime.now(timezone.utc)
        await session.commit()


@celery_app.task(name="anchor_ledger_entry", bind=True, max_retries=3, default_retry_delay=10)
def anchor_ledger_entry(self, ledger_entry_id: int) -> None:
    try:
        asyncio.run(_anchor_ledger_entry_async(ledger_entry_id))
    finally:
        asyncio.run(engine.dispose())
