import asyncio
from datetime import datetime, timezone

from sqlalchemy import select

from app.database import AsyncSessionLocal, engine
from app.models.entities import AuditAction, DocumentAccessGrant
from app.services.audit import append_entry
from app.tasks.celery_app import celery_app

EXPIRY_MARKER = "expired"


async def _expire_grants_async() -> int:
    """Record grants that have lapsed.

    Access is already denied the moment `expires_at` passes -- enforcement reads
    the timestamp directly. This exists so expiry appears in the custody record
    as an event, rather than as an absence of one.
    """
    now = datetime.now(timezone.utc)
    expired_count = 0

    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(DocumentAccessGrant).where(
                DocumentAccessGrant.expires_at <= now,
                DocumentAccessGrant.revoked_at.is_(None),
            )
        )

        for grant in result.scalars().all():
            grant.revoked_at = grant.expires_at
            await append_entry(
                session,
                action=AuditAction.ACCESS_GRANT_EXPIRED,
                actor_id=None,
                payload={
                    "document_id": str(grant.document_id),
                    "grant_id": str(grant.id),
                    "grantee_id": str(grant.grantee_id),
                    "expired_at": grant.expires_at.isoformat(),
                },
            )
            await session.commit()
            expired_count += 1

    return expired_count


@celery_app.task(name="expire_access_grants")
def expire_access_grants() -> dict:
    try:
        count = asyncio.run(_expire_grants_async())
    finally:
        asyncio.run(engine.dispose())

    return {"expired": count}
