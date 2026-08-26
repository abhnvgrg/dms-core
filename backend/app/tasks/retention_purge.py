import asyncio
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import AsyncSessionLocal, engine
from app.models.entities import AuditAction, Document, RetentionPolicy
from app.services import storage
from app.services.audit import append_entry
from app.tasks.celery_app import celery_app

DEFAULT_RETENTION_MINUTES = 525_600  # ~365 days


async def purge_expired_documents_in_session(session: AsyncSession) -> tuple[int, int]:
    """Purge expired documents using an existing session. Returns (purged_count, retention_minutes)."""
    policy = await session.scalar(
        select(RetentionPolicy).order_by(RetentionPolicy.updated_at.desc()).limit(1)
    )
    retention_minutes = policy.retention_minutes if policy else DEFAULT_RETENTION_MINUTES
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=retention_minutes)

    result = await session.execute(select(Document).where(Document.created_at < cutoff))
    expired_documents = result.scalars().all()

    purged_count = 0
    for document in expired_documents:
        try:
            storage.delete_file(document.object_key)
        except FileNotFoundError:
            pass
        except Exception:
            continue

        await append_entry(
            session,
            action=AuditAction.DOCUMENT_PURGED,
            actor_id=None,
            payload={
                "document_id": str(document.id),
                "case_id": str(document.case_id),
                "original_filename": document.original_filename,
                "sha256_hash": document.sha256_hash,
                "uploaded_by_id": str(document.uploaded_by_id),
                "retention_minutes": retention_minutes,
                "reason": "retention_policy_expired",
            },
        )
        await session.delete(document)
        await session.commit()
        purged_count += 1

    return purged_count, retention_minutes


async def _purge_expired_documents_async() -> None:
    async with AsyncSessionLocal() as session:
        await purge_expired_documents_in_session(session)


@celery_app.task(name="purge_expired_documents")
def purge_expired_documents() -> None:
    try:
        asyncio.run(_purge_expired_documents_async())
    finally:
        asyncio.run(engine.dispose())
