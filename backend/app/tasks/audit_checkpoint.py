import asyncio

from app.database import AsyncSessionLocal, engine
from app.services import checkpoints
from app.tasks.celery_app import celery_app


async def _create_checkpoint_async() -> int | None:
    async with AsyncSessionLocal() as session:
        checkpoint = await checkpoints.create_checkpoint(session, force=False)
        if checkpoint is None:
            return None
        checkpoint_id = checkpoint.id
        await session.commit()
        return checkpoint_id


@celery_app.task(name="create_audit_checkpoint")
def create_audit_checkpoint() -> dict:
    try:
        checkpoint_id = asyncio.run(_create_checkpoint_async())
    finally:
        asyncio.run(engine.dispose())

    return {"checkpoint_id": checkpoint_id, "created": checkpoint_id is not None}
