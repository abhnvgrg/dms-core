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
    """Sign off the ledger entries written since the last checkpoint, when due.

    Runs often and checkpoints only once a threshold is crossed -- entry count
    or elapsed time, whichever comes first.

    Deliberately not audited itself: an entry written by the checkpointer would
    always fall outside the checkpoint that just ran, so the ledger would never
    reach a quiet state.
    """
    try:
        checkpoint_id = asyncio.run(_create_checkpoint_async())
    finally:
        asyncio.run(engine.dispose())

    return {"checkpoint_id": checkpoint_id, "created": checkpoint_id is not None}
