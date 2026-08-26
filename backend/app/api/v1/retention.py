from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_roles
from app.database import get_db
from app.models.entities import AuditAction, RetentionPolicy, Role, User
from app.schemas.retention import PurgeNowResponse, RetentionPolicyResponse, RetentionPolicyUpdate
from app.services.audit import append_entry
from app.tasks.retention_purge import purge_expired_documents_in_session

router = APIRouter(prefix="/retention", tags=["retention"])

DEFAULT_RETENTION_MINUTES = 525_600  # ~365 days


async def _get_or_create_policy(session: AsyncSession) -> RetentionPolicy:
    policy = await session.scalar(
        select(RetentionPolicy).order_by(RetentionPolicy.updated_at.desc()).limit(1)
    )
    if policy is None:
        policy = RetentionPolicy(retention_minutes=DEFAULT_RETENTION_MINUTES)
        session.add(policy)
        await session.flush()
    return policy


@router.get("/policy", response_model=RetentionPolicyResponse)
async def get_retention_policy(
    current_user: User = Depends(require_roles(Role.ADMIN)),
    session: AsyncSession = Depends(get_db),
) -> RetentionPolicyResponse:
    policy = await _get_or_create_policy(session)
    await session.commit()
    return RetentionPolicyResponse.model_validate(policy)


@router.put("/policy", response_model=RetentionPolicyResponse)
async def update_retention_policy(
    payload: RetentionPolicyUpdate,
    current_user: User = Depends(require_roles(Role.ADMIN)),
    session: AsyncSession = Depends(get_db),
) -> RetentionPolicyResponse:
    policy = await _get_or_create_policy(session)
    policy.retention_minutes = payload.retention_minutes
    policy.updated_by_id = current_user.id
    await session.flush()

    await append_entry(
        session,
        action=AuditAction.RETENTION_POLICY_UPDATED,
        actor_id=current_user.id,
        payload={"retention_policy_id": str(policy.id), "retention_minutes": policy.retention_minutes},
    )

    await session.commit()
    await session.refresh(policy)
    return RetentionPolicyResponse.model_validate(policy)


@router.post("/purge-now", response_model=PurgeNowResponse)
async def trigger_purge_now(
    current_user: User = Depends(require_roles(Role.ADMIN)),
    session: AsyncSession = Depends(get_db),
) -> PurgeNowResponse:
    """Run the retention purge immediately instead of waiting for the scheduled beat job.
    Intended for demos/manual admin use — runs against the current retention policy."""
    purged_count, retention_minutes = await purge_expired_documents_in_session(session)
    return PurgeNowResponse(purged_count=purged_count, retention_minutes=retention_minutes)
