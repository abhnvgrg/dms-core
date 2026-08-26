from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, require_roles
from app.api.v1.cases import _get_case_if_authorized
from app.database import get_db
from app.models.entities import AuditCheckpoint, AuditLedger, Document, Role, User
from app.schemas.audit import (
    AuditEntryResponse,
    CheckpointResponse,
    LedgerVerifyResponse,
    OnchainVerifyResponse,
)
from app.services import blockchain, checkpoints
from app.services.audit import verify_ledger

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("/verify", response_model=LedgerVerifyResponse)
async def verify_audit_ledger(
    current_user: User = Depends(require_roles(Role.ADMIN)),
    session: AsyncSession = Depends(get_db),
) -> LedgerVerifyResponse:
    """Three questions, not one.

    Is the chain internally consistent; do the entries still hash to each
    recorded checkpoint; and is each checkpoint signature intact. A ledger
    rewritten wholesale passes the first and fails the other two.
    """
    chain = await verify_ledger(session)
    checkpoint_result = await checkpoints.verify_checkpoints(session)

    if chain["status"] != "VERIFIED":
        overall = "TAMPERED"
    elif checkpoint_result["status"] == "TAMPERED":
        overall = "TAMPERED"
    elif checkpoint_result["status"] == "UNVERIFIABLE":
        overall = "UNVERIFIABLE"
    else:
        overall = "VERIFIED"

    return LedgerVerifyResponse(
        status=overall,
        chain_status=chain["status"],
        entries_checked=chain.get("entries_checked"),
        broken_at_entry_id=chain.get("broken_at_entry_id"),
        reason=chain.get("reason") or checkpoint_result.get("reason"),
        checkpoint_status=checkpoint_result["status"],
        checkpoints_checked=checkpoint_result.get("checkpoints_checked"),
        entries_covered_by_checkpoints=checkpoint_result.get("entries_covered"),
        broken_at_checkpoint_id=checkpoint_result.get("broken_at_checkpoint_id"),
        mirrored_to_write_once_store=checkpoint_result.get("mirrored_to_write_once_store"),
    )


@router.get("/checkpoints", response_model=list[CheckpointResponse])
async def list_checkpoints(
    limit: int = 50,
    current_user: User = Depends(require_roles(Role.ADMIN)),
    session: AsyncSession = Depends(get_db),
) -> list[CheckpointResponse]:
    result = await session.execute(
        select(AuditCheckpoint).order_by(AuditCheckpoint.id.desc()).limit(limit)
    )
    return [
        CheckpointResponse(
            id=checkpoint.id,
            from_entry_id=checkpoint.from_entry_id,
            to_entry_id=checkpoint.to_entry_id,
            entry_count=checkpoint.entry_count,
            checkpoint_hash=checkpoint.checkpoint_hash,
            signing_key_version=checkpoint.signing_key_version,
            object_key=checkpoint.object_key,
            created_at=checkpoint.created_at,
        )
        for checkpoint in result.scalars().all()
    ]


@router.post("/checkpoints", response_model=CheckpointResponse, status_code=status.HTTP_201_CREATED)
async def create_checkpoint_now(
    current_user: User = Depends(require_roles(Role.ADMIN)),
    session: AsyncSession = Depends(get_db),
) -> CheckpointResponse:
    """Force a checkpoint instead of waiting for the scheduled one."""
    checkpoint = await checkpoints.create_checkpoint(session)
    if checkpoint is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="No new ledger entries to checkpoint",
        )

    await session.commit()

    return CheckpointResponse(
        id=checkpoint.id,
        from_entry_id=checkpoint.from_entry_id,
        to_entry_id=checkpoint.to_entry_id,
        entry_count=checkpoint.entry_count,
        checkpoint_hash=checkpoint.checkpoint_hash,
        signing_key_version=checkpoint.signing_key_version,
        object_key=checkpoint.object_key,
        created_at=checkpoint.created_at,
    )


async def _authorize_entity(
    entity_type: str, entity_id: UUID, current_user: User, session: AsyncSession
) -> None:
    if current_user.role == Role.ADMIN:
        return

    if entity_type == "case":
        await _get_case_if_authorized(entity_id, current_user, session)
        return

    if entity_type == "document":
        document = await session.scalar(select(Document).where(Document.id == entity_id))
        if document is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document not found")
        await _get_case_if_authorized(document.case_id, current_user, session)
        return

    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="You do not have permission to view this audit trail",
    )


@router.get("/entities/{entity_type}/{entity_id}", response_model=list[AuditEntryResponse])
async def get_entity_audit_trail(
    entity_type: str,
    entity_id: UUID,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> list[AuditEntryResponse]:
    await _authorize_entity(entity_type, entity_id, current_user, session)

    result = await session.execute(
        select(AuditLedger)
        .where(AuditLedger.entity_type == entity_type, AuditLedger.entity_id == entity_id)
        .order_by(AuditLedger.created_at.asc())
    )
    return [AuditEntryResponse.model_validate(entry) for entry in result.scalars().all()]


@router.post("/ledger/{entry_id}/verify-onchain", response_model=OnchainVerifyResponse)
async def verify_ledger_entry_onchain(
    entry_id: int,
    current_user: User = Depends(require_roles(Role.ADMIN)),
    session: AsyncSession = Depends(get_db),
) -> OnchainVerifyResponse:
    entry = await session.get(AuditLedger, entry_id)
    if entry is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Audit entry not found")

    if entry.chain_tx_hash is None:
        return OnchainVerifyResponse(
            entry_id=entry.id, db_entry_hash=entry.entry_hash, status="NOT_YET_ANCHORED"
        )

    try:
        onchain = blockchain.get_onchain_anchor(entry.id)
    except Exception:
        return OnchainVerifyResponse(
            entry_id=entry.id, db_entry_hash=entry.entry_hash, status="CHAIN_UNREACHABLE"
        )

    if onchain is None:
        return OnchainVerifyResponse(
            entry_id=entry.id, db_entry_hash=entry.entry_hash, status="NOT_YET_ANCHORED"
        )

    match = onchain["entry_hash"] == entry.entry_hash
    return OnchainVerifyResponse(
        entry_id=entry.id,
        db_entry_hash=entry.entry_hash,
        onchain_entry_hash=onchain["entry_hash"],
        match=match,
        status="VERIFIED" if match else "TAMPERED",
    )
