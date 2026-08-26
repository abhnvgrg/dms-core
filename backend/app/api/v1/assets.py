import json
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, require_fresh_mfa
from app.api.v1.cases import _get_case_if_authorized
from app.api.v1.documents import _resolve_case
from app.database import get_db
from app.models.entities import (
    AssetTransfer,
    AuditAction,
    CustodyStatus,
    OfficerSigningKey,
    PhysicalAsset,
    Role,
    User,
)
from app.schemas.assets import (
    AssetRegisterRequest,
    AssetResponse,
    AssetTransferRequest,
    TransferRecordResponse,
)
from app.services import officer_keys
from app.services.audit import append_entry

router = APIRouter(prefix="/assets", tags=["assets"])

REGISTER_ROLES = (Role.INVESTIGATING_OFFICER, Role.FORENSICS_OFFICER, Role.ADMIN)


def transfer_message(
    qr_uuid: UUID,
    expected_prior_custody_status: str,
    new_custody_status: str,
    receiving_officer_badge_number: str,
) -> str:
    """The exact string the officer's browser signs.

    Canonical JSON so the client and server agree byte-for-byte on what was
    signed, including the expected prior status that makes the conflict check
    meaningful.
    """
    return json.dumps(
        {
            "qr_uuid": str(qr_uuid),
            "expected_prior_custody_status": expected_prior_custody_status,
            "new_custody_status": new_custody_status,
            "receiving_officer_badge_number": receiving_officer_badge_number,
        },
        sort_keys=True,
        separators=(",", ":"),
    )


async def _to_response(asset: PhysicalAsset, fir_number: str, session: AsyncSession) -> AssetResponse:
    custodian_badge = None
    if asset.current_custodian_id:
        custodian = await session.scalar(select(User).where(User.id == asset.current_custodian_id))
        custodian_badge = custodian.badge_number if custodian else None

    return AssetResponse(
        id=asset.id,
        case_id=fir_number,
        qr_uuid=asset.qr_uuid,
        item_name=asset.item_name,
        category=asset.category,
        custody_status=asset.custody_status.value,
        current_custodian_badge_number=custodian_badge,
        created_at=asset.created_at,
    )


@router.post("", response_model=AssetResponse, status_code=status.HTTP_201_CREATED)
async def register_asset(
    payload: AssetRegisterRequest,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> AssetResponse:
    case = await _resolve_case(payload.case_id, current_user, session)
    if current_user.role not in REGISTER_ROLES:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to register physical evidence")

    asset = PhysicalAsset(
        case_id=case.id,
        registered_by_id=current_user.id,
        item_name=payload.item_name,
        category=payload.category,
        custody_status=CustodyStatus.POLICE_CUSTODY,
        current_custodian_id=current_user.id,
    )
    session.add(asset)
    await session.flush()

    await append_entry(
        session,
        action=AuditAction.ASSET_REGISTERED,
        actor_id=current_user.id,
        payload={"asset_id": str(asset.id), "case_id": str(case.id), "item_name": payload.item_name},
    )
    await session.commit()

    return await _to_response(asset, case.fir_number, session)


@router.get("", response_model=list[AssetResponse])
async def list_assets(
    case_id: str = Query(...),
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> list[AssetResponse]:
    case = await _resolve_case(case_id, current_user, session)
    result = await session.execute(
        select(PhysicalAsset).where(PhysicalAsset.case_id == case.id).order_by(PhysicalAsset.created_at.desc())
    )
    return [await _to_response(asset, case.fir_number, session) for asset in result.scalars().all()]


@router.get("/by-qr/{qr_uuid}", response_model=AssetResponse)
async def get_asset_by_qr(
    qr_uuid: UUID,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> AssetResponse:
    """Resolve a scanned QR tag to the asset it belongs to."""
    asset = await session.scalar(select(PhysicalAsset).where(PhysicalAsset.qr_uuid == qr_uuid))
    if asset is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No asset carries that tag")

    case = await _get_case_if_authorized(asset.case_id, current_user, session)
    return await _to_response(asset, case.fir_number, session)


@router.get("/{asset_id}/transfers", response_model=list[TransferRecordResponse])
async def list_transfers(
    asset_id: UUID,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> list[TransferRecordResponse]:
    """The custody history, with each handover re-verified against its key."""
    asset = await session.scalar(select(PhysicalAsset).where(PhysicalAsset.id == asset_id))
    if asset is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")

    await _get_case_if_authorized(asset.case_id, current_user, session)

    result = await session.execute(
        select(AssetTransfer)
        .where(AssetTransfer.asset_id == asset_id)
        .order_by(AssetTransfer.created_at.asc())
    )

    records: list[TransferRecordResponse] = []
    for transfer in result.scalars().all():
        performer = await session.scalar(select(User).where(User.id == transfer.performed_by_id))
        receiver = await session.scalar(select(User).where(User.id == transfer.receiving_officer_id))
        key = await session.get(OfficerSigningKey, transfer.signing_key_id)

        signature_valid = False
        key_status = "missing"
        if key is not None:
            signature_valid = officer_keys.verify_signature(
                key.public_key_pem, transfer.signed_payload, transfer.client_signature
            )
            key_status = officer_keys.signature_status(key, transfer.created_at)

        records.append(
            TransferRecordResponse(
                id=transfer.id,
                from_status=transfer.from_status.value,
                to_status=transfer.to_status.value,
                performed_by=performer.badge_number if performer else "unknown",
                received_by=receiver.badge_number if receiver else "unknown",
                signature_valid=signature_valid,
                signing_key_status=key_status,
                created_at=transfer.created_at,
            )
        )

    return records


@router.post("/{asset_id}/transfer", response_model=AssetResponse)
async def transfer_asset(
    asset_id: UUID,
    payload: AssetTransferRequest,
    current_user: User = Depends(require_fresh_mfa),
    session: AsyncSession = Depends(get_db),
) -> AssetResponse:
    """Hand custody to another officer.

    Carries the client's expected prior status so that two officers who both
    prepared a transfer offline cannot both succeed: the second one to sync
    hits a 409 and is recorded as a conflict for a human to resolve.
    """
    asset = await session.scalar(select(PhysicalAsset).where(PhysicalAsset.id == asset_id))
    if asset is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")

    case = await _get_case_if_authorized(asset.case_id, current_user, session)
    if current_user.role not in REGISTER_ROLES:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to transfer physical evidence")

    try:
        expected_status = CustodyStatus(payload.expected_prior_custody_status)
        new_status = CustodyStatus(payload.new_custody_status)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Invalid custody status")

    if asset.custody_status != expected_status:
        await append_entry(
            session,
            action=AuditAction.ASSET_TRANSFER_CONFLICT,
            actor_id=current_user.id,
            payload={
                "asset_id": str(asset.id),
                "case_id": str(asset.case_id),
                "expected_status": expected_status.value,
                "actual_status": asset.custody_status.value,
                "attempted_new_status": new_status.value,
            },
        )
        await session.commit()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"Custody is currently {asset.custody_status.value}, not "
                f"{expected_status.value}. This transfer was not applied and has "
                "been flagged for manual review."
            ),
        )

    receiving_officer = await session.scalar(
        select(User).where(User.badge_number == payload.receiving_officer_badge_number)
    )
    if receiving_officer is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Receiving officer not found")

    signing_key = await officer_keys.get_active_key(session, current_user.id)
    if signing_key is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="No active signing key for this officer; register one before transferring custody",
        )

    message = transfer_message(
        asset.qr_uuid,
        expected_status.value,
        new_status.value,
        payload.receiving_officer_badge_number,
    )
    if not officer_keys.verify_signature(signing_key.public_key_pem, message, payload.client_signature):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Transfer signature does not verify against your registered signing key",
        )

    asset.custody_status = new_status
    asset.current_custodian_id = receiving_officer.id

    transfer = AssetTransfer(
        asset_id=asset.id,
        performed_by_id=current_user.id,
        receiving_officer_id=receiving_officer.id,
        from_status=expected_status,
        to_status=new_status,
        signed_payload=message,
        client_signature=payload.client_signature,
        signing_key_id=signing_key.id,
    )
    session.add(transfer)
    await session.flush()

    await append_entry(
        session,
        action=AuditAction.ASSET_TRANSFERRED,
        actor_id=current_user.id,
        payload={
            "asset_id": str(asset.id),
            "case_id": str(asset.case_id),
            "transfer_id": str(transfer.id),
            "from_status": expected_status.value,
            "to_status": new_status.value,
            "receiving_officer_id": str(receiving_officer.id),
            "signing_key_fingerprint": signing_key.fingerprint,
        },
    )
    await session.commit()

    return await _to_response(asset, case.fir_number, session)
