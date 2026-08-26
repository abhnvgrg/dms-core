import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, require_fresh_mfa, require_roles
from app.core.security import hash_password
from app.database import get_db
from app.models.entities import (
    AuditAction,
    EncryptionKey,
    EncryptionKeyPurpose,
    OfficerSigningKey,
    Role,
    SigningKeyStatus,
    User,
)
from app.schemas.admin import (
    EncryptionKeyResponse,
    UserCreateRequest,
    UserResponse,
    UserUpdateRequest,
)
from app.services import key_management, officer_keys, sessions
from app.services.audit import append_entry

router = APIRouter(prefix="/admin", tags=["admin"])


def _to_user_response(user: User) -> UserResponse:
    return UserResponse(
        id=user.id,
        badge_number=user.badge_number,
        full_name=user.full_name,
        role=user.role,
        is_active=user.is_active,
        mfa_enabled=user.mfa_enabled,
        created_at=user.created_at,
    )


@router.get("/users", response_model=list[UserResponse])
async def list_users(
    current_user: User = Depends(require_roles(Role.ADMIN)),
    session: AsyncSession = Depends(get_db),
) -> list[UserResponse]:
    result = await session.execute(select(User).order_by(User.badge_number.asc()))
    return [_to_user_response(user) for user in result.scalars().all()]


@router.post("/users", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def create_user(
    payload: UserCreateRequest,
    current_user: User = Depends(require_fresh_mfa),
    session: AsyncSession = Depends(get_db),
) -> UserResponse:
    if current_user.role != Role.ADMIN:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only an admin can create users")

    existing = await session.scalar(
        select(User).where(User.badge_number == payload.badge_number)
    )
    if existing is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Badge number is already registered")

    user = User(
        badge_number=payload.badge_number,
        full_name=payload.full_name,
        role=payload.role,
        password_hash=hash_password(payload.password),
        is_active=True,
    )
    session.add(user)
    await session.flush()

    await append_entry(
        session,
        action=AuditAction.USER_CREATED,
        actor_id=current_user.id,
        payload={
            "user_id": str(user.id),
            "badge_number": user.badge_number,
            "role": user.role.value,
        },
    )
    await session.commit()

    return _to_user_response(user)


@router.patch("/users/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: uuid.UUID,
    payload: UserUpdateRequest,
    current_user: User = Depends(require_fresh_mfa),
    session: AsyncSession = Depends(get_db),
) -> UserResponse:
    if current_user.role != Role.ADMIN:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only an admin can modify users")

    user = await session.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    if payload.role is not None and payload.role != user.role:
        previous = user.role
        user.role = payload.role
        await append_entry(
            session,
            action=AuditAction.USER_ROLE_CHANGED,
            actor_id=current_user.id,
            payload={
                "user_id": str(user.id),
                "from_role": previous.value,
                "to_role": payload.role.value,
            },
        )
        # A role change alters what every live session is allowed to do, so the
        # old sessions do not get to keep their previous authority.
        await sessions.revoke_all_sessions(session, user.id)

    if payload.is_active is not None and payload.is_active != user.is_active:
        user.is_active = payload.is_active
        if not payload.is_active:
            await append_entry(
                session,
                action=AuditAction.USER_DEACTIVATED,
                actor_id=current_user.id,
                payload={"user_id": str(user.id), "badge_number": user.badge_number},
            )
            await sessions.revoke_all_sessions(session, user.id)

    await session.commit()
    return _to_user_response(user)


@router.get("/users/{user_id}/signing-keys", response_model=list[dict])
async def list_user_signing_keys(
    user_id: uuid.UUID,
    current_user: User = Depends(require_roles(Role.ADMIN)),
    session: AsyncSession = Depends(get_db),
) -> list[dict]:
    keys = await officer_keys.list_keys(session, user_id)
    return [
        {
            "id": str(key.id),
            "fingerprint": key.fingerprint,
            "status": key.status.value,
            "created_at": key.created_at.isoformat(),
            "revoked_at": key.revoked_at.isoformat() if key.revoked_at else None,
        }
        for key in keys
    ]


@router.post("/signing-keys/{key_id}/revoke", status_code=status.HTTP_200_OK)
async def revoke_signing_key(
    key_id: uuid.UUID,
    current_user: User = Depends(require_fresh_mfa),
    session: AsyncSession = Depends(get_db),
) -> dict:
    """Revoke a compromised officer key.

    Signatures made before the revocation timestamp stay valid; anything after
    it is reported as pending review rather than silently accepted or rejected.
    """
    if current_user.role != Role.ADMIN:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only an admin can revoke signing keys")

    key = await session.get(OfficerSigningKey, key_id)
    if key is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Signing key not found")
    if key.status == SigningKeyStatus.REVOKED:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Signing key is already revoked")

    await officer_keys.revoke_key(session, key, current_user)

    await append_entry(
        session,
        action=AuditAction.SIGNING_KEY_REVOKED,
        actor_id=current_user.id,
        payload={
            "user_id": str(key.user_id),
            "signing_key_id": str(key.id),
            "fingerprint": key.fingerprint,
        },
    )
    await session.commit()

    return {
        "id": str(key.id),
        "status": key.status.value,
        "revoked_at": key.revoked_at.isoformat() if key.revoked_at else None,
    }


@router.get("/keys", response_model=list[EncryptionKeyResponse])
async def list_encryption_keys(
    current_user: User = Depends(require_roles(Role.ADMIN)),
    session: AsyncSession = Depends(get_db),
) -> list[EncryptionKeyResponse]:
    result = await session.execute(
        select(EncryptionKey).order_by(EncryptionKey.purpose.asc(), EncryptionKey.version.desc())
    )
    return [
        EncryptionKeyResponse(
            purpose=key.purpose.value,
            version=key.version,
            is_active=key.is_active,
            created_at=key.created_at,
            rotated_at=key.rotated_at,
        )
        for key in result.scalars().all()
    ]


@router.post("/keys/{purpose}/rotate")
async def rotate_encryption_key(
    purpose: str,
    current_user: User = Depends(require_fresh_mfa),
    session: AsyncSession = Depends(get_db),
) -> dict:
    if current_user.role != Role.ADMIN:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only an admin can rotate encryption keys")

    try:
        purpose_value = EncryptionKeyPurpose(purpose)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Unknown key purpose")

    if purpose_value == EncryptionKeyPurpose.CHECKPOINT_SIGNING:
        new_version = await key_management.rotate_pem_key(session, purpose_value)
    else:
        new_version = await key_management.rotate_key(session, purpose_value)

    key_entity_id = uuid.uuid5(uuid.NAMESPACE_DNS, f"encryption_key:{purpose_value.value}")
    await append_entry(
        session,
        action=AuditAction.KEY_ROTATED,
        actor_id=current_user.id,
        payload={"encryption_key_id": str(key_entity_id), "purpose": purpose_value.value, "new_version": new_version},
    )
    await session.commit()

    return {"purpose": purpose_value.value, "active_version": new_version}
