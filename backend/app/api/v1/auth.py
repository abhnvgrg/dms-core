from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_enrolling_user, oauth2_scheme
from app.core.security import hash_password, needs_rehash, verify_password
from app.database import get_db
from app.models.entities import AuditAction, OfficerSigningKey, Role, User
from app.schemas.auth import (
    CurrentUserResponse,
    MfaActivateRequest,
    MfaEnrollResponse,
    RefreshRequest,
    SigningKeyRegisterRequest,
    SigningKeyResponse,
    TokenResponse,
)
from app.services import devices, encryption, mfa, officer_keys, rate_limit, sessions
from app.services.audit import append_entry

router = APIRouter(prefix="/auth", tags=["authentication"])

# Roles that cannot operate the system at all without a second factor.
MFA_MANDATORY_ROLES = (Role.ADMIN,)


def _to_key_response(key: OfficerSigningKey) -> SigningKeyResponse:
    return SigningKeyResponse(
        id=key.id,
        fingerprint=key.fingerprint,
        status=key.status.value,
        public_key_pem=key.public_key_pem,
        created_at=key.created_at,
        retired_at=key.retired_at,
        revoked_at=key.revoked_at,
    )


@router.post("/login", response_model=TokenResponse)
async def login(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    totp_code: str | None = Form(None),
    session: AsyncSession = Depends(get_db),
) -> TokenResponse:
    client_ip = request.client.host if request.client else "unknown"

    for identifier in (client_ip, form_data.username):
        wait = await rate_limit.retry_after(identifier)
        if wait:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Too many failed login attempts, try again in {wait}s",
                headers={"Retry-After": str(wait)},
            )

    user = await session.scalar(
        select(User).where(User.badge_number == form_data.username)
    )

    credentials_valid = (
        user is not None
        and user.is_active
        and verify_password(form_data.password, user.password_hash)
    )

    if not credentials_valid:
        await rate_limit.register_failure(client_ip)
        if user is not None:
            just_locked = await rate_limit.register_failure(user.badge_number)
            if just_locked:
                await append_entry(
                    session,
                    action=AuditAction.LOGIN_LOCKED,
                    actor_id=user.id,
                    payload={"user_id": str(user.id), "badge_number": user.badge_number},
                )
                await session.commit()

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect badge number or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_agent = request.headers.get("user-agent")

    if user.mfa_enabled:
        secret = await encryption.decrypt_text(session, user.totp_secret_encrypted)
        if not totp_code or not secret or not mfa.verify_code(secret, totp_code):
            await rate_limit.register_failure(client_ip)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or missing MFA code",
            )

    # An account that must have a second factor, and one arriving from an
    # unfamiliar browser or network, both get an enrollment-only session rather
    # than a refusal: there has to be a way in to set the factor up, but that
    # session cannot touch evidence until enrollment completes.
    known_device = await devices.is_known(session, user, user_agent, client_ip)
    mfa_pending = not user.mfa_enabled and (
        user.role in MFA_MANDATORY_ROLES or not known_device
    )

    await rate_limit.clear_failures(client_ip)
    await rate_limit.clear_failures(user.badge_number)

    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(form_data.password)

    # Only a login that actually cleared every required factor makes the device
    # familiar. Remembering an enrollment-gated one would let the gate be walked
    # past on the second attempt.
    if not mfa_pending:
        await devices.remember(session, user, user_agent, client_ip)

    access_token, refresh_token, _ = await sessions.issue_session(
        session, user, client_ip, user_agent, mfa_pending=mfa_pending
    )
    await session.commit()

    signing_key = await officer_keys.get_active_key(session, user.id)

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        role=user.role,
        full_name=user.full_name,
        badge_number=user.badge_number,
        mfa_enabled=user.mfa_enabled,
        mfa_enrollment_required=mfa_pending,
        signing_key_registered=signing_key is not None,
    )


@router.post("/refresh", response_model=TokenResponse)
async def refresh(
    payload: RefreshRequest,
    session: AsyncSession = Depends(get_db),
) -> TokenResponse:
    try:
        access_token, refresh_token, record = await sessions.rotate_session(session, payload.refresh_token)
    except sessions.RefreshRejected as rejection:
        await session.commit()
        if rejection.reused and rejection.user_id:
            await append_entry(
                session,
                action=AuditAction.SESSION_REUSE_DETECTED,
                actor_id=rejection.user_id,
                payload={"user_id": rejection.user_id},
            )
            await session.commit()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired refresh token")

    await session.commit()

    user = await session.scalar(select(User).where(User.id == record.user_id))
    signing_key = await officer_keys.get_active_key(session, user.id)

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        role=user.role,
        full_name=user.full_name,
        badge_number=user.badge_number,
        mfa_enabled=user.mfa_enabled,
        mfa_enrollment_required=record.mfa_pending,
        signing_key_registered=signing_key is not None,
    )


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    token: str = Depends(oauth2_scheme),
    current_user: User = Depends(get_enrolling_user),
    session: AsyncSession = Depends(get_db),
) -> None:
    await sessions.revoke_session(session, token)
    await session.commit()


@router.post("/logout-everywhere", status_code=status.HTTP_204_NO_CONTENT)
async def logout_everywhere(
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> None:
    """Kill every session for this account, including the one making the call."""
    await sessions.revoke_all_sessions(session, current_user.id)
    await session.commit()


@router.post("/mfa/enroll", response_model=MfaEnrollResponse)
async def enroll_mfa(
    current_user: User = Depends(get_enrolling_user),
    session: AsyncSession = Depends(get_db),
) -> MfaEnrollResponse:
    secret = mfa.generate_secret()
    current_user.totp_secret_encrypted = await encryption.encrypt_text(session, secret)
    current_user.mfa_enabled = False
    await session.commit()

    return MfaEnrollResponse(
        secret=secret,
        provisioning_uri=mfa.provisioning_uri(current_user.badge_number, secret),
    )


@router.post("/mfa/activate", response_model=TokenResponse)
async def activate_mfa(
    request: Request,
    payload: MfaActivateRequest,
    current_user: User = Depends(get_enrolling_user),
    session: AsyncSession = Depends(get_db),
) -> TokenResponse:
    """Confirm enrollment, then hand back a fresh session.

    Enrolling raises what this account is allowed to do, so the token that was
    issued at the lower privilege level is retired rather than silently
    promoted — v4 §4 closes session fixation on privilege change, not only on
    login.
    """
    secret = await encryption.decrypt_text(session, current_user.totp_secret_encrypted)
    if not secret or not mfa.verify_code(secret, payload.code):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid MFA code")

    current_user.mfa_enabled = True

    await append_entry(
        session,
        action=AuditAction.MFA_ENABLED,
        actor_id=current_user.id,
        payload={"user_id": str(current_user.id)},
    )

    client_ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent")
    await devices.remember(session, current_user, user_agent, client_ip)

    await sessions.revoke_all_sessions(session, current_user.id)
    access_token, refresh_token, _ = await sessions.issue_session(
        session, current_user, client_ip, user_agent
    )
    await session.commit()

    signing_key = await officer_keys.get_active_key(session, current_user.id)

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        role=current_user.role,
        full_name=current_user.full_name,
        badge_number=current_user.badge_number,
        mfa_enabled=True,
        mfa_enrollment_required=False,
        signing_key_registered=signing_key is not None,
    )


@router.post("/signing-keys", response_model=SigningKeyResponse, status_code=status.HTTP_201_CREATED)
async def register_signing_key(
    payload: SigningKeyRegisterRequest,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> SigningKeyResponse:
    """Register the public half of a keypair generated in the officer's browser.

    Called again on rotation: the previous key is retired, not deleted, so
    signatures made with it still verify.
    """
    try:
        key = await officer_keys.register_key(session, current_user, payload.public_key_pem)
    except officer_keys.InvalidPublicKey as error:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(error))

    await append_entry(
        session,
        action=AuditAction.SIGNING_KEY_REGISTERED,
        actor_id=current_user.id,
        payload={
            "user_id": str(current_user.id),
            "signing_key_id": str(key.id),
            "fingerprint": key.fingerprint,
        },
    )
    await session.commit()

    return _to_key_response(key)


@router.get("/signing-keys", response_model=list[SigningKeyResponse])
async def list_signing_keys(
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> list[SigningKeyResponse]:
    keys = await officer_keys.list_keys(session, current_user.id)
    return [_to_key_response(key) for key in keys]


@router.get("/me", response_model=CurrentUserResponse)
async def get_me(
    current_user: User = Depends(get_enrolling_user),
    session: AsyncSession = Depends(get_db),
) -> CurrentUserResponse:
    signing_key = await officer_keys.get_active_key(session, current_user.id)
    return CurrentUserResponse(
        id=current_user.id,
        badge_number=current_user.badge_number,
        full_name=current_user.full_name,
        role=current_user.role,
        mfa_enabled=current_user.mfa_enabled,
        signing_key_fingerprint=signing_key.fingerprint if signing_key else None,
    )
