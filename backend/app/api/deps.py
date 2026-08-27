from fastapi import Depends, Header, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.entities import Role, Session, User
from app.services import mfa, sessions
from app.services.encryption import decrypt_text

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")


async def get_session_record(
    token: str = Depends(oauth2_scheme),
    session: AsyncSession = Depends(get_db),
) -> Session:
    record = await sessions.get_live_session(session, token)

    if record is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired session",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return record


async def get_current_user(
    record: Session = Depends(get_session_record),
    session: AsyncSession = Depends(get_db),
) -> User:
    user = await session.get(User, record.user_id)

    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired session",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # A session issued to a privileged user who has not yet enrolled MFA can do
    # exactly one thing: enrol. Everything else is closed until they do.
    if record.mfa_pending:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="MFA enrollment is required before this account can be used",
        )

    return user


async def get_enrolling_user(
    record: Session = Depends(get_session_record),
    session: AsyncSession = Depends(get_db),
) -> User:
    """Like get_current_user, but usable from an enrollment-only session."""
    user = await session.get(User, record.user_id)

    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired session",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user


def require_roles(*allowed_roles: Role):
    async def role_guard(
        current_user: User = Depends(get_current_user),
    ) -> User:
        if current_user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You do not have permission to perform this action",
            )

        return current_user

    return role_guard


async def require_fresh_mfa(
    x_mfa_code: str | None = Header(None),
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> User:
    """Step-up: a valid session is not enough for actions with legal consequences.

    Fails closed. A user who has never enrolled cannot perform these actions at
    all -- being un-enrolled is not a way to skip the check.
    """
    if not current_user.mfa_enabled:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "This action requires multi-factor authentication. "
                "Enrol at /api/v1/auth/mfa/enroll first."
            ),
        )

    if not x_mfa_code:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="This action requires a fresh MFA code (X-MFA-Code header)",
        )

    secret = await decrypt_text(session, current_user.totp_secret_encrypted)
    if not secret or not mfa.verify_code(secret, x_mfa_code):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid MFA code")

    if await mfa.is_code_used(current_user.id, x_mfa_code):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="This MFA code has already been used; wait for the next one",
        )
    await mfa.mark_code_used(current_user.id, x_mfa_code)

    return current_user


def require_roles_with_fresh_mfa(*allowed_roles: Role):
    """Role check plus step-up, as one dependency.

    Declaring both in the signature is what makes the requirement visible in
    the OpenAPI schema and to the route audit. An equivalent check written
    inside the handler body is invisible to both, and can be skipped by an
    early return added later.
    """

    async def role_guard(
        current_user: User = Depends(require_fresh_mfa),
    ) -> User:
        if current_user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You do not have permission to perform this action",
            )

        return current_user

    return role_guard
