import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.entities import Session, User

ACCESS_TOKEN_MINUTES = 15
REFRESH_TOKEN_HOURS = 8


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _new_token() -> str:
    return secrets.token_urlsafe(32)


async def issue_session(
    session: AsyncSession,
    user: User,
    ip_address: str | None,
    user_agent: str | None,
    mfa_pending: bool = False,
) -> tuple[str, str, Session]:
    access_token = _new_token()
    refresh_token = _new_token()
    now = datetime.now(timezone.utc)

    record = Session(
        user_id=user.id,
        access_token_hash=_hash_token(access_token),
        refresh_token_hash=_hash_token(refresh_token),
        access_expires_at=now + timedelta(minutes=ACCESS_TOKEN_MINUTES),
        refresh_expires_at=now + timedelta(hours=REFRESH_TOKEN_HOURS),
        ip_address=ip_address,
        user_agent=user_agent,
        mfa_pending=mfa_pending,
    )
    session.add(record)
    await session.flush()

    return access_token, refresh_token, record


async def get_session_by_access_token(session: AsyncSession, access_token: str) -> Session | None:
    return await session.scalar(
        select(Session).where(Session.access_token_hash == _hash_token(access_token))
    )


async def get_live_session(session: AsyncSession, access_token: str) -> Session | None:
    record = await get_session_by_access_token(session, access_token)
    if record is None:
        return None

    now = datetime.now(timezone.utc)
    if record.revoked_at is not None or record.access_expires_at < now:
        return None

    return record


async def resolve_user_for_access_token(session: AsyncSession, access_token: str) -> User | None:
    record = await get_live_session(session, access_token)
    if record is None:
        return None

    return await session.scalar(select(User).where(User.id == record.user_id))



class RefreshRejected(Exception):
    def __init__(self, reused: bool, user_id: str | None = None):
        self.reused = reused
        self.user_id = user_id


async def rotate_session(
    session: AsyncSession, refresh_token: str
) -> tuple[str, str, Session]:
    presented_hash = _hash_token(refresh_token)

    record = await session.scalar(select(Session).where(Session.refresh_token_hash == presented_hash))
    if record is not None:
        now = datetime.now(timezone.utc)
        if record.revoked_at is not None or record.refresh_expires_at < now:
            raise RefreshRejected(reused=False)

        access_token = _new_token()
        new_refresh_token = _new_token()

        record.previous_refresh_token_hash = record.refresh_token_hash
        record.access_token_hash = _hash_token(access_token)
        record.refresh_token_hash = _hash_token(new_refresh_token)
        record.access_expires_at = now + timedelta(minutes=ACCESS_TOKEN_MINUTES)
        await session.flush()

        return access_token, new_refresh_token, record

    reused = await session.scalar(
        select(Session).where(Session.previous_refresh_token_hash == presented_hash)
    )
    if reused is not None and reused.revoked_at is None:
        reused.revoked_at = datetime.now(timezone.utc)
        await session.flush()
        raise RefreshRejected(reused=True, user_id=str(reused.user_id))

    raise RefreshRejected(reused=False)


async def revoke_session(session: AsyncSession, access_token: str) -> None:
    record = await get_session_by_access_token(session, access_token)
    if record is not None:
        record.revoked_at = datetime.now(timezone.utc)
        await session.flush()


async def revoke_all_sessions(session: AsyncSession, user_id) -> None:
    result = await session.execute(
        select(Session).where(Session.user_id == user_id, Session.revoked_at.is_(None))
    )
    for record in result.scalars().all():
        record.revoked_at = datetime.now(timezone.utc)
    await session.flush()
