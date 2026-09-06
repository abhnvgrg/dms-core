import hashlib
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.entities import KnownDevice, User


def _ip_range(ip_address: str | None) -> str:
    if not ip_address:
        return "unknown"

    if ":" in ip_address:
        return ":".join(ip_address.split(":")[:4])

    octets = ip_address.split(".")
    if len(octets) == 4:
        return ".".join(octets[:3])

    return ip_address


def fingerprint(user_agent: str | None, ip_address: str | None) -> str:
    return hashlib.sha256(
        f"{user_agent or 'unknown'}|{_ip_range(ip_address)}".encode("utf-8")
    ).hexdigest()


async def is_known(
    session: AsyncSession, user: User, user_agent: str | None, ip_address: str | None
) -> bool:
    record = await session.scalar(
        select(KnownDevice).where(
            KnownDevice.user_id == user.id,
            KnownDevice.fingerprint == fingerprint(user_agent, ip_address),
        )
    )
    return record is not None


async def remember(
    session: AsyncSession, user: User, user_agent: str | None, ip_address: str | None
) -> None:
    digest = fingerprint(user_agent, ip_address)
    now = datetime.now(timezone.utc)

    record = await session.scalar(
        select(KnownDevice).where(
            KnownDevice.user_id == user.id, KnownDevice.fingerprint == digest
        )
    )

    if record is None:
        session.add(
            KnownDevice(
                user_id=user.id,
                fingerprint=digest,
                user_agent=(user_agent or "")[:512] or None,
                ip_address=ip_address,
                first_seen_at=now,
                last_seen_at=now,
            )
        )
    else:
        record.last_seen_at = now

    await session.flush()
