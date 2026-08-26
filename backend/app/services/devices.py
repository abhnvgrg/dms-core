"""Recognising the browser and network an officer normally logs in from.

v4 §5 requires a second factor for any login from a new or unrecognised device
or IP range. For a user with MFA enabled that is satisfied already, since a code
is demanded on every login. This exists so the rule still means something for a
user who has not enrolled: an unfamiliar login gets an enrollment-only session
rather than a free pass.
"""
import hashlib
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.entities import KnownDevice, User


def _ip_range(ip_address: str | None) -> str:
    """Collapse an address to its range, so a new lease is not a new device."""
    if not ip_address:
        return "unknown"

    if ":" in ip_address:  # IPv6: keep the routing prefix
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
    """Record the device, but only once the login has actually been allowed."""
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
