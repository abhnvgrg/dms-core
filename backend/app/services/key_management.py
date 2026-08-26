from datetime import datetime, timezone

from cryptography.fernet import Fernet
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.models.entities import EncryptionKey, EncryptionKeyPurpose

_root: Fernet | None = None


def _root_fernet() -> Fernet:
    global _root
    if _root is None:
        _root = Fernet(get_settings().root_encryption_key.encode("utf-8"))
    return _root


async def get_active_key(session: AsyncSession, purpose: EncryptionKeyPurpose) -> tuple[int, bytes]:
    row = await session.scalar(
        select(EncryptionKey).where(EncryptionKey.purpose == purpose, EncryptionKey.is_active.is_(True))
    )
    if row is not None:
        return row.version, _root_fernet().decrypt(row.wrapped_key.encode("utf-8"))

    raw_key = Fernet.generate_key()
    wrapped = _root_fernet().encrypt(raw_key).decode("utf-8")
    row = EncryptionKey(purpose=purpose, version=1, wrapped_key=wrapped, is_active=True)
    session.add(row)
    await session.flush()
    return 1, raw_key


async def get_key_version(session: AsyncSession, purpose: EncryptionKeyPurpose, version: int) -> bytes:
    row = await session.scalar(
        select(EncryptionKey).where(EncryptionKey.purpose == purpose, EncryptionKey.version == version)
    )
    if row is None:
        raise ValueError(f"No {purpose.value} key at version {version}")
    return _root_fernet().decrypt(row.wrapped_key.encode("utf-8"))


async def rotate_key(session: AsyncSession, purpose: EncryptionKeyPurpose) -> int:
    current = await session.scalar(
        select(EncryptionKey).where(EncryptionKey.purpose == purpose, EncryptionKey.is_active.is_(True))
    )
    next_version = 1
    if current is not None:
        current.is_active = False
        current.rotated_at = datetime.now(timezone.utc)
        next_version = current.version + 1

    raw_key = Fernet.generate_key()
    wrapped = _root_fernet().encrypt(raw_key).decode("utf-8")
    row = EncryptionKey(purpose=purpose, version=next_version, wrapped_key=wrapped, is_active=True)
    session.add(row)
    await session.flush()
    return next_version


async def get_or_create_pem_key(
    session: AsyncSession, purpose: EncryptionKeyPurpose
) -> tuple[int, bytes]:
    """Like get_active_key, but the wrapped material is an RSA private key.

    Used for the checkpoint signing key, which has to be asymmetric so that
    verifying a checkpoint never requires the ability to forge one.
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    row = await session.scalar(
        select(EncryptionKey).where(EncryptionKey.purpose == purpose, EncryptionKey.is_active.is_(True))
    )
    if row is not None:
        return row.version, _root_fernet().decrypt(row.wrapped_key.encode("utf-8"))

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    wrapped = _root_fernet().encrypt(pem).decode("utf-8")
    row = EncryptionKey(purpose=purpose, version=1, wrapped_key=wrapped, is_active=True)
    session.add(row)
    await session.flush()
    return 1, pem


async def rotate_pem_key(session: AsyncSession, purpose: EncryptionKeyPurpose) -> int:
    """Rotate an asymmetric key, keeping old versions so old signatures verify."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    current = await session.scalar(
        select(EncryptionKey).where(EncryptionKey.purpose == purpose, EncryptionKey.is_active.is_(True))
    )
    next_version = 1
    if current is not None:
        current.is_active = False
        current.rotated_at = datetime.now(timezone.utc)
        next_version = current.version + 1

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    wrapped = _root_fernet().encrypt(pem).decode("utf-8")
    row = EncryptionKey(purpose=purpose, version=next_version, wrapped_key=wrapped, is_active=True)
    session.add(row)
    await session.flush()
    return next_version
