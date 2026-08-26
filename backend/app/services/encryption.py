import logging

from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.entities import EncryptionKeyPurpose
from app.services import key_management

logger = logging.getLogger(__name__)


async def encrypt_text(session: AsyncSession, plaintext: str | None) -> str | None:
    if not plaintext:
        return plaintext

    version, raw_key = await key_management.get_active_key(session, EncryptionKeyPurpose.PII_DATA)
    token = Fernet(raw_key).encrypt(plaintext.encode("utf-8")).decode("utf-8")
    return f"{version}:{token}"


async def decrypt_text(session: AsyncSession, ciphertext: str | None) -> str | None:
    if not ciphertext:
        return ciphertext

    version_str, _, token = ciphertext.partition(":")
    if not token or not version_str.isdigit():
        return ciphertext

    try:
        raw_key = await key_management.get_key_version(session, EncryptionKeyPurpose.PII_DATA, int(version_str))
        return Fernet(raw_key).decrypt(token.encode("utf-8")).decode("utf-8")
    except (InvalidToken, ValueError):
        logger.warning("Failed to decrypt PII field; returning raw stored value (legacy/dev fallback)")
        return ciphertext


async def encrypt_bytes(session: AsyncSession, data: bytes) -> bytes:
    version, raw_key = await key_management.get_active_key(session, EncryptionKeyPurpose.OBJECT_STORAGE)
    token = Fernet(raw_key).encrypt(data)
    return f"{version}:".encode("utf-8") + token


async def decrypt_bytes(session: AsyncSession, blob: bytes) -> bytes:
    header, _, token = blob.partition(b":")
    if not token or not header.isdigit():
        return blob

    raw_key = await key_management.get_key_version(session, EncryptionKeyPurpose.OBJECT_STORAGE, int(header))
    return Fernet(raw_key).decrypt(token)
