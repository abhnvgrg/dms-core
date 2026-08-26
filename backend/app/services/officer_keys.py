"""Officer signing-key custody.

The private half of these keys is generated in the officer's browser and never
leaves it, so the server can only ever verify. Registering, rotating and revoking
a key are all recorded in the audit ledger by the callers in `app/api/v1`.
"""
import hashlib
from datetime import datetime, timezone

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.entities import OfficerSigningKey, SigningKeyStatus, User

# WebCrypto signs with a fixed salt length equal to the digest size; python's
# AUTO would also verify, but pinning it keeps both halves explicit.
_PSS_PADDING = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)

MIN_KEY_SIZE_BITS = 2048


class InvalidPublicKey(Exception):
    pass


def fingerprint(public_key_pem: str) -> str:
    return hashlib.sha256(public_key_pem.strip().encode("utf-8")).hexdigest()


def _load_public_key(public_key_pem: str):
    try:
        key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
    except Exception as error:
        raise InvalidPublicKey("Public key is not valid PEM") from error

    if not isinstance(key, rsa.RSAPublicKey):
        raise InvalidPublicKey("Only RSA public keys are accepted")
    if key.key_size < MIN_KEY_SIZE_BITS:
        raise InvalidPublicKey(f"Key must be at least {MIN_KEY_SIZE_BITS} bits")

    return key


async def get_active_key(session: AsyncSession, user_id) -> OfficerSigningKey | None:
    return await session.scalar(
        select(OfficerSigningKey).where(
            OfficerSigningKey.user_id == user_id,
            OfficerSigningKey.status == SigningKeyStatus.ACTIVE,
        )
    )


async def list_keys(session: AsyncSession, user_id) -> list[OfficerSigningKey]:
    result = await session.execute(
        select(OfficerSigningKey)
        .where(OfficerSigningKey.user_id == user_id)
        .order_by(OfficerSigningKey.created_at.desc())
    )
    return list(result.scalars().all())


async def register_key(
    session: AsyncSession, user: User, public_key_pem: str
) -> OfficerSigningKey:
    """Register a new public key, retiring whatever the officer had before.

    Retiring rather than deleting is what keeps historical signatures verifiable
    after a rotation.
    """
    _load_public_key(public_key_pem)

    digest = fingerprint(public_key_pem)
    existing = await session.scalar(
        select(OfficerSigningKey).where(OfficerSigningKey.fingerprint == digest)
    )
    if existing is not None:
        raise InvalidPublicKey("This public key is already registered")

    current = await get_active_key(session, user.id)
    if current is not None:
        current.status = SigningKeyStatus.RETIRED
        current.retired_at = datetime.now(timezone.utc)

    key = OfficerSigningKey(
        user_id=user.id,
        public_key_pem=public_key_pem.strip(),
        fingerprint=digest,
        status=SigningKeyStatus.ACTIVE,
    )
    session.add(key)
    user.public_key_pem = public_key_pem.strip()
    await session.flush()
    return key


async def revoke_key(
    session: AsyncSession, key: OfficerSigningKey, revoked_by: User
) -> OfficerSigningKey:
    key.status = SigningKeyStatus.REVOKED
    key.revoked_at = datetime.now(timezone.utc)
    key.revoked_by_id = revoked_by.id

    owner = await session.scalar(select(User).where(User.id == key.user_id))
    if owner is not None and owner.public_key_pem == key.public_key_pem:
        owner.public_key_pem = None

    await session.flush()
    return key


def verify_signature(public_key_pem: str, message: str, signature_b64: str) -> bool:
    """Verify a base64 RSA-PSS/SHA-256 signature produced by WebCrypto."""
    import base64

    try:
        key = _load_public_key(public_key_pem)
        key.verify(
            base64.b64decode(signature_b64),
            message.encode("utf-8"),
            _PSS_PADDING,
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False


def signature_status(key: OfficerSigningKey, signed_at: datetime) -> str:
    """How much a signature made with this key is worth now.

    Signatures predating a revocation stay valid; anything after it is suspect
    until a human has looked at it.
    """
    if key.status != SigningKeyStatus.REVOKED or key.revoked_at is None:
        return "valid"

    revoked_at = key.revoked_at
    if revoked_at.tzinfo is None:
        revoked_at = revoked_at.replace(tzinfo=timezone.utc)
    if signed_at.tzinfo is None:
        signed_at = signed_at.replace(tzinfo=timezone.utc)

    return "valid" if signed_at < revoked_at else "pending_review"
