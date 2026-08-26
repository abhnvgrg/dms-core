import pyotp

from app.core.config import get_settings


def generate_secret() -> str:
    return pyotp.random_base32()


def provisioning_uri(badge_number: str, secret: str) -> str:
    return pyotp.totp.TOTP(secret).provisioning_uri(
        name=badge_number, issuer_name=get_settings().mfa_issuer
    )


def verify_code(secret: str, code: str) -> bool:
    return pyotp.TOTP(secret).verify(code, valid_window=1)


async def is_code_used(user_id, code: str) -> bool:
    """TOTP codes stay valid for a window; replay within it is still replay."""
    from app.services.rate_limit import _redis

    return await _redis().exists(f"mfa_used:{user_id}:{code}") == 1


async def mark_code_used(user_id, code: str) -> None:
    from app.services.rate_limit import _redis

    await _redis().set(f"mfa_used:{user_id}:{code}", "1", ex=180)
