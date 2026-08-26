"""Login throttling: exponential backoff per identifier, then a hard lockout.

Applied to both the badge number and the client IP, so neither guessing one
account from many addresses nor many accounts from one address gets unlimited
attempts.
"""
from redis.asyncio import Redis

from app.core.config import get_settings

FREE_ATTEMPTS = 3
MAX_ATTEMPTS = 8
FAILURE_WINDOW_SECONDS = 900
BASE_BACKOFF_SECONDS = 2
MAX_BACKOFF_SECONDS = 300
LOCKOUT_SECONDS = 900

_client: Redis | None = None


def _redis() -> Redis:
    global _client
    if _client is None:
        _client = Redis.from_url(get_settings().redis_url, decode_responses=True)
    return _client


def backoff_seconds(attempts: int) -> int:
    """0s for the first few failures, then 2s, 4s, 8s... capped at 5 minutes."""
    if attempts <= FREE_ATTEMPTS:
        return 0
    return min(BASE_BACKOFF_SECONDS ** (attempts - FREE_ATTEMPTS), MAX_BACKOFF_SECONDS)


async def is_locked(identifier: str) -> bool:
    return await _redis().exists(f"login_lock:{identifier}") == 1


async def retry_after(identifier: str) -> int:
    """Seconds the caller must wait: the hard lockout if set, else the backoff."""
    client = _redis()

    lock_ttl = await client.ttl(f"login_lock:{identifier}")
    if lock_ttl and lock_ttl > 0:
        return lock_ttl

    backoff_ttl = await client.ttl(f"login_backoff:{identifier}")
    return backoff_ttl if backoff_ttl and backoff_ttl > 0 else 0


async def register_failure(identifier: str) -> bool:
    """Record a failure. Returns True if this one triggered the hard lockout."""
    client = _redis()
    key = f"login_fail:{identifier}"

    attempts = await client.incr(key)
    if attempts == 1:
        await client.expire(key, FAILURE_WINDOW_SECONDS)

    if attempts >= MAX_ATTEMPTS:
        await client.set(f"login_lock:{identifier}", "1", ex=LOCKOUT_SECONDS)
        return True

    delay = backoff_seconds(attempts)
    if delay:
        await client.set(f"login_backoff:{identifier}", "1", ex=delay)

    return False


async def clear_failures(identifier: str) -> None:
    client = _redis()
    await client.delete(f"login_fail:{identifier}")
    await client.delete(f"login_backoff:{identifier}")
    await client.delete(f"login_lock:{identifier}")
