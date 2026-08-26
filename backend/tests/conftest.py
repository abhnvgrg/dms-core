from __future__ import annotations

import asyncio
import os
import uuid

import pytest
import pytest_asyncio

os.environ.setdefault("MINIO_ACCESS_KEY", "test-access-key")
os.environ.setdefault("MINIO_SECRET_KEY", "test-secret-key")
os.environ.setdefault("ROOT_ENCRYPTION_KEY", "6Yt3xUlSKZ1nS3HmB6pJvY5PbLQq3H4bYyR9dQnJqXo=")
os.environ.setdefault("BLOCKCHAIN_ANCHORING_ENABLED", "false")
os.environ.setdefault("MALWARE_SCANNING_ENABLED", "false")

TEST_DATABASE_URL = os.environ.get(
    "NYAYVAULT_TEST_DATABASE_URL",
    "postgresql+asyncpg://nyayvault:11239@localhost:5432/nyayvault_test",
)
os.environ["DATABASE_URL"] = TEST_DATABASE_URL

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine  # noqa: E402

from app.models.entities import Base, Role, User  # noqa: E402


def _maintenance_url(url: str) -> tuple[str, str]:
    base, _, database = url.rpartition("/")
    return f"{base}/postgres", database


async def _ensure_database() -> None:
    import asyncpg

    admin_url, database = _maintenance_url(TEST_DATABASE_URL)
    dsn = admin_url.replace("postgresql+asyncpg://", "postgresql://")

    conn = await asyncpg.connect(dsn)
    try:
        exists = await conn.fetchval(
            "SELECT 1 FROM pg_database WHERE datname = $1", database
        )
        if not exists:
            await conn.execute(f'CREATE DATABASE "{database}"')
    finally:
        await conn.close()

    dsn = TEST_DATABASE_URL.replace("postgresql+asyncpg://", "postgresql://")
    conn = await asyncpg.connect(dsn)
    try:
        await conn.execute("CREATE EXTENSION IF NOT EXISTS vector")
        await conn.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto")
    finally:
        await conn.close()


def pytest_configure(config):
    try:
        asyncio.run(asyncio.wait_for(_ensure_database(), timeout=10))
    except Exception as error:
        pytest.exit(
            f"PostgreSQL is not reachable at {TEST_DATABASE_URL}.\n"
            f"Start it with: docker compose -f infrastructure/docker-compose.yml up -d postgres\n"
            f"Or point NYAYVAULT_TEST_DATABASE_URL at another instance.\n"
            f"({type(error).__name__}: {error})",
            returncode=1,
        )


@pytest_asyncio.fixture(scope="session")
async def engine():
    engine = create_async_engine(TEST_DATABASE_URL, pool_pre_ping=True)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()


@pytest_asyncio.fixture
async def session(engine):
    connection = await engine.connect()
    transaction = await connection.begin()
    maker = async_sessionmaker(bind=connection, class_=AsyncSession, expire_on_commit=False)

    async with maker() as session:
        yield session

    await transaction.rollback()
    await connection.close()


@pytest.fixture(autouse=True)
def offline_object_storage(monkeypatch):
    from app.services import storage

    def unavailable(*args, **kwargs):
        raise ConnectionError("object storage is offline in tests")

    monkeypatch.setattr(storage, "put_checkpoint", unavailable)


@pytest.fixture
def working_object_storage(monkeypatch):
    written: dict[int, bytes] = {}

    def put(checkpoint_id: int, data: bytes) -> str:
        written[checkpoint_id] = data
        return f"checkpoints/{checkpoint_id:012d}.json"

    from app.services import storage

    monkeypatch.setattr(storage, "put_checkpoint", put)
    return written


@pytest_asyncio.fixture
async def officer(session) -> User:
    user = User(
        id=uuid.uuid4(),
        badge_number=f"BADGE-{uuid.uuid4().hex[:8]}",
        full_name="Test Officer",
        role=Role.INVESTIGATING_OFFICER,
        password_hash="not-used-in-these-tests",
    )
    session.add(user)
    await session.flush()
    return user


@pytest_asyncio.fixture
async def admin(session) -> User:
    user = User(
        id=uuid.uuid4(),
        badge_number=f"ADMIN-{uuid.uuid4().hex[:8]}",
        full_name="Test Admin",
        role=Role.ADMIN,
        password_hash="not-used-in-these-tests",
    )
    session.add(user)
    await session.flush()
    return user
