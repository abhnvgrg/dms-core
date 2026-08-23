import asyncio
from getpass import getpass

from sqlalchemy import select

from app.core.security import hash_password
from app.database import AsyncSessionLocal
from app.models.entities import Role, User


DEVELOPMENT_USERS = [
    ("IO-001", "Investigating Officer Sharma", Role.INVESTIGATING_OFFICER),
    ("FOR-001", "Forensics Officer Mehta", Role.FORENSICS_OFFICER),
    ("COURT-001", "Court Official Rao", Role.COURT_OFFICIAL),
    ("ADM-001", "Administrator Verma", Role.ADMIN),
]


async def seed_users() -> None:
    password = getpass("Development password for all seeded users: ")

    if len(password) < 12:
        raise ValueError("Use a development password of at least 12 characters.")

    async with AsyncSessionLocal() as session:
        for badge_number, full_name, role in DEVELOPMENT_USERS:
            existing = await session.scalar(
                select(User).where(User.badge_number == badge_number)
            )

            if existing is not None:
                print(f"Skipped existing user: {badge_number}")
                continue

            session.add(
                User(
                    badge_number=badge_number,
                    full_name=full_name,
                    role=role,
                    password_hash=hash_password(password),
                    is_active=True,
                )
            )
            print(f"Created user: {badge_number} ({role.value})")

        await session.commit()


if __name__ == "__main__":
    asyncio.run(seed_users())