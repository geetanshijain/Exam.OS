"""
Run once to seed the database with four demo users.
Usage: python seed.py  (from the backend/ directory)
"""

import asyncio

from sqlalchemy import select

from app.core.security import hash_password
from app.db.session import AsyncSessionLocal, engine
from app.models import Base, User, UserRole


SEED_USERS = [
    {"email": "setter@examos.com",     "full_name": "Alex Setter",      "role": UserRole.setter},
    {"email": "hod@examos.com",        "full_name": "Dr. HOD Controller","role": UserRole.controller},
    {"email": "controller@examos.com", "full_name": "Sam Controller",    "role": UserRole.controller},
    {"email": "printer@examos.com",    "full_name": "Pat Printer",       "role": UserRole.printer},
]

PASSWORD = "password123"


async def seed() -> None:
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with AsyncSessionLocal() as session:
        for ud in SEED_USERS:
            existing = await session.scalar(select(User).where(User.email == ud["email"]))
            if existing:
                print(f"  skip  {ud['email']} (already exists)")
                continue

            user = User(
                email=ud["email"],
                full_name=ud["full_name"],
                role=ud["role"],
                hashed_password=hash_password(PASSWORD),
            )
            session.add(user)
            print(f"  seed  {ud['email']} [{ud['role'].value}]")

        await session.commit()
    print("Done.")


if __name__ == "__main__":
    asyncio.run(seed())
