from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, selectinload

from .config import settings


class Base(DeclarativeBase):
    """Base class for all ORM models."""


logger = logging.getLogger(__name__)


engine: AsyncEngine = create_async_engine(
    settings.database_url,
    echo=settings.environment == "development",
    future=True,
    pool_pre_ping=True,
)
SessionLocal = async_sessionmaker(engine, expire_on_commit=False)


@asynccontextmanager
async def session_manager() -> AsyncIterator[AsyncSession]:
    session: AsyncSession = SessionLocal()
    try:
        yield session
        await session.commit()
    except Exception:
        await session.rollback()
        raise
    finally:
        await session.close()


async def get_session() -> AsyncIterator[AsyncSession]:
    async with session_manager() as session:
        yield session


async def init_db() -> None:
    attempt = 0
    last_error: Exception | None = None

    while attempt < settings.db_init_max_attempts:
        attempt += 1
        try:
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
        except Exception as exc:
            last_error = exc
            if attempt >= settings.db_init_max_attempts:
                break
            wait_time = settings.db_init_retry_seconds
            logger.warning(
                "Database unavailable (attempt %s/%s): %s; retrying in %.1f seconds",
                attempt,
                settings.db_init_max_attempts,
                exc,
                wait_time,
            )
            await asyncio.sleep(wait_time)
        else:
            if attempt > 1:
                logger.info("Database connection re-established after %s attempts", attempt)
            await _seed_initial_data()
            return

    logger.error(
        "Failed to initialize database after %s attempts", settings.db_init_max_attempts
    )
    if last_error is not None:
        raise last_error
    raise RuntimeError("Failed to initialize database without an explicit error")


async def _seed_initial_data() -> None:
    from .models import Permission, Role, User
    from .security import hash_password

    async with SessionLocal() as session:
        created = False

        admin_permission = await session.scalar(
            select(Permission).where(Permission.name == "admin:manage")
        )
        if admin_permission is None:
            admin_permission = Permission(
                name="admin:manage",
                description="Full administrative access",
            )
            session.add(admin_permission)
            created = True

        logs_permission = await session.scalar(
            select(Permission).where(Permission.name == "logs:view")
        )
        if logs_permission is None:
            logs_permission = Permission(
                name="logs:view",
                description="View audit logs",
            )
            session.add(logs_permission)
            created = True

        admin_role = await session.scalar(
            select(Role).options(selectinload(Role.permissions)).where(Role.name == "Administrator")
        )
        if admin_role is None:
            admin_role = Role(name="Administrator", description="Platform administrator")
            session.add(admin_role)
            created = True
        if admin_permission and admin_permission not in admin_role.permissions:
            admin_role.permissions.append(admin_permission)
            created = True
        if logs_permission and logs_permission not in admin_role.permissions:
            admin_role.permissions.append(logs_permission)
            created = True

        # seed admin user
        admin_user = await session.scalar(
            select(User).options(selectinload(User.roles)).where(User.username == "admin")
        )
        if admin_user is None:
            admin_user = User(
                username="admin",
                email="admin@example.com",
                hashed_password=hash_password("admin"),
                is_active=True,
            )
            admin_user.roles.append(admin_role)
            session.add(admin_user)
            created = True
        elif admin_role not in admin_user.roles:
            admin_user.roles.append(admin_role)
            created = True

        # seed normal user
        normal_user = await session.scalar(
            select(User).options(selectinload(User.roles)).where(User.username == "user")
        )
        if normal_user is None:
            normal_user = User(
                username="user",
                email="user@example.com",
                hashed_password=hash_password("user"),
                is_active=True,
            )
            session.add(normal_user)
            created = True

        if created:
            logger.info("Initial data seeded into the database")

        await session.commit()
