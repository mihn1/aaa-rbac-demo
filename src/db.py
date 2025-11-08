from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

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
    from . import models

    attempt = 0
    last_error: Exception | None = None

    while attempt < settings.db_init_max_attempts:
        attempt += 1
        try:
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
        except Exception as exc:  # noqa: BLE001 - propagate for final attempt
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
            return

    logger.error(
        "Failed to initialize database after %s attempts", settings.db_init_max_attempts
    )
    if last_error is not None:
        raise last_error
    raise RuntimeError("Failed to initialize database without an explicit error")
