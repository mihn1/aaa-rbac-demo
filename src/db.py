import asyncio
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, selectinload

from .constants.permissions import (
    ALL_PERMISSIONS,
    LOG_READ_PERMISSION,
    PERMISSION_DESCRIPTIONS,
    ROLE_READ_PERMISSION,
    USER_READ_PERMISSION,
)
from .constants.roles import ADMIN_ROLE, ALL_ROLES, ROLE_DESCRIPTIONS, USER_ROLE

from .config import settings
from .search import ensure_elasticsearch_index


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
            await ensure_elasticsearch_index()
            return

    logger.error(
        "Failed to initialize database after %s attempts", settings.db_init_max_attempts
    )
    if last_error is not None:
        raise last_error
    raise RuntimeError("Failed to initialize database without an explicit error")


async def _seed_initial_data() -> None:
    from .models import DetectionRule, Permission, Role, User
    from .security import hash_password

    async with SessionLocal() as session:
        created = False

        existing_permissions = await session.execute(
            select(Permission).where(Permission.name.in_(ALL_PERMISSIONS))
        )
        permissions_by_name = {permission.name: permission for permission in existing_permissions.scalars()}

        for permission_name in ALL_PERMISSIONS:
            if permission_name not in permissions_by_name:
                permission = Permission(
                    name=permission_name,
                    description=PERMISSION_DESCRIPTIONS.get(permission_name),
                )
                session.add(permission)
                permissions_by_name[permission_name] = permission
                created = True

        existing_roles = await session.execute(
            select(Role).options(selectinload(Role.permissions)).where(Role.name.in_(ALL_ROLES))
        )
        roles_by_name = {role.name: role for role in existing_roles.scalars()}

        for role_name in ALL_ROLES:
            if role_name not in roles_by_name:
                role = Role(name=role_name, description=ROLE_DESCRIPTIONS.get(role_name))
                session.add(role)
                roles_by_name[role_name] = role
                created = True

        role_permission_map = {
            ADMIN_ROLE: ALL_PERMISSIONS,
            USER_ROLE: [LOG_READ_PERMISSION, USER_READ_PERMISSION, ROLE_READ_PERMISSION],
        }

        for role_name, permission_list in role_permission_map.items():
            role = roles_by_name.get(role_name)
            if role is None:
                continue
            current_permissions = set(role.permissions)
            for permission_name in permission_list:
                permission = permissions_by_name.get(permission_name)
                if permission and permission not in current_permissions:
                    role.permissions.append(permission)
                    created = True

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
            if ADMIN_ROLE in roles_by_name:
                admin_user.roles.append(roles_by_name[ADMIN_ROLE])
            session.add(admin_user)
            created = True
        elif ADMIN_ROLE in roles_by_name and roles_by_name[ADMIN_ROLE] not in admin_user.roles:
            admin_user.roles.append(roles_by_name[ADMIN_ROLE])
            created = True

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
            user_role = roles_by_name.get(USER_ROLE)
            if user_role:
                normal_user.roles.append(user_role)
            session.add(normal_user)
            created = True
        else:
            user_role = roles_by_name.get(USER_ROLE)
            if user_role and user_role not in normal_user.roles:
                normal_user.roles.append(user_role)
                created = True

        default_rules = [
            {
                "name": "Failed Login Burst",
                "description": "Alert when overall failed logins exceed the rolling threshold",
                "rule_type": "failed_login_threshold",
                "window_seconds": settings.brute_force_window_seconds,
                "threshold": settings.brute_force_threshold,
                "severity": "high",
                "config": {
                    "endpoint": "/auth/login",
                    "status_code": 401,
                    "result": "failure",
                },
            },
            {
                "name": "User Failed Login Spike",
                "description": "Detect a single user failing authentication repeatedly in a short window",
                "rule_type": "per_user_failed_login_threshold",
                "window_seconds": settings.brute_force_window_seconds,
                "threshold": 3,
                "severity": "high",
                "config": {
                    "endpoint": "/auth/login",
                    "status_code": 401,
                    "result": "failure",
                    "group_by": "user_name",
                },
            },
            {
                "name": "IP Failed Login Spike",
                "description": "Detect a remote host rotating through credentials and failing repeatedly",
                "rule_type": "per_ip_failed_login_threshold",
                "window_seconds": settings.brute_force_window_seconds,
                "threshold": 10,
                "severity": "medium",
                "config": {
                    "endpoint": "/auth/login",
                    "status_code": 401,
                    "result": "failure",
                    "group_by": "ip_address",
                },
            },
            {
                "name": "Forbidden Admin Probe",
                "description": "Alert when multiple forbidden hits land on admin routes from the same IP",
                "rule_type": "forbidden_admin_probe",
                "window_seconds": 300,
                "threshold": 5,
                "severity": "medium",
                "config": {
                    "status_code": 403,
                    "endpoint": {"value": "/admin/%", "match": "like"},
                    "group_by": "ip_address",
                },
            },
        ]

        for rule in default_rules:
            existing_rule = await session.scalar(
                select(DetectionRule).where(DetectionRule.name == rule["name"])
            )
            if existing_rule is None:
                session.add(DetectionRule(**rule))
                logger.info("Seeded default detection rule: %s", rule["name"])
                created = True

        if created:
            logger.info("Initial data seeded into the database")

        await session.commit()
