from __future__ import annotations

from typing import Iterable

from fastapi import Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .db import get_session
from .models import Permission, Role, User
from .security import get_current_user


async def fetch_user_permissions(session: AsyncSession, user: User) -> set[str]:
    stmt = (
        select(Permission.name)
        .join(Role.permissions)
        .join(Role.users)
        .where(User.id == user.id)
    )
    result = await session.execute(stmt)
    return {row[0] for row in result}


async def require_roles(
    required_roles: Iterable[str],
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> User:
    stmt = select(Role.name).join(Role.users).where(User.id == current_user.id)
    result = await session.execute(stmt)
    user_roles = {row[0] for row in result}

    if not set(required_roles).intersection(user_roles):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient role")
    return current_user


def require_permission(permission_name: str):
    async def dependency(
        current_user: User = Depends(get_current_user),
        session: AsyncSession = Depends(get_session),
    ) -> User:
        permissions = await fetch_user_permissions(session, current_user)
        if permission_name not in permissions:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permission")
        return current_user

    return dependency


def require_permissions(permission_names: Iterable[str]):
    required = set(permission_names)

    async def dependency(
        current_user: User = Depends(get_current_user),
        session: AsyncSession = Depends(get_session),
    ) -> User:
        permissions = await fetch_user_permissions(session, current_user)
        if not required.issubset(permissions):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")
        return current_user

    return dependency
