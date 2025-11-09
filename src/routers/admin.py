from pathlib import Path
from typing import Iterable, Sequence
from fastapi import APIRouter, Depends, Form, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from src.constants.permissions import (
    ROLE_MANAGE_PERMISSION,
    ROLE_READ_PERMISSION,
    USER_MANAGE_PERMISSION,
    USER_READ_PERMISSION,
)

from ..db import get_session
from ..models import Permission, Role, User
from ..rbac import require_permission
from ..security import hash_password

router = APIRouter()

template_dir = Path(__file__).resolve().parent.parent / "templates"
templates = Jinja2Templates(directory=str(template_dir))

def _parse_id_list(values: Iterable[object]) -> list[int]:
    ids: list[int] = []
    for value in values:
        if isinstance(value, str):
            candidate = value.strip()
            if not candidate:
                continue
            try:
                ids.append(int(candidate))
            except ValueError:
                continue
    return ids


@router.get("/users", response_class=HTMLResponse)
async def users_page(
    request: Request,
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(require_permission(USER_READ_PERMISSION)),
) -> HTMLResponse:
    result = await session.execute(select(User).options(selectinload(User.roles)))
    users: Sequence[User] = result.scalars().all()

    roles_result = await session.execute(select(Role))
    roles = roles_result.scalars().all()

    return templates.TemplateResponse(
        "users.html",
        {
            "request": request,
            "users": users,
            "roles": roles,
            "current_user": current_user,
        },
    )


@router.post("/users", response_class=Response)
async def create_user(
    request: Request,
    username: str = Form(...),
    email: str | None = Form(None),
    password: str = Form(...),
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(require_permission(USER_MANAGE_PERMISSION)),
) -> Response:
    new_user = User(username=username, email=email, hashed_password=hash_password(password))
    form = await request.form()
    role_ids = _parse_id_list(form.getlist("role_ids"))
    if role_ids:
        roles = await session.execute(select(Role).where(Role.id.in_(role_ids)))
        new_user.roles = list(roles.scalars())

    session.add(new_user)
    try:
        await session.commit()
    except IntegrityError as exc:
        await session.rollback()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username or email already exists") from exc

    return RedirectResponse(url="/admin/users", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/users/{user_id}/roles", response_class=Response)
async def assign_roles(
    request: Request,
    user_id: int,
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(require_permission(USER_MANAGE_PERMISSION)),
) -> Response:
    result = await session.execute(
        select(User).where(User.id == user_id).options(selectinload(User.roles))
    )
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    form = await request.form()
    role_ids = _parse_id_list(form.getlist("role_ids"))
    if role_ids:
        roles = await session.execute(select(Role).where(Role.id.in_(role_ids)))
        user.roles = list(roles.scalars())
    else:
        user.roles.clear()

    await session.commit()
    return RedirectResponse(url="/admin/users", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/roles", response_class=HTMLResponse)
async def roles_page(
    request: Request,
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(require_permission(ROLE_READ_PERMISSION)),
) -> HTMLResponse:
    result = await session.execute(select(Role).options(selectinload(Role.permissions)))
    roles = result.scalars().all()

    permissions_result = await session.execute(select(Permission))
    permissions = permissions_result.scalars().all()

    return templates.TemplateResponse(
        "roles.html",
        {
            "request": request,
            "roles": roles,
            "permissions": permissions,
            "current_user": current_user,
        },
    )


@router.post("/roles", response_class=Response)
async def create_role(
    name: str = Form(...),
    description: str | None = Form(None),
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(require_permission(ROLE_MANAGE_PERMISSION)),
) -> Response:
    role = Role(name=name, description=description)
    session.add(role)
    try:
        await session.commit()
    except IntegrityError as exc:
        await session.rollback()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Role already exists") from exc
    return RedirectResponse(url="/admin/roles", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/permissions", response_class=Response)
async def create_permission(
    name: str = Form(...),
    description: str | None = Form(None),
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(require_permission(ROLE_MANAGE_PERMISSION)),
) -> Response:
    permission = Permission(name=name, description=description)
    session.add(permission)
    try:
        await session.commit()
    except IntegrityError as exc:
        await session.rollback()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Permission already exists") from exc
    return RedirectResponse(url="/admin/roles", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/roles/{role_id}/permissions", response_class=Response)
async def update_role_permissions(
    request: Request,
    role_id: int,
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(require_permission(ROLE_MANAGE_PERMISSION)),
) -> Response:
    result = await session.execute(
        select(Role).where(Role.id == role_id).options(selectinload(Role.permissions))
    )
    role = result.scalar_one_or_none()
    if role is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Role not found")

    form = await request.form()
    permission_ids = _parse_id_list(form.getlist("permission_ids"))
    if permission_ids:
        permissions = await session.execute(
            select(Permission).where(Permission.id.in_(permission_ids))
        )
        role.permissions = list(permissions.scalars())
    else:
        role.permissions.clear()

    await session.commit()
    return RedirectResponse(url="/admin/roles", status_code=status.HTTP_303_SEE_OTHER)
