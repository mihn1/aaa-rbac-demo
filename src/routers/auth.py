from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Response, status
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, ConfigDict
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import get_session
from ..audit_logging import default_event_logger
from ..models import User
from ..security import (
    TokenPair,
    authenticate_user,
    generate_token_pair,
    get_current_user,
    get_user_by_refresh_token,
)

router = APIRouter()


class UserRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    email: str | None = None
    roles: list[str]


class LoginResponse(BaseModel):
    token_type: str
    access_token: str
    refresh_token: str
    user: UserRead


class RefreshRequest(BaseModel):
    refresh_token: str


@router.post("/login", response_model=LoginResponse)
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    session: AsyncSession = Depends(get_session),
) -> LoginResponse:
    user = await authenticate_user(session, form_data.username, form_data.password)
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    tokens = await generate_token_pair(user)
    user_roles = [role.name for role in user.roles]

    await default_event_logger.emit(
        action="login",
        endpoint="/auth/login",
        status_code=status.HTTP_200_OK,
        result="success",
        user=user.username,
        role=",".join(user_roles) or None,
    )

    return LoginResponse(
        token_type=tokens.token_type,
        access_token=tokens.access_token,
        refresh_token=tokens.refresh_token,
        user=UserRead(id=user.id, username=user.username, email=user.email, roles=user_roles),
    )


@router.post("/refresh", response_model=TokenPair)
async def refresh(
    payload: RefreshRequest,
    session: AsyncSession = Depends(get_session),
) -> TokenPair:
    user = await get_user_by_refresh_token(payload.refresh_token, session)
    return await generate_token_pair(user)


@router.post("/logout", status_code=status.HTTP_200_OK)
async def logout(current_user: User = Depends(get_current_user)) -> dict[str, str]:
    roles = ",".join(role.name for role in current_user.roles) or None
    await default_event_logger.emit(
        action="logout",
        endpoint="/auth/logout",
        status_code=status.HTTP_200_OK,
        result="success",
        user=current_user.username,
        role=roles,
    )
    return {"detail": "logged out"}


@router.get("/me", response_model=UserRead)
async def me(current_user: User = Depends(get_current_user)) -> UserRead:
    return UserRead(
        id=current_user.id,
        username=current_user.username,
        email=current_user.email,
        roles=[role.name for role in current_user.roles],
    )
