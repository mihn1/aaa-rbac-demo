from pathlib import Path
from fastapi import APIRouter, Depends, Form, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, ConfigDict
from sqlalchemy.ext.asyncio import AsyncSession

from ..audit_logging import default_event_logger
from ..config import settings
from ..db import get_session
from ..models import User
from ..security import (
    TokenPair,
    authenticate_user,
    generate_token_pair,
    get_current_user,
    get_user_by_refresh_token,
)

router = APIRouter()

template_dir = Path(__file__).resolve().parent.parent / "templates"
templates = Jinja2Templates(directory=str(template_dir))


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


@router.get("/login-ui")
async def login_page(request: Request) -> Response:
    if request.cookies.get("access_token"):
        return RedirectResponse(url="/home", status_code=status.HTTP_303_SEE_OTHER)
    return templates.TemplateResponse("login.html", {"request": request, "current_user": None})


@router.post("/login-ui")
async def login_ui(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    session: AsyncSession = Depends(get_session),
) -> Response:
    user = await authenticate_user(session, username, password)
    if user is None:
        return templates.TemplateResponse(
            "login.html",
            {
                "request": request,
                "error": "Invalid username or password",
                "current_user": None,
            },
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    tokens = await generate_token_pair(user)
    user_roles = [role.name for role in user.roles]

    await default_event_logger.emit(
        action="login",
        endpoint="/auth/login-ui",
        status_code=status.HTTP_200_OK,
        result="success",
        user=user.username,
        role=",".join(user_roles) or None,
    )

    response = RedirectResponse(url="/home", status_code=status.HTTP_303_SEE_OTHER)
    secure_cookie = settings.environment.lower() == "production"
    response.set_cookie(
        "access_token",
        tokens.access_token,
        max_age=settings.access_token_expire_minutes * 60,
        httponly=True,
        secure=secure_cookie,
        samesite="lax",
        path="/",
    )
    response.set_cookie(
        "refresh_token",
        tokens.refresh_token,
        max_age=settings.refresh_token_expire_minutes * 60,
        httponly=True,
        secure=secure_cookie,
        samesite="lax",
        path="/",
    )
    return response


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


@router.get("/logout-ui")
async def logout_ui(current_user: User = Depends(get_current_user)) -> Response:
    roles = ",".join(role.name for role in current_user.roles) or None
    await default_event_logger.emit(
        action="logout",
        endpoint="/auth/logout-ui",
        status_code=status.HTTP_200_OK,
        result="success",
        user=current_user.username,
        role=roles,
    )
    response = RedirectResponse(url="/auth/login-ui", status_code=status.HTTP_303_SEE_OTHER)
    response.delete_cookie("access_token", path="/")
    response.delete_cookie("refresh_token", path="/")
    return response


@router.get("/me", response_model=UserRead)
async def me(current_user: User = Depends(get_current_user)) -> UserRead:
    return UserRead(
        id=current_user.id,
        username=current_user.username,
        email=current_user.email,
        roles=[role.name for role in current_user.roles],
    )
