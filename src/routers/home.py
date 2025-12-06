from pathlib import Path
from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from ..constants.roles import ADMIN_ROLE
from ..models import User
from ..security import get_current_user

router = APIRouter()

template_dir = Path(__file__).resolve().parent.parent / "templates"
templates = Jinja2Templates(directory=str(template_dir))


@router.get("/home", response_class=HTMLResponse)
async def home(
    request: Request,
    current_user: User = Depends(get_current_user),
) -> HTMLResponse:
    show_rule_link = False
    if current_user and getattr(current_user, "roles", None):
        admin_name = ADMIN_ROLE.lower()
        show_rule_link = any((role.name or "").lower() == admin_name for role in current_user.roles)

    return templates.TemplateResponse(
        "home.html",
        {
            "request": request,
            "current_user": current_user,
            "show_rule_link": show_rule_link,
        },
    )
