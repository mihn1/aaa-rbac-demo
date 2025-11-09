from datetime import datetime, timedelta, timezone
from pathlib import Path
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, ConfigDict
from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.constants.permissions import LOG_READ_PERMISSION

from ..db import get_session
from ..models import Alert, AuditLog, User
from ..rbac import require_permission

router = APIRouter()

template_dir = Path(__file__).resolve().parent.parent / "templates"
templates = Jinja2Templates(directory=str(template_dir))

class AuditLogRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    occurred_at: datetime
    user_name: str | None
    role_name: str | None
    ip_address: str | None
    endpoint: str | None
    action: str | None
    status_code: int | None
    outcome: str | None
    latency_ms: int | None


class AlertRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    rule_name: str
    severity: str
    detected_at: datetime
    acknowledged: bool
    details: dict


@router.get("/dashboard", response_class=HTMLResponse)
async def dashboard(
    request: Request,
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(require_permission(LOG_READ_PERMISSION)),
) -> HTMLResponse:
    stats = await _summaries(session)
    alerts_stmt = select(Alert).order_by(Alert.detected_at.desc()).limit(10)
    alerts_result = await session.execute(alerts_stmt)
    alerts = alerts_result.scalars().all()

    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "stats": stats,
            "alerts": alerts,
            "current_user": current_user,
        },
    )


@router.get("/events", response_model=list[AuditLogRead])
async def list_events(
    limit: int = 100,
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(require_permission(LOG_READ_PERMISSION)),
) -> list[AuditLogRead]:
    stmt = select(AuditLog).order_by(AuditLog.occurred_at.desc()).limit(limit)
    result = await session.execute(stmt)
    events = result.scalars().all()
    return [AuditLogRead.model_validate(event) for event in events]


@router.get("/alerts", response_model=list[AlertRead])
async def list_alerts(
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(require_permission(LOG_READ_PERMISSION)),
) -> list[AlertRead]:
    stmt = select(Alert).order_by(Alert.detected_at.desc())
    result = await session.execute(stmt)
    alerts = result.scalars().all()
    return [AlertRead.model_validate(alert) for alert in alerts]


@router.post("/alerts/{alert_id}/ack", response_model=AlertRead)
async def acknowledge_alert(
    alert_id: int,
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(require_permission(LOG_READ_PERMISSION)),
) -> AlertRead:
    stmt = select(Alert).where(Alert.id == alert_id)
    result = await session.execute(stmt)
    alert = result.scalar_one_or_none()
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert.acknowledged = True
    await session.commit()
    return AlertRead.model_validate(alert)


async def _summaries(session: AsyncSession) -> dict[str, int]:
    now = datetime.now(tz=timezone.utc)
    five_minutes_ago = now - timedelta(minutes=5)

    total_logins_stmt = select(func.count()).where(AuditLog.action == "login")
    failed_logins_stmt = select(func.count()).where(
        and_(AuditLog.action == "login", AuditLog.outcome == "failure")
    )
    recent_failed_stmt = select(func.count()).where(
        and_(
            AuditLog.action == "login",
            AuditLog.outcome == "failure",
            AuditLog.occurred_at >= five_minutes_ago,
        )
    )

    total_logins = (await session.execute(total_logins_stmt)).scalar() or 0
    failed_logins = (await session.execute(failed_logins_stmt)).scalar() or 0
    recent_failed = (await session.execute(recent_failed_stmt)).scalar() or 0

    return {
        "total_logins": total_logins,
        "failed_logins": failed_logins,
        "recent_failed_logins": recent_failed,
    }
