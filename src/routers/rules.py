from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, Form, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..constants.permissions import RULE_MANAGE_PERMISSION
from ..db import get_session
from ..models import DetectionRule, User
from ..rbac import require_permission


router = APIRouter()

template_dir = Path(__file__).resolve().parent.parent / "templates"
templates = Jinja2Templates(directory=str(template_dir))


def _parse_int(value: str, default: int) -> int:
	try:
		return int(value)
	except (TypeError, ValueError):
		return default


def _parse_json(value: str | None) -> dict[str, Any]:
	if not value:
		return {}
	try:
		parsed = json.loads(value)
	except json.JSONDecodeError:
		return {}
	return parsed if isinstance(parsed, dict) else {}


@router.get("/rules", response_class=HTMLResponse)
async def rules_page(
	request: Request,
	session: AsyncSession = Depends(get_session),
	current_user: User = Depends(require_permission(RULE_MANAGE_PERMISSION)),
) -> HTMLResponse:
	result = await session.execute(select(DetectionRule).order_by(DetectionRule.id))
	rules = result.scalars().all()
	return templates.TemplateResponse(
		"rules.html",
		{
			"request": request,
			"rules": rules,
			"current_user": current_user,
		},
	)


@router.post("/rules", response_class=Response)
async def create_rule(
	name: str = Form(...),
	rule_type: str = Form(...),
	threshold: str = Form("5"),
	window_seconds: str = Form("300"),
	severity: str = Form("medium"),
	description: str | None = Form(None),
	config_json: str | None = Form(None),
	session: AsyncSession = Depends(get_session),
	current_user: User = Depends(require_permission(RULE_MANAGE_PERMISSION)),
) -> Response:
	rule = DetectionRule(
		name=name.strip(),
		description=description,
		rule_type=rule_type.strip() or "custom",
		threshold=_parse_int(threshold, 5),
		window_seconds=_parse_int(window_seconds, 300),
		severity=severity or "medium",
		config=_parse_json(config_json),
	)

	session.add(rule)
	try:
		await session.commit()
	except Exception as exc:  # noqa: BLE001
		await session.rollback()
		raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Unable to create rule") from exc

	return RedirectResponse(url="/admin/rules", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/rules/{rule_id}/update", response_class=Response)
async def update_rule(
	rule_id: int,
	threshold: str = Form(...),
	window_seconds: str = Form(...),
	severity: str = Form(...),
	description: str | None = Form(None),
	config_json: str | None = Form(None),
	session: AsyncSession = Depends(get_session),
	current_user: User = Depends(require_permission(RULE_MANAGE_PERMISSION)),
) -> Response:
	result = await session.execute(select(DetectionRule).where(DetectionRule.id == rule_id))
	rule = result.scalar_one_or_none()
	if rule is None:
		raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rule not found")

	rule.threshold = _parse_int(threshold, rule.threshold)
	rule.window_seconds = _parse_int(window_seconds, rule.window_seconds)
	rule.severity = severity or rule.severity
	rule.description = description or rule.description
	new_config = _parse_json(config_json)
	if new_config:
		rule.config = new_config

	await session.commit()
	return RedirectResponse(url="/admin/rules", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/rules/{rule_id}/toggle", response_class=Response)
async def toggle_rule(
	rule_id: int,
	session: AsyncSession = Depends(get_session),
	current_user: User = Depends(require_permission(RULE_MANAGE_PERMISSION)),
) -> Response:
	result = await session.execute(select(DetectionRule).where(DetectionRule.id == rule_id))
	rule = result.scalar_one_or_none()
	if rule is None:
		raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rule not found")

	rule.enabled = not rule.enabled
	await session.commit()
	return RedirectResponse(url="/admin/rules", status_code=status.HTTP_303_SEE_OTHER)
