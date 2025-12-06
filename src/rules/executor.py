from __future__ import annotations

import asyncio
import logging
from contextlib import suppress
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import settings
from ..db import SessionLocal
from ..models import Alert, AuditLog, DetectionRule

logger = logging.getLogger(__name__)


class RuleExecutor:
    """Background task that evaluates detection rules at a fixed cadence."""

    def __init__(self, interval_seconds: int | None = None) -> None:
        self._interval = interval_seconds or settings.rule_eval_interval_seconds
        self._task: asyncio.Task[None] | None = None

    def start(self) -> None:
        if self._task is None or self._task.done():
            self._task = asyncio.create_task(self._run(), name="rule-executor")
            logger.info("Rule executor started (interval=%ss)", self._interval)

    async def stop(self) -> None:
        if self._task is None:
            return
        self._task.cancel()
        with suppress(asyncio.CancelledError):
            await self._task
        self._task = None
        logger.info("Rule executor stopped")

    async def _run(self) -> None:
        try:
            while True:
                try:
                    await self._evaluate_rules()
                except Exception:  # noqa: BLE001
                    logger.exception("Rule executor encountered an unexpected error")
                await asyncio.sleep(self._interval)
        except asyncio.CancelledError:
            raise

    async def _evaluate_rules(self) -> None:
        async with SessionLocal() as session:
            result = await session.execute(
                select(DetectionRule).where(DetectionRule.enabled.is_(True))
            )
            rules = result.scalars().all()
            if not rules:
                return

            for rule in rules:
                try:
                    await self._evaluate_rule(session, rule)
                except Exception:  # noqa: BLE001
                    logger.exception("Failed to evaluate rule %s", rule.name)

            await session.commit()

    async def _evaluate_rule(self, session: AsyncSession, rule: DetectionRule) -> None:
        now = datetime.now(tz=timezone.utc)
        window_start = now - timedelta(seconds=rule.window_seconds)

        config = dict(rule.config or {})
        group_by_field = config.pop("group_by", None)

        filters: list[Any] = [AuditLog.occurred_at >= window_start]
        filters.extend(self._build_filters(config))

        count_stmt = select(func.count()).select_from(AuditLog)
        if filters:
            count_stmt = count_stmt.where(and_(*filters))

        if group_by_field:
            await self._evaluate_grouped(session, filters, rule, now, window_start, group_by_field)
        else:
            await self._evaluate_total(session, count_stmt, rule, now, window_start)

    async def _evaluate_total(
        self,
        session: AsyncSession,
        stmt,
        rule: DetectionRule,
        now: datetime,
        window_start: datetime,
    ) -> None:
        count = (await session.execute(stmt)).scalar() or 0
        rule.last_evaluated_at = now

        if count < rule.threshold:
            return
        if rule.last_triggered_at and rule.last_triggered_at >= window_start:
            return

        alert = Alert(
            rule_name=rule.name,
            severity=rule.severity,
            details={
                "count": count,
                "threshold": rule.threshold,
                "window_seconds": rule.window_seconds,
                "config": rule.config,
            },
        )
        session.add(alert)
        rule.last_triggered_at = now
        logger.info(
            "Rule triggered: %s (count=%s threshold=%s window=%ss)",
            rule.name,
            count,
            rule.threshold,
            rule.window_seconds,
        )

    async def _evaluate_grouped(
        self,
        session: AsyncSession,
        filters: list[Any],
        rule: DetectionRule,
        now: datetime,
        window_start: datetime,
        group_by_field: str,
    ) -> None:
        column = self._resolve_column(group_by_field)
        if column is None:
            logger.warning("Unknown group_by field '%s' for rule %s", group_by_field, rule.name)
            return

        grouped_stmt = select(column.label("group_value"), func.count().label("count")).select_from(AuditLog)
        if filters:
            grouped_stmt = grouped_stmt.where(and_(*filters))
        grouped_stmt = grouped_stmt.group_by(column)

        result = await session.execute(grouped_stmt)
        violations: list[dict[str, Any]] = []
        for group_value, count in result.all():
            if count >= rule.threshold:
                violations.append({"value": group_value, "count": count})

        rule.last_evaluated_at = now
        if not violations:
            return
        if rule.last_triggered_at and rule.last_triggered_at >= window_start:
            return

        alert = Alert(
            rule_name=rule.name,
            severity=rule.severity,
            details={
                "threshold": rule.threshold,
                "window_seconds": rule.window_seconds,
                "config": rule.config,
                "group_by": group_by_field,
                "violations": violations,
            },
        )
        session.add(alert)
        rule.last_triggered_at = now
        logger.info(
            "Rule triggered: %s (violations=%s threshold=%s window=%ss)",
            rule.name,
            len(violations),
            rule.threshold,
            rule.window_seconds,
        )

    def _build_filters(self, config: dict[str, Any]):  # type: ignore[no-untyped-def]
        filters = []
        for field, condition in config.items():
            column = self._resolve_column(field)
            if column is None:
                continue
            expression = self._build_expression(column, condition)
            if expression is not None:
                filters.append(expression)
        return filters

    def _build_expression(self, column, condition):  # type: ignore[no-untyped-def]
        if isinstance(condition, (list, tuple, set)):
            expressions = [self._build_expression(column, value) for value in condition]
            expressions = [expr for expr in expressions if expr is not None]
            if expressions:
                return or_(*expressions)
            return None

        match_type = "exact"
        value = condition
        if isinstance(condition, dict):
            value = condition.get("value")
            match_type = condition.get("match", "exact").lower()

        if value is None:
            return column.is_(None)

        if isinstance(value, (int, float)):
            return column == value

        if not isinstance(value, str):
            return column == value

        if match_type == "regex" or value.startswith("regex:"):
            pattern = value.split("regex:", 1)[-1] if value.startswith("regex:") else value
            return column.op("~")(pattern)

        if match_type == "like":
            return column.ilike(self._wildcard_to_like(value))

        if match_type == "contains":
            return column.ilike(f"%{value}%")

        if match_type == "prefix":
            return column.ilike(f"{value}%")

        if match_type == "suffix":
            return column.ilike(f"%{value}")

        if "*" in value or "?" in value:
            return column.ilike(self._wildcard_to_like(value))

        return column == value

    @staticmethod
    def _wildcard_to_like(pattern: str) -> str:
        return pattern.replace("*", "%").replace("?", "_")

    @staticmethod
    def _resolve_column(field_name: str):  # type: ignore[no-untyped-def]
        mapping = {
            "action": AuditLog.action,
            "endpoint": AuditLog.endpoint,
            "outcome": AuditLog.outcome,
            "result": AuditLog.outcome,
            "role": AuditLog.role_name,
            "role_name": AuditLog.role_name,
            "user": AuditLog.user_name,
            "user_name": AuditLog.user_name,
            "status_code": AuditLog.status_code,
            "ip_address": AuditLog.ip_address,
        }
        return mapping.get(field_name)
