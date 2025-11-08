from __future__ import annotations

import asyncio
import json
from datetime import datetime
from pathlib import Path
from typing import Iterable, Protocol

import asyncpg

from ..config import settings


class LogSink(Protocol):
    async def write(self, payload: dict) -> None: ...


class FileLogSink:
    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self._lock = asyncio.Lock()
        self._path.parent.mkdir(parents=True, exist_ok=True)

    async def write(self, payload: dict) -> None:
        line = json.dumps(payload, ensure_ascii=True)
        async with self._lock:
            await asyncio.to_thread(self._append_line, line)

    def _append_line(self, line: str) -> None:
        with self._path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")


class PostgresLogSink:
    def __init__(self, dsn: str) -> None:
        self._dsn = dsn
        self._pool: asyncpg.Pool | None = None
        self._pool_lock = asyncio.Lock()

    async def _get_pool(self) -> asyncpg.Pool:
        if self._pool is None:
            async with self._pool_lock:
                if self._pool is None:
                    self._pool = await asyncpg.create_pool(self._dsn)
        return self._pool

    async def write(self, payload: dict) -> None:
        pool = await self._get_pool()
        occurred_at = datetime.fromisoformat(payload["timestamp"])
        async with pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO audit_logs (
                    occurred_at,
                    request_id,
                    user_name,
                    role_name,
                    ip_address,
                    endpoint,
                    action,
                    status_code,
                    outcome,
                    latency_ms,
                    extra
                ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
                """,
                occurred_at,
                payload.get("request_id"),
                payload.get("user"),
                payload.get("role"),
                payload.get("ip_address"),
                payload.get("endpoint"),
                payload.get("action"),
                payload.get("status_code"),
                payload.get("result"),
                payload.get("latency_ms"),
                json.dumps(payload.get("metadata", {})),
            )


class CompositeLogSink:
    def __init__(self, sinks: Iterable[LogSink]) -> None:
        self._sinks = tuple(sinks)

    async def write(self, payload: dict) -> None:
        if not self._sinks:
            return
        await asyncio.gather(*(sink.write(payload) for sink in self._sinks))


def build_default_sink() -> LogSink:
    sinks: list[LogSink] = []
    if settings.log_to_file:
        sinks.append(FileLogSink(settings.log_file_path))
    if settings.log_to_database:
        dsn = settings.database_url.replace("+asyncpg", "")
        sinks.append(PostgresLogSink(dsn))
    return CompositeLogSink(sinks)
