import asyncio
import json
from datetime import datetime
import logging
from pathlib import Path
from typing import Iterable, Protocol

import asyncpg
import httpx

from ..config import settings

logger = logging.getLogger(__name__)

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

    async def _get_pool(self) -> asyncpg.Pool | None:
        if self._pool is None:
            async with self._pool_lock:
                if self._pool is None:
                    self._pool = await asyncpg.create_pool(self._dsn)
        return self._pool

    async def write(self, payload: dict) -> None:
        pool = await self._get_pool()
        if pool is None:
            logger.error("PostgresLogSink: unable to acquire connection pool")
            return
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


class ElasticsearchLogSink:
    def __init__(self, base_url: str, index: str) -> None:
        self._base_url = base_url.rstrip("/")
        self._index = index
        self._client: httpx.AsyncClient | None = None
        self._client_lock = asyncio.Lock()

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            async with self._client_lock:
                if self._client is None:
                    self._client = httpx.AsyncClient(base_url=self._base_url, timeout=10)
        return self._client

    async def write(self, payload: dict) -> None:
        client = await self._get_client()
        try:
            response = await client.post(f"/{self._index}/_doc", json=payload)
            if response.status_code >= 300:
                logger.error(
                    "ElasticsearchLogSink write failed: status=%s body=%s",
                    response.status_code,
                    response.text,
                )
        except httpx.HTTPError as exc:
            logger.error("ElasticsearchLogSink write error: %s", exc)


def get_default_sink() -> LogSink:
    sinks: list[LogSink] = []
    if settings.log_to_file:
        sinks.append(FileLogSink(settings.log_file_path))
    if settings.log_to_database:
        dsn = settings.database_url.replace("+asyncpg", "")
        sinks.append(PostgresLogSink(dsn))
    if settings.log_to_elasticsearch:
        sinks.append(
            ElasticsearchLogSink(
                base_url=settings.elasticsearch_url,
                index=settings.elasticsearch_index,
            )
        )
    return CompositeLogSink(sinks)
