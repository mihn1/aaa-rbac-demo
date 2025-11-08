from __future__ import annotations

import time
from typing import Any
from uuid import uuid4

from fastapi import Request, Response, status
from starlette.middleware.base import BaseHTTPMiddleware

from .events import AAAEvent
from .sinks import LogSink, build_default_sink


class LoggingMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, *, sink: LogSink | None = None) -> None:
        super().__init__(app)
        self._sink = sink or build_default_sink()

    async def dispatch(self, request: Request, call_next) -> Response:
        start = time.perf_counter()
        request_id = request.headers.get("x-request-id") or str(uuid4())
        try:
            response = await call_next(request)
        except Exception:
            latency_ms = int((time.perf_counter() - start) * 1000)
            await self._log_event(
                request,
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                result="error",
                latency_ms=latency_ms,
                request_id=request_id,
            )
            raise

        latency_ms = int((time.perf_counter() - start) * 1000)
        outcome = "success" if response.status_code < 400 else "failure"
        await self._log_event(
            request,
            status_code=response.status_code,
            result=outcome,
            latency_ms=latency_ms,
            request_id=request_id,
        )
        response.headers.setdefault("x-request-id", request_id)
        return response

    async def _log_event(
        self,
        request: Request,
        *,
        status_code: int,
        result: str,
        latency_ms: int,
        request_id: str,
    ) -> None:
        current_user = getattr(request.state, "current_user", None)
        role_name = None
        if current_user and getattr(current_user, "roles", None):
            role_name = ",".join(sorted(role.name for role in current_user.roles))

        client_host = request.client.host if request.client else None
        event = AAAEvent.now(
            user=getattr(current_user, "username", None),
            role=role_name,
            ip_address=client_host,
            endpoint=request.url.path,
            action=request.method,
            status_code=status_code,
            result=result,
            latency_ms=latency_ms,
            request_id=request_id,
            metadata={
                "query": str(request.url.query) if request.url.query else None,
                "user_agent": request.headers.get("user-agent"),
            },
        )
        await self._sink.write(event.to_payload())
