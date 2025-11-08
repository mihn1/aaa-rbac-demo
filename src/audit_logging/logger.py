from __future__ import annotations

from typing import Mapping

from .events import AAAEvent
from .sinks import LogSink, build_default_sink


class AAAEventLogger:
    def __init__(self, sink: LogSink | None = None) -> None:
        self._sink = sink or build_default_sink()

    async def emit(
        self,
        *,
        action: str,
        endpoint: str,
        status_code: int,
        result: str,
        user: str | None = None,
        role: str | None = None,
        ip_address: str | None = None,
        latency_ms: int | None = None,
        request_id: str | None = None,
        metadata: Mapping | None = None,
    ) -> None:
        event = AAAEvent.now(
            user=user,
            role=role,
            ip_address=ip_address,
            endpoint=endpoint,
            action=action,
            status_code=status_code,
            result=result,
            latency_ms=latency_ms,
            request_id=request_id,
            metadata=metadata,
        )
        await self._sink.write(event.to_payload())


default_event_logger = AAAEventLogger()
