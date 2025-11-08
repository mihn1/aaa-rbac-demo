from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping


@dataclass(slots=True)
class AAAEvent:
    """Structured representation of an AAA (authentication, authorization, accounting) log entry."""

    timestamp: datetime
    user: str | None
    role: str | None
    ip_address: str | None
    endpoint: str
    action: str
    status_code: int
    result: str
    latency_ms: int | None = None
    request_id: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def to_payload(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["timestamp"] = self.timestamp.astimezone(timezone.utc).isoformat()
        payload["metadata"] = dict(self.metadata)
        return payload

    @classmethod
    def now(
        cls,
        *,
        user: str | None,
        role: str | None,
        ip_address: str | None,
        endpoint: str,
        action: str,
        status_code: int,
        result: str,
        latency_ms: int | None = None,
        request_id: str | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> "AAAEvent":
        return cls(
            timestamp=datetime.now(tz=timezone.utc),
            user=user,
            role=role,
            ip_address=ip_address,
            endpoint=endpoint,
            action=action,
            status_code=status_code,
            result=result,
            latency_ms=latency_ms,
            request_id=request_id,
            metadata=metadata or {},
        )
