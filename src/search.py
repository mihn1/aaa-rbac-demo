from __future__ import annotations

import logging

import httpx

from .config import settings

logger = logging.getLogger(__name__)


async def ensure_elasticsearch_index() -> None:
    """Ensure the configured Elasticsearch index exists with basic mappings."""

    if not settings.log_to_elasticsearch:
        return

    base_url = settings.elasticsearch_url.rstrip("/")
    index = settings.elasticsearch_index
    mapping = {
        "mappings": {
            "properties": {
                "timestamp": {"type": "date"},
                "user": {"type": "keyword"},
                "role": {"type": "keyword"},
                "ip_address": {"type": "ip"},
                "endpoint": {"type": "keyword"},
                "action": {"type": "keyword"},
                "status_code": {"type": "integer"},
                "result": {"type": "keyword"},
                "latency_ms": {"type": "integer"},
                "request_id": {"type": "keyword"},
                "metadata": {"type": "object", "enabled": True},
            }
        }
    }

    async with httpx.AsyncClient(timeout=10) as client:
        try:
            head_response = await client.head(f"{base_url}/{index}")
        except httpx.HTTPError as exc:
            logger.error("Unable to reach Elasticsearch at %s: %s", base_url, exc)
            return

        if head_response.status_code == 200:
            return

        if head_response.status_code not in {404, 400}:  # 400 when index missing with security disabled
            logger.warning(
                "Unexpected status when checking index %s: %s %s",
                index,
                head_response.status_code,
                head_response.text,
            )

        try:
            create_response = await client.put(f"{base_url}/{index}", json=mapping)
        except httpx.HTTPError as exc:
            logger.error("Failed to create Elasticsearch index %s: %s", index, exc)
            return

        if create_response.status_code >= 300:
            logger.error(
                "Elasticsearch index creation failed (%s): %s",
                create_response.status_code,
                create_response.text,
            )
        else:
            logger.info("Created Elasticsearch index %s", index)
