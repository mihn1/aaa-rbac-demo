#!/usr/bin/env python3
"""Synthetic traffic generator for the AAA RBAC demo."""

from __future__ import annotations

import argparse
import asyncio
import random
from typing import Awaitable, Callable, Iterable, Sequence

import httpx

DEFAULT_BASE_URL = "http://localhost:8080"


async def login_api(client: httpx.AsyncClient, base_url: str, username: str, password: str) -> str | None:
    response = await client.post(
        f"{base_url}/auth/login",
        data={"username": username, "password": password},
        timeout=10,
    )
    if response.status_code != 200:
        return None
    payload = response.json()
    return payload.get("access_token")


def auth_headers(token: str | None) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"} if token else {}


async def _run_failed_login_pattern(
    client: httpx.AsyncClient,
    base_url: str,
    usernames: Sequence[str],
    attempts: int,
    delay: float = 0.1,
) -> None:
    if not usernames:
        return
    for idx in range(attempts):
        username = usernames[idx % len(usernames)]
        await client.post(
            f"{base_url}/auth/login",
            data={"username": username, "password": "wrong-password"},
            timeout=10,
        )
        await asyncio.sleep(delay)


async def scenario_benign(client: httpx.AsyncClient, base_url: str, iterations: int) -> None:
    token = await login_api(client, base_url, "admin", "admin")
    if not token:
        return
    for _ in range(iterations):
        await client.get(f"{base_url}/logs/events?limit=10", headers=auth_headers(token))
        await asyncio.sleep(random.uniform(0.2, 0.6))


async def scenario_bruteforce(client: httpx.AsyncClient, base_url: str, attempts: int) -> None:
    await _run_failed_login_pattern(client, base_url, ["admin"], attempts)


async def scenario_user_spike(client: httpx.AsyncClient, base_url: str, attempts: int) -> None:
    await _run_failed_login_pattern(client, base_url, ["user"], attempts)


async def scenario_ip_rotation(client: httpx.AsyncClient, base_url: str, attempts: int) -> None:
    spray_users = [
        "alpha",
        "bravo",
        "charlie",
        "delta",
        "echo",
        "foxtrot",
        "ghost",
    ]
    await _run_failed_login_pattern(client, base_url, spray_users, attempts, delay=0.05)


async def scenario_forbidden(client: httpx.AsyncClient, base_url: str, iterations: int) -> None:
    token = await login_api(client, base_url, "user", "user")
    if not token:
        return

    headers = auth_headers(token)
    for attempt in range(iterations):
        username = f"blocked-{attempt}"
        await client.post(
            f"{base_url}/admin/users",
            headers=headers,
            data={
                "username": username,
                "email": f"{username}@example.com",
                "password": "Temp123!",
            },
            timeout=10,
        )
        await client.post(
            f"{base_url}/admin/roles",
            headers=headers,
            data={
                "name": f"forbidden-{attempt}",
                "description": "auto-generated",
            },
            timeout=10,
        )
        await asyncio.sleep(0.2)


async def scenario_admin_probe(client: httpx.AsyncClient, base_url: str, iterations: int) -> None:
    await scenario_forbidden(client, base_url, iterations)


SCENARIOS: dict[str, Callable[[httpx.AsyncClient, str, int], Awaitable[None]]] = {
    "benign": scenario_benign,
    "bruteforce": scenario_bruteforce,
    "user_spike": scenario_user_spike,
    "ip_rotation": scenario_ip_rotation,
    "forbidden": scenario_forbidden,
    "admin_probe": scenario_admin_probe,
}


async def run_selected_scenarios(scenarios: Iterable[str], base_url: str, count: int) -> None:
    async with httpx.AsyncClient(follow_redirects=True) as client:
        for name in scenarios:
            handler = SCENARIOS.get(name)
            if handler is None:
                continue
            await handler(client, base_url, count)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="AAA RBAC synthetic traffic generator")
    parser.add_argument(
        "--base-url",
        default=DEFAULT_BASE_URL,
        help="Base URL for the FastAPI service (default: %(default)s)",
    )
    parser.add_argument(
        "--scenario",
        choices=sorted(SCENARIOS.keys()) + ["all"],
        default="all",
        help="Scenario to execute",
    )
    parser.add_argument(
        "--count",
        type=int,
        default=10,
        help="Iterations per scenario (default: %(default)s)",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    scenarios = SCENARIOS.keys() if args.scenario == "all" else [args.scenario]
    asyncio.run(run_selected_scenarios(scenarios, args.base_url.rstrip("/"), args.count))


if __name__ == "__main__":
    main()
