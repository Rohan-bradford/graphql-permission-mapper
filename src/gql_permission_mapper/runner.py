from __future__ import annotations

import asyncio
import time
from typing import Any

import httpx

from .models import Role, RoleResult, TestCase


def flatten_fields(value: Any, prefix: str = "") -> set[str]:
    fields: set[str] = set()
    if isinstance(value, dict):
        for key, child in value.items():
            path = f"{prefix}.{key}" if prefix else key
            fields.add(path)
            fields.update(flatten_fields(child, path))
    elif isinstance(value, list):
        for child in value[:3]:
            fields.update(flatten_fields(child, prefix))
    return fields


async def _run_one(
    client: httpx.AsyncClient,
    endpoint: str,
    role: Role,
    test: TestCase,
) -> RoleResult:
    started = time.perf_counter()
    try:
        response = await client.post(
            endpoint,
            headers=role.headers,
            json={"query": test.query, "variables": test.variables},
        )
        elapsed = round((time.perf_counter() - started) * 1000)
        try:
            payload = response.json()
        except ValueError:
            payload = {}
        errors = tuple(
            str(item.get("message", item)) if isinstance(item, dict) else str(item)
            for item in payload.get("errors", [])
        )
        fields = tuple(sorted(flatten_fields(payload.get("data"))))
        return RoleResult(role.name, test.name, response.status_code, fields, errors, elapsed)
    except httpx.RequestError as exc:
        elapsed = round((time.perf_counter() - started) * 1000)
        return RoleResult(role.name, test.name, 0, (), (str(exc),), elapsed)


async def run_matrix(
    endpoint: str,
    roles: list[Role],
    tests: list[TestCase],
    timeout: float = 15.0,
    verify_tls: bool = True,
) -> list[RoleResult]:
    limits = httpx.Limits(max_connections=max(10, len(roles) * 2))
    async with httpx.AsyncClient(timeout=timeout, verify=verify_tls, limits=limits) as client:
        tasks = [_run_one(client, endpoint, role, test) for test in tests for role in roles]
        return list(await asyncio.gather(*tasks))

