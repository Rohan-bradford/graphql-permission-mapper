from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

import yaml

from .models import Role, TestCase

ENV_PATTERN = re.compile(r"\$\{([A-Z_][A-Z0-9_]*)\}")


def _expand(value: Any) -> Any:
    if isinstance(value, str):
        return ENV_PATTERN.sub(lambda match: os.getenv(match.group(1), ""), value)
    if isinstance(value, dict):
        return {key: _expand(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_expand(item) for item in value]
    return value


def load_config(path: Path) -> tuple[str, list[Role], list[TestCase], dict[str, Any]]:
    with path.open(encoding="utf-8") as handle:
        raw = _expand(yaml.safe_load(handle) or {})
    endpoint = raw.get("endpoint")
    if not endpoint:
        raise ValueError("Config must define an endpoint")
    roles = [
        Role(
            name=item["name"],
            headers={str(k): str(v) for k, v in item.get("headers", {}).items()},
        )
        for item in raw.get("roles", [])
    ]
    tests = [
        TestCase(
            name=item["name"],
            query=item["query"],
            variables=item.get("variables") or {},
        )
        for item in raw.get("operations", [])
    ]
    if not roles:
        raise ValueError("Config must define at least one role")
    if not tests:
        raise ValueError("Config must define at least one operation")
    return endpoint, roles, tests, raw
