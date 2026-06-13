from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .models import Argument, Operation

DANGEROUS_TERMS = (
    "admin",
    "apikey",
    "api_key",
    "billing",
    "credential",
    "invite",
    "permission",
    "role",
    "secret",
    "token",
    "user",
    "workspace",
)

DESTRUCTIVE_TERMS = (
    "archive",
    "create",
    "delete",
    "disable",
    "grant",
    "invite",
    "remove",
    "reset",
    "revoke",
    "set",
    "terminate",
    "transfer",
    "update",
)

CRITICAL_TERMS = ("apikey", "api_key", "credential", "secret", "token")


def normalize_schema(payload: dict[str, Any]) -> dict[str, Any]:
    if "__schema" in payload:
        return payload["__schema"]
    data = payload.get("data")
    if isinstance(data, dict) and "__schema" in data:
        return data["__schema"]
    raise ValueError("File does not contain a GraphQL introspection __schema object")


def load_schema(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        return normalize_schema(json.load(handle))


def unwrap_type(type_ref: dict[str, Any]) -> tuple[str, str, bool]:
    required = type_ref.get("kind") == "NON_NULL"
    current = type_ref
    while current.get("ofType"):
        current = current["ofType"]
    return current.get("name") or "Unknown", current.get("kind") or "UNKNOWN", required


def _tokens(value: str) -> set[str]:
    snake = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", value).lower()
    return {part for part in re.split(r"[^a-z0-9_]+|_", snake) if part}


def _matched_terms(name: str) -> tuple[str, ...]:
    lowered = name.lower()
    tokens = _tokens(name)
    matches = []
    for term in DANGEROUS_TERMS:
        compact = term.replace("_", "")
        if term in lowered or compact in lowered or term in tokens:
            matches.append(term)
    return tuple(sorted(set(matches)))


def _sensitive_field_paths(
    type_name: str,
    types: dict[str, dict[str, Any]],
    prefix: str = "",
    depth: int = 0,
    visited: frozenset[str] = frozenset(),
) -> tuple[str, ...]:
    if depth >= 2 or type_name in visited:
        return ()
    paths: list[str] = []
    type_def = types.get(type_name, {})
    for field in type_def.get("fields") or []:
        path = f"{prefix}.{field['name']}" if prefix else field["name"]
        if _matched_terms(field["name"]):
            paths.append(path)
        child_name, child_kind, _ = unwrap_type(field["type"])
        if child_kind == "OBJECT":
            paths.extend(
                _sensitive_field_paths(
                    child_name,
                    types,
                    path,
                    depth + 1,
                    visited | {type_name},
                )
            )
    return tuple(sorted(set(paths)))


def assess_risk(
    kind: str,
    name: str,
    return_type: str,
    sensitive_paths: tuple[str, ...] = (),
) -> tuple[str, tuple[str, ...]]:
    haystack = f"{name} {return_type}"
    dangerous = tuple(
        sorted(
            set(_matched_terms(haystack)).union(
                term for path in sensitive_paths for term in _matched_terms(path)
            )
        )
    )
    name_tokens = _tokens(name)
    compact_name = name.lower().replace("_", "")
    destructive = tuple(term for term in DESTRUCTIVE_TERMS if term in name_tokens)
    critical_haystack = compact_name + "".join(sensitive_paths).lower().replace("_", "")
    critical = tuple(
        term for term in CRITICAL_TERMS if term.replace("_", "") in critical_haystack
    )
    reasons: list[str] = []

    if dangerous:
        reasons.append(f"sensitive terms: {', '.join(dangerous)}")
    if sensitive_paths:
        reasons.append(f"sensitive return fields: {', '.join(sensitive_paths)}")
    if destructive:
        reasons.append(f"state-changing action: {', '.join(destructive)}")

    if critical or (kind == "mutation" and dangerous and destructive):
        risk = "Critical"
    elif kind == "mutation" and (dangerous or destructive):
        risk = "High"
    elif dangerous:
        risk = "High"
    elif kind == "mutation":
        risk = "Medium"
    else:
        risk = "Low"
    return risk, tuple(reasons)


def analyze_schema(schema: dict[str, Any]) -> list[Operation]:
    types = {item["name"]: item for item in schema.get("types", []) if item.get("name")}
    roots = (
        ("query", schema.get("queryType")),
        ("mutation", schema.get("mutationType")),
        ("subscription", schema.get("subscriptionType")),
    )
    operations: list[Operation] = []

    for kind, root_ref in roots:
        if not root_ref or not root_ref.get("name"):
            continue
        root = types.get(root_ref["name"], {})
        for item in root.get("fields") or []:
            return_name, return_kind, _ = unwrap_type(item["type"])
            arguments = []
            for arg in item.get("args") or []:
                type_name, type_kind, required = unwrap_type(arg["type"])
                arguments.append(Argument(arg["name"], type_name, type_kind, required))
            sensitive_paths = _sensitive_field_paths(return_name, types)
            risk, reasons = assess_risk(kind, item["name"], return_name, sensitive_paths)
            operations.append(
                Operation(
                    name=item["name"],
                    kind=kind,
                    return_type=return_name,
                    return_kind=return_kind,
                    arguments=tuple(arguments),
                    dangerous_terms=tuple(
                        sorted(
                            set(_matched_terms(f"{item['name']} {return_name}")).union(
                                term
                                for path in sensitive_paths
                                for term in _matched_terms(path)
                            )
                        )
                    ),
                    risk=risk,
                    risk_reasons=reasons,
                )
            )
    risk_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    return sorted(operations, key=lambda op: (risk_order[op.risk], op.kind, op.name.lower()))


def schema_types(schema: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {item["name"]: item for item in schema.get("types", []) if item.get("name")}
