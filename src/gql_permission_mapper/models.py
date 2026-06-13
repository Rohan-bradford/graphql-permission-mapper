from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Argument:
    name: str
    type_name: str
    type_kind: str
    required: bool


@dataclass(frozen=True)
class Operation:
    name: str
    kind: str
    return_type: str
    return_kind: str
    arguments: tuple[Argument, ...] = ()
    dangerous_terms: tuple[str, ...] = ()
    risk: str = "Low"
    risk_reasons: tuple[str, ...] = ()


@dataclass(frozen=True)
class GeneratedQuery:
    operation: str
    kind: str
    document: str
    variables: dict[str, Any]
    executable: bool
    warning: str | None = None


@dataclass(frozen=True)
class Role:
    name: str
    headers: dict[str, str]


@dataclass(frozen=True)
class TestCase:
    name: str
    query: str
    variables: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class RoleResult:
    role: str
    operation: str
    status: int
    fields: tuple[str, ...]
    errors: tuple[str, ...]
    elapsed_ms: int


@dataclass(frozen=True)
class MatrixRow:
    operation: str
    role_statuses: dict[str, int]
    role_fields: dict[str, tuple[str, ...]]
    risk: str
    findings: tuple[str, ...]

