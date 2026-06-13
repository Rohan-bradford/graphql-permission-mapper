from __future__ import annotations

from typing import Any

from .models import GeneratedQuery, Operation
from .schema import schema_types, unwrap_type

SCALAR_DEFAULTS: dict[str, Any] = {
    "Boolean": False,
    "Float": 0.0,
    "ID": "REPLACE_ME",
    "Int": 0,
    "String": "REPLACE_ME",
}


def _selection(type_name: str, types: dict[str, dict[str, Any]], depth: int = 0) -> str:
    if depth >= 2:
        return "__typename"
    type_def = types.get(type_name, {})
    if type_def.get("kind") in {"SCALAR", "ENUM"}:
        return ""
    fields = []
    for field in type_def.get("fields") or []:
        if field.get("args"):
            continue
        child_name, child_kind, _ = unwrap_type(field["type"])
        if child_kind in {"SCALAR", "ENUM"}:
            fields.append(field["name"])
        elif len(fields) < 4:
            child = _selection(child_name, types, depth + 1)
            fields.append(f"{field['name']} {{ {child} }}")
        if len(fields) >= 6:
            break
    return " ".join(fields) if fields else "__typename"


def _sample_value(type_name: str, types: dict[str, dict[str, Any]], depth: int = 0) -> Any:
    if type_name in SCALAR_DEFAULTS:
        return SCALAR_DEFAULTS[type_name]
    type_def = types.get(type_name, {})
    if type_def.get("kind") == "ENUM":
        values = type_def.get("enumValues") or []
        return values[0]["name"] if values else "REPLACE_ME"
    if type_def.get("kind") == "INPUT_OBJECT" and depth < 2:
        result = {}
        for field in type_def.get("inputFields") or []:
            child_name, _, required = unwrap_type(field["type"])
            if required:
                result[field["name"]] = _sample_value(child_name, types, depth + 1)
        return result
    return "REPLACE_ME"


def _type_signature(type_ref: dict[str, Any]) -> str:
    kind = type_ref.get("kind")
    if kind == "NON_NULL":
        return f"{_type_signature(type_ref['ofType'])}!"
    if kind == "LIST":
        return f"[{_type_signature(type_ref['ofType'])}]"
    return type_ref.get("name") or "String"


def generate_query(
    operation: Operation, schema: dict[str, Any], include_mutations: bool = False
) -> GeneratedQuery:
    types = schema_types(schema)
    root_name = schema.get(f"{operation.kind}Type", {}).get("name")
    root = types.get(root_name, {})
    field = next(item for item in root.get("fields") or [] if item["name"] == operation.name)

    definitions = []
    calls = []
    variables: dict[str, Any] = {}
    for arg in field.get("args") or []:
        definitions.append(f"${arg['name']}: {_type_signature(arg['type'])}")
        calls.append(f"{arg['name']}: ${arg['name']}")
        type_name, _, required = unwrap_type(arg["type"])
        if required:
            variables[arg["name"]] = _sample_value(type_name, types)

    definition_text = f"({', '.join(definitions)})" if definitions else ""
    call_text = f"({', '.join(calls)})" if calls else ""
    selection = _selection(operation.return_type, types)
    selection_text = f" {{ {selection} }}" if selection else ""
    operation_name = f"PermissionMap{operation.name[0].upper()}{operation.name[1:]}"
    document = (
        f"{operation.kind} {operation_name}{definition_text} {{\n"
        f"  {operation.name}{call_text}{selection_text}\n"
        "}"
    )
    is_mutation = operation.kind == "mutation"
    return GeneratedQuery(
        operation=operation.name,
        kind=operation.kind,
        document=document,
        variables=variables,
        executable=not is_mutation or include_mutations,
        warning=(
            "Mutation template only. Review variables and side effects before execution."
            if is_mutation
            else None
        ),
    )

