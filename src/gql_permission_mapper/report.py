from __future__ import annotations

import csv
import json
from pathlib import Path

from .models import MatrixRow, Operation, RoleResult

RISK_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Unknown": 4}


def build_matrix(
    results: list[RoleResult], operations: dict[str, Operation], role_names: list[str]
) -> list[MatrixRow]:
    grouped: dict[str, list[RoleResult]] = {}
    for result in results:
        grouped.setdefault(result.operation, []).append(result)

    rows = []
    for name, items in grouped.items():
        by_role = {item.role: item for item in items}
        statuses = {role: by_role[role].status if role in by_role else 0 for role in role_names}
        fields = {role: by_role[role].fields if role in by_role else () for role in role_names}
        findings: list[str] = []
        successful = [role for role, status in statuses.items() if 200 <= status < 300]
        if successful and len(successful) == len(role_names):
            findings.append("accessible to every tested role")
        field_sets = {role: set(value) for role, value in fields.items()}
        if len({frozenset(value) for value in field_sets.values()}) > 1:
            findings.append("returned fields differ by role")
        errors = [error for item in items for error in item.errors]
        if errors:
            findings.append(f"{len(errors)} GraphQL error(s)")
        operation = operations.get(name)
        rows.append(
            MatrixRow(
                operation=name,
                role_statuses=statuses,
                role_fields=fields,
                risk=operation.risk if operation else "Unknown",
                findings=tuple(findings),
            )
        )
    return sorted(rows, key=lambda row: (RISK_ORDER[row.risk], row.operation.lower()))


def _status_label(status: int) -> str:
    return str(status) if status else "ERR"


def markdown_report(rows: list[MatrixRow], role_names: list[str]) -> str:
    headers = ["Operation", *role_names, "Risk", "Findings"]
    divider = ["---"] * len(headers)
    lines = [
        "# GraphQL Permission Matrix",
        "",
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join(divider) + " |",
    ]
    for row in rows:
        values = [
            f"`{row.operation}`",
            *[_status_label(row.role_statuses[role]) for role in role_names],
            f"**{row.risk}**",
            "; ".join(row.findings) or "-",
        ]
        lines.append("| " + " | ".join(values) + " |")
    lines.extend(["", "> Run only against systems you own or are authorized to test.", ""])
    return "\n".join(lines)


def write_reports(rows: list[MatrixRow], role_names: list[str], output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "permission-matrix.md").write_text(
        markdown_report(rows, role_names), encoding="utf-8"
    )
    serializable = [
        {
            "operation": row.operation,
            "statuses": row.role_statuses,
            "fields": {key: list(value) for key, value in row.role_fields.items()},
            "risk": row.risk,
            "findings": list(row.findings),
        }
        for row in rows
    ]
    (output_dir / "permission-matrix.json").write_text(
        json.dumps(serializable, indent=2) + "\n", encoding="utf-8"
    )
    with (output_dir / "permission-matrix.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["Operation", *role_names, "Risk", "Findings"])
        for row in rows:
            writer.writerow(
                [
                    row.operation,
                    *[_status_label(row.role_statuses[role]) for role in role_names],
                    row.risk,
                    "; ".join(row.findings),
                ]
            )

