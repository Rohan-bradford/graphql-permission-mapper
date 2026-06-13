from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Annotated

import httpx
import typer
from rich.console import Console
from rich.table import Table

from .config import load_config
from .generator import generate_query
from .report import build_matrix, write_reports
from .runner import run_matrix
from .schema import analyze_schema, load_schema, normalize_schema

app = typer.Typer(
    name="gql-permission-map",
    help="Analyze GraphQL schemas and compare authorization behavior across roles.",
    no_args_is_help=True,
)
console = Console()


def _display_operations(operations) -> None:
    table = Table(title="GraphQL Operation Risk Map")
    table.add_column("Operation")
    table.add_column("Type")
    table.add_column("Returns")
    table.add_column("Risk")
    table.add_column("Reason")
    for operation in operations:
        table.add_row(
            operation.name,
            operation.kind,
            operation.return_type,
            operation.risk,
            "; ".join(operation.risk_reasons) or "-",
        )
    console.print(table)


@app.command()
def fetch_schema(
    endpoint: Annotated[str, typer.Option(help="GraphQL HTTP endpoint")],
    output: Annotated[Path, typer.Option("-o", help="Output introspection JSON")] = Path(
        "schema.json"
    ),
    header: Annotated[
        list[str] | None,
        typer.Option("--header", "-H", help="HTTP header, e.g. 'Authorization: Bearer x'"),
    ] = None,
    timeout: Annotated[float, typer.Option(help="Request timeout in seconds")] = 15.0,
) -> None:
    """Fetch a standard introspection schema from an authorized endpoint."""
    headers = {}
    for item in header or []:
        if ":" not in item:
            raise typer.BadParameter("Headers must use 'Name: value' format")
        key, value = item.split(":", 1)
        headers[key.strip()] = value.strip()
    query = """
    query IntrospectionQuery {
      __schema {
        queryType { name }
        mutationType { name }
        subscriptionType { name }
        types {
          kind
          name
          fields(includeDeprecated: true) {
            name
            args {
              name
              type {
                kind name
                ofType { kind name ofType { kind name ofType { kind name } } }
              }
            }
            type {
              kind name
              ofType { kind name ofType { kind name ofType { kind name } } }
            }
          }
          inputFields {
            name
            type { kind name ofType { kind name ofType { kind name } } }
          }
          enumValues(includeDeprecated: true) { name }
        }
      }
    }
    """
    response = httpx.post(endpoint, headers=headers, json={"query": query}, timeout=timeout)
    response.raise_for_status()
    payload = response.json()
    normalize_schema(payload)
    output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    console.print(f"[green]Schema saved to {output}[/green]")


@app.command()
def analyze(
    schema_file: Annotated[Path, typer.Argument(help="Introspection JSON file")],
    json_output: Annotated[
        Path | None, typer.Option("--json", help="Also save JSON results")
    ] = None,
) -> None:
    """Find sensitive fields and rank operation risk."""
    operations = analyze_schema(load_schema(schema_file))
    _display_operations(operations)
    if json_output:
        data = [
            {
                "name": item.name,
                "kind": item.kind,
                "return_type": item.return_type,
                "risk": item.risk,
                "dangerous_terms": item.dangerous_terms,
                "reasons": item.risk_reasons,
            }
            for item in operations
        ]
        json_output.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


@app.command()
def generate(
    schema_file: Annotated[Path, typer.Argument(help="Introspection JSON file")],
    output: Annotated[Path, typer.Option("-o", help="Output JSON file")] = Path(
        "generated-queries.json"
    ),
    include_mutations: Annotated[
        bool, typer.Option(help="Mark reviewed mutation templates as executable")
    ] = False,
) -> None:
    """Generate minimal query templates with placeholder variables."""
    schema = load_schema(schema_file)
    generated = [
        generate_query(operation, schema, include_mutations)
        for operation in analyze_schema(schema)
        if operation.kind in {"query", "mutation"}
    ]
    output.write_text(
        json.dumps(
            [
                {
                    "name": item.operation,
                    "kind": item.kind,
                    "query": item.document,
                    "variables": item.variables,
                    "executable": item.executable,
                    "warning": item.warning,
                }
                for item in generated
            ],
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    console.print(f"[green]Generated {len(generated)} templates in {output}[/green]")


@app.command()
def run(
    config_file: Annotated[Path, typer.Argument(help="YAML test configuration")],
    schema_file: Annotated[
        Path | None, typer.Option("--schema", help="Schema used to assign operation risk")
    ] = None,
    output_dir: Annotated[Path, typer.Option("-o", help="Report directory")] = Path("reports"),
    authorize: Annotated[
        bool, typer.Option(help="Confirm you are authorized to test this endpoint")
    ] = False,
    insecure: Annotated[bool, typer.Option(help="Disable TLS certificate verification")] = False,
) -> None:
    """Execute configured operations for every role and create a permission matrix."""
    if not authorize:
        console.print("[red]Refusing live requests without --authorize.[/red]")
        raise typer.Exit(2)
    endpoint, roles, tests, raw = load_config(config_file)
    timeout = float(raw.get("timeout", 15))
    results = asyncio.run(run_matrix(endpoint, roles, tests, timeout, not insecure))
    operations = {}
    if schema_file:
        operations = {item.name: item for item in analyze_schema(load_schema(schema_file))}
    role_names = [role.name for role in roles]
    rows = build_matrix(results, operations, role_names)
    write_reports(rows, role_names, output_dir)
    console.print(f"[green]Wrote Markdown, JSON, and CSV reports to {output_dir}[/green]")


if __name__ == "__main__":
    app()
