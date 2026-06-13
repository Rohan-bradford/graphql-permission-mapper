from pathlib import Path

from gql_permission_mapper.generator import generate_query
from gql_permission_mapper.schema import analyze_schema, load_schema

SCHEMA_PATH = Path(__file__).parents[1] / "examples" / "schema.json"


def test_sensitive_operations_are_ranked() -> None:
    operations = {item.name: item for item in analyze_schema(load_schema(SCHEMA_PATH))}

    assert operations["listApiKeys"].risk == "Critical"
    assert operations["updateBillingSettings"].risk == "Critical"
    assert operations["deleteWorkspaceInvite"].risk == "Critical"
    assert operations["viewer"].risk == "High"
    assert "sensitive return fields: token" in operations["listApiKeys"].risk_reasons


def test_generated_mutation_is_review_only_by_default() -> None:
    schema = load_schema(SCHEMA_PATH)
    operation = next(
        item for item in analyze_schema(schema) if item.name == "updateBillingSettings"
    )
    generated = generate_query(operation, schema)

    assert generated.executable is False
    assert "$plan: String!" in generated.document
    assert generated.variables == {"plan": "REPLACE_ME"}
    assert "id" in generated.document
