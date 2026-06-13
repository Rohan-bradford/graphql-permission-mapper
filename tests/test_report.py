from gql_permission_mapper.models import Operation, RoleResult
from gql_permission_mapper.report import build_matrix, markdown_report


def test_matrix_identifies_role_field_differences() -> None:
    results = [
        RoleResult("Viewer", "listApiKeys", 200, ("listApiKeys.id",), (), 10),
        RoleResult(
            "Admin",
            "listApiKeys",
            200,
            ("listApiKeys.id", "listApiKeys.token"),
            (),
            12,
        ),
    ]
    operation = Operation("listApiKeys", "query", "ApiKey", "OBJECT", risk="Critical")
    rows = build_matrix(results, {"listApiKeys": operation}, ["Viewer", "Admin"])

    assert "returned fields differ by role" in rows[0].findings
    report = markdown_report(rows, ["Viewer", "Admin"])
    assert "`listApiKeys`" in report
    assert "**Critical**" in report

