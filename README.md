# GraphQL Permission Mapper

A defensive GraphQL authorization analysis CLI. It inventories schema operations, flags
sensitive fields, generates minimal test documents, runs the same operation as multiple
roles, and exports a permission matrix.

> Use this tool only on GraphQL APIs you own or have explicit permission to test.

## Features

- Load or fetch a GraphQL introspection schema
- Detect sensitive operations involving users, admins, billing, workspaces, tokens,
  secrets, invites, roles, credentials, and API keys
- Rank operations as Low, Medium, High, or Critical risk
- Generate minimal query and mutation templates
- Run identical operations with multiple role credentials
- Compare HTTP status codes and returned field paths
- Export Markdown, JSON, and CSV permission matrices
- Keep credentials out of config files with environment-variable expansion

## Quick Start

```bash
git clone https://github.com/your-username/graphql-permission-mapper.git
cd graphql-permission-mapper
python -m venv .venv
```

Activate the environment:

```bash
# Windows PowerShell
.venv\Scripts\Activate.ps1

# macOS/Linux
source .venv/bin/activate
```

Install and inspect the included demo schema:

```bash
pip install -e ".[dev]"
gql-permission-map analyze examples/schema.json
gql-permission-map generate examples/schema.json -o generated-queries.json
```

## Demo Permission Matrix

Start the local mock GraphQL endpoint:

```bash
python examples/mock_server.py
```

In another terminal:

```bash
gql-permission-map run examples/config.yml \
  --schema examples/schema.json \
  --authorize \
  -o reports
```

The command creates:

- `reports/permission-matrix.md`
- `reports/permission-matrix.json`
- `reports/permission-matrix.csv`

Example:

| Operation | Viewer | Editor | Admin | Risk |
| --- | --- | --- | --- | --- |
| `updateBillingSettings` | 403 | 200 | 200 | **Critical** |
| `deleteWorkspaceInvite` | 200 | 200 | 200 | **Critical** |
| `listApiKeys` | 200 | 200 | 200 | **Critical** |

GraphQL APIs often return HTTP 200 with an `errors` array. The JSON report preserves those
errors, while the matrix also identifies field-level differences between roles.

## Configuration

```yaml
endpoint: https://api.example.com/graphql
timeout: 15

roles:
  - name: Viewer
    headers:
      Authorization: Bearer ${VIEWER_TOKEN}
  - name: Admin
    headers:
      Authorization: Bearer ${ADMIN_TOKEN}

operations:
  - name: listApiKeys
    query: |
      query PermissionMapListApiKeys {
        listApiKeys {
          id
          name
          token
        }
      }
    variables: {}
```

Set tokens in the shell rather than committing them:

```bash
export VIEWER_TOKEN="..."
export ADMIN_TOKEN="..."
```

PowerShell:

```powershell
$env:VIEWER_TOKEN = "..."
$env:ADMIN_TOKEN = "..."
```

## Commands

```text
gql-permission-map fetch-schema --endpoint URL [-H "Authorization: Bearer ..."]
gql-permission-map analyze schema.json [--json findings.json]
gql-permission-map generate schema.json [-o generated-queries.json]
gql-permission-map run config.yml --schema schema.json --authorize [-o reports]
```

Mutation templates are generated for review but marked non-executable by default.
`run` never consumes generated templates automatically, and live requests require the
explicit `--authorize` confirmation.

## Development

```bash
pip install -e ".[dev]"
ruff check .
pytest
```

## Responsible Use

Avoid production mutations unless the test case and rollback behavior are understood.
Use dedicated test accounts, low-impact records, and a staging environment where possible.
Never commit access tokens or captured private data.

## License

MIT

