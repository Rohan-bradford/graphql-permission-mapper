"""Tiny standard-library server for the documented local demo."""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class GraphQLDemoHandler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        payload = json.loads(self.rfile.read(length) or b"{}")
        query = payload.get("query", "")
        role = self.headers.get("X-Demo-Role", "viewer").lower()

        status = 200
        if "updateBillingSettings" in query:
            if role == "viewer":
                status, body = 403, {"errors": [{"message": "Forbidden"}]}
            else:
                body = {"data": {"updateBillingSettings": {"id": "billing-1", "plan": "sandbox"}}}
        elif "deleteWorkspaceInvite" in query:
            body = {"data": {"deleteWorkspaceInvite": {"id": "demo-invite", "status": "deleted"}}}
        elif "listApiKeys" in query:
            key = {"id": "key-1", "name": "Demo key"}
            if role == "admin":
                key["token"] = "demo-redacted-token"
            body = {"data": {"listApiKeys": [key]}}
        else:
            status, body = 400, {"errors": [{"message": "Unknown demo operation"}]}

        encoded = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, format: str, *args: object) -> None:
        return


if __name__ == "__main__":
    address = ("127.0.0.1", 8765)
    print(f"Demo GraphQL endpoint: http://{address[0]}:{address[1]}/graphql")
    ThreadingHTTPServer(address, GraphQLDemoHandler).serve_forever()

