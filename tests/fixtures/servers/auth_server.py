"""A harmless MCP server that needs a key, for testing authenticated scans.

The key is read from AUTH_DEMO_TOKEN. Use any value, for example:

    export AUTH_DEMO_TOKEN=demo-$(python -c "import secrets; print(secrets.token_hex(16))")

Run over stdio:            python auth_server.py
    Like most stdio servers that call an account (GitHub, Slack, ...), it refuses to
    start without its key in the environment. Scan it with --env AUTH_DEMO_TOKEN=...

Run over streamable HTTP:  python auth_server.py --http 8766
    Every request needs the header "Authorization: Bearer <AUTH_DEMO_TOKEN>".
    Without it the server answers HTTP 401 with "WWW-Authenticate: Bearer".
    Scan it with --header "Authorization: Bearer ..."
"""

import hmac
import os
import sys

from mcp.server import MCPServer

TOKEN = os.environ.get("AUTH_DEMO_TOKEN", "")

mcp = MCPServer("auth-demo", instructions="A small project list for a signed in demo account.")

PROJECTS = ["website", "mobile-app", "docs"]


@mcp.tool()
def whoami() -> str:
    """Show which demo account the key belongs to."""
    return "Signed in as demo-user (read only)."


@mcp.tool()
def list_projects() -> list[str]:
    """List the projects of the signed in demo account."""
    return PROJECTS


@mcp.tool()
def get_project(name: str) -> str:
    """Show one project of the signed in demo account by its name."""
    return f"Project {name}: active" if name in PROJECTS else f"No project called {name}."


class BearerAuth:
    """ASGI middleware: every request needs the bearer token."""

    def __init__(self, app, token: str) -> None:  # type: ignore[no-untyped-def]
        self.app = app
        self.expected = f"Bearer {token}".encode()

    async def __call__(self, scope, receive, send) -> None:  # type: ignore[no-untyped-def]
        if scope["type"] == "http":
            given = dict(scope.get("headers") or []).get(b"authorization", b"")
            if not hmac.compare_digest(given, self.expected):
                await send(
                    {
                        "type": "http.response.start",
                        "status": 401,
                        "headers": [
                            (b"content-type", b"application/json"),
                            (b"www-authenticate", b'Bearer realm="auth-demo"'),
                        ],
                    }
                )
                await send({"type": "http.response.body", "body": b'{"error": "missing or wrong bearer token"}'})
                return
        await self.app(scope, receive, send)


def main() -> None:
    if not TOKEN:
        print("auth-demo: AUTH_DEMO_TOKEN is not set. Pass your key in that variable.", file=sys.stderr)
        sys.exit(1)
    if len(sys.argv) > 2 and sys.argv[1] == "--http":
        import uvicorn

        app = BearerAuth(mcp.streamable_http_app(), TOKEN)
        uvicorn.run(app, host="127.0.0.1", port=int(sys.argv[2]), log_level="warning")
    else:
        mcp.run()


if __name__ == "__main__":
    main()
