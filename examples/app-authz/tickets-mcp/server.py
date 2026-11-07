"""tickets-mcp: an MCP server that lets NetBird do the login.

There is no OAuth here. The NetBird proxy authenticates the caller (SSO, API
key or NetBird peer) and sends a short-lived signed JWT with the caller's
roles and the MCP tools they may call. This server:

  1. verifies that JWT on every HTTP request (401 without a valid one),
  2. hides tools the caller may not call from tools/list,
  3. re-checks every tools/call (defense in depth; the proxy checks too).

Run (jwt mode is required here):
  NETBIRD_AUDIENCE=tickets.example.com \
  NETBIRD_JWKS_URL=https://tickets.example.com/.well-known/netbird/jwks.json \
  python server.py
"""

import os
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from itertools import count
from threading import Lock

import anyio
import uvicorn
from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from fastmcp.server.dependencies import get_http_request
from fastmcp.server.middleware import Middleware, MiddlewareContext
from starlette.middleware import Middleware as ASGIMiddleware
from starlette.responses import JSONResponse

from netbird_identity import Identity, IdentityError, IdentityVerifier

verifier = IdentityVerifier.from_env(default_mode="jwt")
if verifier.mode != "jwt":
    raise SystemExit("tickets-mcp needs NETBIRD_IDENTITY_MODE=jwt: tool permissions travel in the JWT")


# ---------------------------------------------------------------- auth glue


class NetBirdAuth:
    """ASGI middleware: verify the NetBird JWT before anything reaches MCP."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope["path"] == "/healthz":
            return await self.app(scope, receive, send)
        headers = {k.decode("latin-1"): v.decode("latin-1") for k, v in scope["headers"]}
        headers = _CaseInsensitive(headers)
        try:
            # JWKS lookups may hit the network; keep them off the event loop.
            ident = await anyio.to_thread.run_sync(verifier.identify, headers)
        except IdentityError as e:
            resp = JSONResponse({"error": "unauthorized", "detail": str(e)}, status_code=401)
            return await resp(scope, receive, send)
        scope.setdefault("state", {})["netbird"] = ident
        return await self.app(scope, receive, send)


class _CaseInsensitive(dict):
    def __init__(self, d):
        super().__init__({k.lower(): v for k, v in d.items()})

    def get(self, key, default=None):
        return super().get(key.lower(), default)


def caller() -> Identity:
    """The verified caller of the current request."""
    ident = get_http_request().scope.get("state", {}).get("netbird")
    if not isinstance(ident, Identity):
        raise ToolError("no verified NetBird identity")  # cannot happen behind NetBirdAuth
    return ident


class ToolPermissions(Middleware):
    """Filter tools/list by the mcp_tools claim and re-check tools/call."""

    async def on_list_tools(self, context: MiddlewareContext, call_next):
        tools = await call_next(context)
        ident = caller()
        return [t for t in tools if ident.tool_allowed(t.name)]

    async def on_call_tool(self, context: MiddlewareContext, call_next):
        ident = caller()
        if not ident.tool_allowed(context.message.name):
            raise ToolError(f"your NetBird roles do not allow the tool '{context.message.name}'")
        return await call_next(context)


# ---------------------------------------------------------------- the app


@dataclass
class Ticket:
    id: int
    title: str
    body: str
    status: str
    created_by: str
    created_at: str


_tickets: dict[int, Ticket] = {}
_ids = count(1)
_lock = Lock()


def _add(title: str, body: str, created_by: str) -> Ticket:
    with _lock:
        t = Ticket(next(_ids), title, body, "open", created_by, datetime.now(timezone.utc).isoformat())
        _tickets[t.id] = t
    return t


_add("VPN drops every hour", "Seen on three laptops since Monday.", "seed")
_add("Rotate staging API key", "Old key leaked in a screenshot.", "seed")

mcp = FastMCP(
    name="tickets",
    instructions="A small ticket tracker. Who you are and what you may call is decided by NetBird.",
    middleware=[ToolPermissions()],
)


@mcp.tool
def list_tickets(status: str = "") -> list[dict]:
    """List tickets, optionally only those with the given status (open or closed)."""
    with _lock:
        items = [asdict(t) for t in _tickets.values() if not status or t.status == status]
    return items


@mcp.tool
def get_ticket(ticket_id: int) -> dict:
    """Get one ticket by id."""
    with _lock:
        t = _tickets.get(ticket_id)
    if t is None:
        raise ToolError(f"ticket {ticket_id} not found")
    return asdict(t)


@mcp.tool
def create_ticket(title: str, body: str = "") -> dict:
    """Create a ticket. It is attributed to the calling NetBird user."""
    return asdict(_add(title, body, caller().display_name))


@mcp.tool
def delete_ticket(ticket_id: int) -> str:
    """Delete a ticket for good."""
    with _lock:
        if _tickets.pop(ticket_id, None) is None:
            raise ToolError(f"ticket {ticket_id} not found")
    return f"deleted ticket {ticket_id}"


app = mcp.http_app(
    path="/mcp",
    middleware=[ASGIMiddleware(NetBirdAuth)],
    stateless_http=True,
    json_response=True,
)


async def healthz(_request):
    return JSONResponse({"ok": True})


app.add_route("/healthz", healthz)

if __name__ == "__main__":
    uvicorn.run(app, host=os.environ.get("HOST", "127.0.0.1"), port=int(os.environ.get("PORT", "8002")))
