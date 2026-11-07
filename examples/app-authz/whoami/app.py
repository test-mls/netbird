"""whoami: shows exactly what the NetBird proxy tells your app about the caller.

Run:  NETBIRD_IDENTITY_MODE=headers python app.py
 or:  NETBIRD_IDENTITY_MODE=jwt NETBIRD_AUDIENCE=whoami.example.com \
        NETBIRD_JWKS_URL=https://whoami.example.com/.well-known/netbird/jwks.json python app.py

Binds to 127.0.0.1 by default. Set HOST=0.0.0.0 only inside a private
network (for example docker compose) that nothing but NetBird can reach.
"""

import html
import json
import os

from flask import Flask, abort, request

from netbird_identity import (
    HEADER_AUTH_METHOD,
    HEADER_GROUPS,
    HEADER_IDENTITY,
    HEADER_ROLES,
    HEADER_USER,
    HEADER_USER_ID,
    IdentityError,
    IdentityVerifier,
)

app = Flask(__name__)
verifier = IdentityVerifier.from_env(default_mode="headers")

PAGE = """<!doctype html><html><head><meta charset="utf-8"><title>whoami</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>body{{font:15px system-ui,sans-serif;max-width:760px;margin:2rem auto;padding:0 16px}}
pre{{background:#f4f4f5;padding:12px;overflow:auto}}td{{padding:2px 12px 2px 0;vertical-align:top}}
.bad{{color:#b91c1c}}</style></head><body>{body}</body></html>"""


def current_identity():
    """The verified identity, or a 401. Every protected route starts here."""
    try:
        return verifier.identify(request.headers)
    except IdentityError as e:
        abort(401, description=str(e))


def require_role(role: str):
    ident = current_identity()
    if not ident.has_role(role):
        abort(403, description=f"you need the '{role}' role")
    return ident


def _row(name: str, value) -> str:
    shown = value if value not in (None, "", []) else "(not set)"
    return f"<tr><td><code>{html.escape(name)}</code></td><td>{html.escape(str(shown))}</td></tr>"


@app.get("/")
def index():
    parts = [f"<h1>whoami</h1><p>Identity mode: <b>{verifier.mode}</b></p>"]
    try:
        ident = verifier.identify(request.headers)
        parts.append("<h2>You are</h2><table>")
        parts += [
            _row("user id", ident.user_id),
            _row("email", ident.email),
            _row("groups", ", ".join(ident.groups)),
            _row("roles", ", ".join(ident.roles)),
            _row("mcp tools", ", ".join(ident.mcp_tools)),
            _row("auth method", ident.auth_method),
            _row("source", ident.source),
        ]
        parts.append("</table>")
        if ident.claims:
            parts.append("<h2>Verified JWT claims</h2><pre>"
                         + html.escape(json.dumps(ident.claims, indent=2)) + "</pre>")
        parts.append('<p><a href="/admin">/admin</a> needs the <code>admin</code> role.</p>')
    except IdentityError as e:
        parts.append(f'<p class="bad">No trusted identity: {html.escape(str(e))}</p>')

    parts.append("<h2>Raw X-NetBird-* headers</h2><table>")
    for h in (HEADER_USER, HEADER_GROUPS, HEADER_USER_ID, HEADER_ROLES, HEADER_AUTH_METHOD):
        parts.append(_row(h, request.headers.get(h)))
    token = verifier.raw_token(request.headers) if verifier.mode == "jwt" else request.headers.get(HEADER_IDENTITY)
    parts.append(_row(verifier.jwt_header if verifier.mode == "jwt" else HEADER_IDENTITY,
                      (token[:24] + "...") if token else None))
    parts.append("</table>")
    if verifier.mode == "jwt":
        parts.append("<p>In jwt mode only the verified claims count. The plain headers are shown for "
                     "debugging and are not used for decisions.</p>")
    return PAGE.format(body="".join(parts))


@app.get("/api/whoami")
def api_whoami():
    ident = current_identity()
    return {
        "user_id": ident.user_id,
        "email": ident.email,
        "groups": ident.groups,
        "roles": ident.roles,
        "mcp_tools": ident.mcp_tools,
        "auth_method": ident.auth_method,
        "source": ident.source,
        "claims": ident.claims,
    }


# App-side authorization in five lines: the proxy says who, the app decides what.
@app.get("/admin")
def admin():
    ident = require_role("admin")
    return PAGE.format(body=f"<h1>Admin</h1><p>Welcome, {html.escape(ident.display_name)}.</p>")


@app.get("/healthz")
def healthz():
    return {"ok": True}


if __name__ == "__main__":
    app.run(host=os.environ.get("HOST", "127.0.0.1"), port=int(os.environ.get("PORT", "8001")))
