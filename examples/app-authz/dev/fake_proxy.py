#!/usr/bin/env python3
"""A tiny stand-in for the NetBird reverse proxy, for local development.

It forwards every request to your app and stamps the identity NetBird would
send, picked from command-line flags. It also strips any X-NetBird-* headers
the client sent, exactly like the real proxy, and can enforce MCP tool
permissions (403 on a forbidden tools/call).

Examples:
  # headers mode, logged in as the "viewer" example user
  python dev/fake_proxy.py --upstream http://127.0.0.1:8001 --preset viewer

  # jwt mode, admin, token in X-NetBird-Identity, MCP enforcement on
  python dev/fake_proxy.py --upstream http://127.0.0.1:8002 --listen 127.0.0.1:9002 \\
      --mode jwt --preset admin --domain tickets.localhost --enforce-mcp

  # custom identity
  python dev/fake_proxy.py --upstream http://127.0.0.1:8003 --mode headers \\
      --sub usr_1 --email me@example.com --groups eng --roles editor

The JWKS for the local key is served at /.well-known/netbird/jwks.json, the
same path the real proxy uses. This is a development tool: it has no login,
so anyone who can reach it is "logged in". Bind it to localhost.
"""

import argparse
import http.client
import json
import re
import sys
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import devkeys

HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade",
}
JWKS_PATH = "/.well-known/netbird/jwks.json"


def _csv(value: str) -> list[str]:
    return [v.strip() for v in value.split(",") if v.strip()]


def tool_allowed(patterns: list[str], tool: str) -> bool:
    """Same rule as the proxy: '*' matches any run of characters, the rest is literal."""
    if not tool:
        return False
    for p in patterns:
        regex = "".join(".*" if part == "*" else re.escape(part) for part in re.split(r"(\*)", p))
        if re.fullmatch(regex, tool, flags=re.DOTALL):
            return True
    return False


def tool_calls(body: bytes) -> list[str]:
    """Tool names of every tools/call in a JSON-RPC body (single or batch). Raises on junk."""
    msg = json.loads(body)
    messages = msg if isinstance(msg, list) else [msg]
    names = []
    for m in messages:
        if not isinstance(m, dict):
            raise ValueError("not a JSON-RPC object")
        if m.get("method") == "tools/call":
            params = m.get("params") or {}
            names.append(params.get("name", "") if isinstance(params, dict) else "")
    return names


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    cfg: argparse.Namespace
    ident: dict
    key = None

    def log_message(self, fmt, *args):
        sys.stderr.write("fake-proxy: " + (fmt % args) + "\n")

    def do_GET(self):
        self._handle()

    def do_POST(self):
        self._handle()

    def do_PUT(self):
        self._handle()

    def do_PATCH(self):
        self._handle()

    def do_DELETE(self):
        self._handle()

    def do_OPTIONS(self):
        self._handle()

    def do_HEAD(self):
        self._handle()

    def _send_json(self, status: int, payload: dict, extra: dict | None = None):
        data = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def _handle(self):
        if self.path == JWKS_PATH and self.command == "GET":
            self._send_json(200, devkeys.jwks(self.key), {"Cache-Control": "public, max-age=300"})
            return

        if "chunked" in self.headers.get("Transfer-Encoding", "").lower():
            self._send_json(411, {"code": "length_required", "message": "fake-proxy needs Content-Length"})
            return
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""

        if self.cfg.enforce_mcp and self.command == "POST" and not self._mcp_allowed(body):
            return

        headers = self._upstream_headers()
        self._forward(body, headers)

    def _mcp_allowed(self, body: bytes) -> bool:
        if not body.strip():
            return True
        try:
            calls = tool_calls(body)
        except (ValueError, json.JSONDecodeError):
            self._deny("mcp_request_uninspectable", "request body is not unambiguous JSON-RPC", "")
            return False
        for name in calls:
            if not tool_allowed(self.ident.get("mcp_tools") or [], name):
                self._deny("mcp_tool_forbidden", "your roles do not allow this MCP tool", name)
                return False
        return True

    def _deny(self, code: str, message: str, tool: str):
        payload = {"code": code, "message": message, "middleware": "app_authz"}
        if tool:
            payload["details"] = {"tool": tool}
        self.log_message("deny %s tool=%r", code, tool)
        self._send_json(403, payload)

    def _upstream_headers(self) -> dict:
        out = {}
        for k, v in self.headers.items():
            lk = k.lower()
            if lk in HOP_BY_HOP or lk == "host" or lk.startswith("x-netbird-"):
                continue  # the real proxy strips every client-sent X-NetBird-* header
            if lk == "authorization" and self.cfg.mode == "jwt" and self.cfg.jwt_header.lower() == "authorization":
                continue
            out[k] = v
        out["X-Forwarded-For"] = self.client_address[0]
        out["X-Forwarded-Proto"] = "https"
        out["X-Forwarded-Host"] = self.cfg.domain

        ident = self.ident
        if self.cfg.mode == "none" or not ident.get("sub"):
            return out

        # Stamped in both modes, like the real proxy.
        if ident.get("email"):
            out["X-NetBird-User"] = ident["email"]
        groups = [g for g in ident.get("groups") or [] if "," not in g]
        if groups:
            out["X-NetBird-Groups"] = ",".join(groups)

        if self.cfg.mode == "headers":
            out["X-NetBird-User-Id"] = ident["sub"]
            out["X-NetBird-Auth-Method"] = ident.get("auth_method", "oidc")
            if ident.get("roles"):
                out["X-NetBird-Roles"] = ",".join(ident["roles"])
            return out

        token = devkeys.mint(
            self.key,
            self.cfg.domain,
            sub=ident["sub"],
            email=ident.get("email", ""),
            groups=ident.get("groups"),
            roles=ident.get("roles"),
            mcp_tools=ident.get("mcp_tools"),
            auth_method=ident.get("auth_method", "oidc"),
            ttl=self.cfg.ttl,
        )
        if self.cfg.jwt_header.lower() == "authorization":
            out["Authorization"] = "Bearer " + token
        else:
            out[self.cfg.jwt_header] = token
        return out

    def _forward(self, body: bytes, headers: dict):
        up = self.cfg.upstream_url
        conn_cls = http.client.HTTPSConnection if up.scheme == "https" else http.client.HTTPConnection
        conn = conn_cls(up.hostname, up.port, timeout=self.cfg.timeout)
        headers["Host"] = up.netloc
        if body:
            headers["Content-Length"] = str(len(body))
        try:
            conn.request(self.command, self.path, body=body or None, headers=headers)
            resp = conn.getresponse()
        except OSError as e:
            self._send_json(502, {"code": "bad_gateway", "message": f"upstream unreachable: {e}"})
            return

        self.send_response(resp.status, resp.reason)
        length = resp.getheader("Content-Length")
        for k, v in resp.getheaders():
            if k.lower() in HOP_BY_HOP:
                continue
            self.send_header(k, v)
        if length is None:
            # Streaming (SSE) or chunked upstream: relay until the upstream closes.
            self.send_header("Connection", "close")
            self.close_connection = True
        self.end_headers()
        if self.command == "HEAD":
            conn.close()
            return
        try:
            while chunk := resp.read1(65536):
                self.wfile.write(chunk)
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            conn.close()


def build_identity(args) -> dict:
    ident = dict(devkeys.PRESETS.get(args.preset or "", {}))
    for field, value in (
        ("sub", args.sub),
        ("email", args.email),
        ("groups", args.groups),
        ("roles", args.roles),
        ("mcp_tools", args.tools),
        ("auth_method", args.auth_method),
    ):
        if value is not None:
            ident[field] = value
    return ident


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--upstream", required=True, help="your app, e.g. http://127.0.0.1:8001")
    p.add_argument("--listen", default="127.0.0.1:9000", help="host:port to listen on (default 127.0.0.1:9000)")
    p.add_argument("--mode", choices=["headers", "jwt", "none"], default="headers",
                   help="identity forwarding mode; 'none' sends no identity at all")
    p.add_argument("--jwt-header", default="X-NetBird-Identity",
                   help="X-NetBird-Identity (default) or Authorization")
    p.add_argument("--domain", default="app.localhost", help="service domain: JWT iss is https://<domain>, aud is <domain>")
    p.add_argument("--ttl", type=int, default=60, help="JWT lifetime in seconds (<= 0 sends expired tokens)")
    p.add_argument("--enforce-mcp", action="store_true", help="403 on tools/call outside the caller's mcp_tools")
    p.add_argument("--timeout", type=float, default=300)
    p.add_argument("--preset", choices=sorted(devkeys.PRESETS), help="example identity (see dev/devkeys.py)")
    p.add_argument("--sub", help="user id")
    p.add_argument("--email")
    p.add_argument("--groups", type=_csv)
    p.add_argument("--roles", type=_csv)
    p.add_argument("--tools", type=_csv, help="MCP tool globs for this caller, e.g. 'list_*,get_ticket'")
    p.add_argument("--auth-method", choices=["oidc", "header", "password", "pin"])
    args = p.parse_args()

    if args.jwt_header.lower() not in ("x-netbird-identity", "authorization"):
        p.error("--jwt-header must be X-NetBird-Identity or Authorization")
    args.upstream_url = urllib.parse.urlsplit(args.upstream)
    if args.upstream_url.scheme not in ("http", "https") or not args.upstream_url.hostname:
        p.error("--upstream must be an http(s) URL")

    host, _, port = args.listen.rpartition(":")
    Handler.cfg = args
    Handler.ident = build_identity(args)
    Handler.key = devkeys.load_or_create_key()

    if args.mode != "none" and not Handler.ident.get("sub"):
        p.error("pick an identity with --preset or --sub, or use --mode none")

    server = ThreadingHTTPServer((host or "127.0.0.1", int(port)), Handler)
    print(f"fake-proxy on http://{args.listen} -> {args.upstream} (mode={args.mode})", file=sys.stderr)
    print(f"identity: {json.dumps(Handler.ident)}", file=sys.stderr)
    if args.mode == "jwt":
        print(f"verify with NETBIRD_JWKS_URL=http://{args.listen}{JWKS_PATH} "
              f"NETBIRD_AUDIENCE={args.domain}, or this PEM:", file=sys.stderr)
        print(devkeys.public_pem(Handler.key), file=sys.stderr)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
