#!/usr/bin/env python3
"""Poke an MCP server over Streamable HTTP: initialize, tools/list, tools/call.

Standard library only. Point it at the fake proxy (or the real NetBird URL)
to see what a caller with a given identity can do.

Examples:
  python dev/try_mcp.py http://127.0.0.1:9002/mcp
  python dev/try_mcp.py http://127.0.0.1:9002/mcp --call get_ticket '{"ticket_id": 1}'
  python dev/try_mcp.py http://127.0.0.1:8002/mcp -H "X-NetBird-Identity: $(python dev/mint_token.py token --preset admin --domain tickets.localhost)"
  python dev/try_mcp.py https://tickets.example.com/mcp -H "X-API-Key: ..."   # through NetBird with an API key
"""

import argparse
import json
import sys
import urllib.error
import urllib.request

PROTOCOL_VERSION = "2025-06-18"


class MCP:
    def __init__(self, url: str, headers: dict[str, str]):
        self.url = url
        self.headers = headers
        self.session = None
        self.next_id = 1

    def rpc(self, method: str, params: dict | None = None, notify: bool = False):
        msg = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params
        if not notify:
            msg["id"] = self.next_id
            self.next_id += 1
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "MCP-Protocol-Version": PROTOCOL_VERSION,
            **self.headers,
        }
        if self.session:
            headers["Mcp-Session-Id"] = self.session
        req = urllib.request.Request(self.url, data=json.dumps(msg).encode(), headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                self.session = resp.headers.get("Mcp-Session-Id") or self.session
                body = resp.read().decode()
                ctype = resp.headers.get("Content-Type", "")
                status = resp.status
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode()
        if notify or not body.strip():
            return status, None
        if ctype.startswith("text/event-stream"):
            data = [line[5:].strip() for line in body.splitlines() if line.startswith("data:")]
            body = data[-1] if data else "{}"
        return status, json.loads(body)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("url")
    p.add_argument("-H", "--header", action="append", default=[], help="extra header 'Name: value'")
    p.add_argument("--call", nargs=2, metavar=("TOOL", "JSON_ARGS"), action="append", default=[],
                   help="call a tool after listing; repeatable")
    args = p.parse_args()

    headers = {}
    for h in args.header:
        name, _, value = h.partition(":")
        headers[name.strip()] = value.strip()

    c = MCP(args.url, headers)
    status, res = c.rpc("initialize", {
        "protocolVersion": PROTOCOL_VERSION,
        "capabilities": {},
        "clientInfo": {"name": "try_mcp", "version": "0.1"},
    })
    print(f"initialize -> HTTP {status}")
    if status != 200:
        print(f"  {res}")
        return 1
    c.rpc("notifications/initialized", notify=True)

    status, res = c.rpc("tools/list", {})
    names = [t["name"] for t in res.get("result", {}).get("tools", [])] if isinstance(res, dict) else res
    print(f"tools/list -> HTTP {status}: {names}")

    rc = 0
    for tool, raw in args.call:
        status, res = c.rpc("tools/call", {"name": tool, "arguments": json.loads(raw)})
        if status != 200:
            print(f"tools/call {tool} -> HTTP {status}: {res}")
            rc = 1
            continue
        result = res.get("result", {})
        text = " ".join(part.get("text", "") for part in result.get("content", []))
        verdict = "ERROR" if result.get("isError") or "error" in res else "ok"
        print(f"tools/call {tool} -> HTTP {status} {verdict}: {text or res.get('error')}")
        rc = rc or (1 if verdict == "ERROR" else 0)
    return rc


if __name__ == "__main__":
    sys.exit(main())
