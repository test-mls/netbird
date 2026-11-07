# Protect that slop: put NetBird in front of your app

You built an app or an MCP server in an afternoon with an AI. Now you want
your team to use it without writing a login screen, an OAuth flow or a users
table. Put the NetBird reverse proxy in front of it and let NetBird do the
login. Your app only reads who is calling.

This folder has working examples you can copy:

| Folder | What it is |
| --- | --- |
| [`whoami/`](whoami/) | Tiny Python (Flask) page that shows what NetBird tells your app, plus an `/admin` page that needs the `admin` role. |
| [`tickets-mcp/`](tickets-mcp/) | MCP server (Python, FastMCP) with `list_tickets`, `get_ticket`, `create_ticket`, `delete_ticket`. Verifies the NetBird JWT and only shows each caller the tools they may call. No OAuth. |
| [`notes-app/`](notes-app/) | Typical Node/Express CRUD app with its login code deleted. Its README shows the before and after. |
| [`dev/`](dev/) | Test without NetBird: a fake proxy, a token minter and an MCP test client. |
| [`docker-compose.yml`](docker-compose.yml) | Runs all three apps on a private network. |

## What NetBird does for you

- **No login screens.** People sign in with your company SSO (Google,
  Microsoft Entra ID, Okta and others) before a request ever reaches your app.
- **No OAuth.** Scripts and AI agents use an API key header, and NetBird peers
  can come in over the tunnel. Your app never sees a password or an OAuth
  redirect.
- **No user table.** Who someone is and which groups they are in comes from
  NetBird. You map groups to roles in the dashboard, for example
  `ops` → `admin` and `eng` → `viewer`.
- **MCP tool permissions.** For MCP servers, each role lists the tools it may
  call (`*` is a wildcard, so `list_*` means "every tool starting with
  list_"). NetBird blocks a forbidden `tools/call` before it reaches your
  server and answers the client with a tool error the AI can read.

```text
browser / script / AI agent
          |
          v
  NetBird reverse proxy     1. login (SSO, API key or NetBird peer)
          |                 2. groups -> roles, MCP tool check
          |                 3. adds identity headers or a signed JWT
          v
      your app              reads who is calling, checks roles
  (private, not public)
```

## The 3 rules for your app

1. **Never expose the app directly.** Bind it to `127.0.0.1` or a private
   network that only the NetBird proxy can reach. The identity headers are only
   trustworthy when the proxy is the only way in: anyone who can reach your
   app directly can type `X-NetBird-Roles: admin` themselves.
2. **Read identity from the headers, or verify the JWT.** Nothing else. Not a
   cookie your app sets, not a query parameter, not a field in the request
   body.
3. **Check roles for anything destructive.** Delete, edit, admin pages,
   anything that costs money. Check on the server, every time. Hiding a button
   is nice, but it is not security.

## What your app receives

### Headers mode

| Header | Value |
| --- | --- |
| `X-NetBird-User-Id` | Stable user ID. Use this as the key for per-user data. |
| `X-NetBird-User` | Email. Missing for API key callers. For a NetBird peer without a user it can be the peer name. |
| `X-NetBird-Groups` | Group names, comma-separated, for example `ops,eng`. |
| `X-NetBird-Roles` | Roles, comma-separated, for example `admin,viewer`. Missing means no roles. |
| `X-NetBird-Auth-Method` | `oidc` (SSO), `header` (API key), `password` or `pin`. |
| `X-NetBird-MCP-Tools` | MCP tool patterns the caller's roles allow, comma-separated, for example `list_*,get_ticket`. Missing means none. |

NetBird removes any of these headers that the client sent and sets its own.

### JWT mode

One header, `X-NetBird-Identity: <token>` (or `Authorization: Bearer <token>`
if you pick that in the dashboard). The token is signed with Ed25519 (`alg:
EdDSA`), lives for 60 seconds and is minted fresh for every request. Its
claims:

```json
{
  "iss": "https://tickets.example.com",
  "aud": "tickets.example.com",
  "sub": "usr_bob",
  "email": "bob@example.com",
  "groups": ["eng"],
  "roles": ["viewer"],
  "mcp_tools": ["list_*", "get_ticket"],
  "auth_method": "oidc",
  "jti": "64e83be7661c1c0eab290a438b2fc17b",
  "iat": 1794048032, "nbf": 1794048032, "exp": 1794048092
}
```

`email`, `groups` and `mcp_tools` are left out when empty. `roles` is always
there, possibly as `[]`.

To verify it you need the service's public key. You can get it two ways:

- **JWKS URL:** `https://<service domain>/.well-known/netbird/jwks.json`. Set
  `NETBIRD_JWKS_URL` to it. The key can then rotate without a redeploy.
- **PEM:** in the dashboard, or from the API at
  `GET /api/reverse-proxies/services/{id}` in
  `auth.authorization.forwarding.public_key_pem`:

  ```bash
  curl -s -H "Authorization: Token $NETBIRD_PAT" \
    https://api.netbird.io/api/reverse-proxies/services/$SERVICE_ID \
    | jq -r .auth.authorization.forwarding.public_key_pem > public-key.pem
  ```

  Self-hosted: use your management URL instead of `api.netbird.io`. Set
  `NETBIRD_PUBLIC_KEY_PEM` to the PEM text or to the file path.

In JWT mode NetBird still sends `X-NetBird-User` and `X-NetBird-Groups` as
plain headers. Ignore them and use only the verified claims.

### Things to know about who is calling

- **API key callers** all share one identity: user ID `header-user`, no
  email, no groups. Their roles come from the service's "API key roles"
  setting. You cannot tell two API keys apart in your app.
- **Password and PIN** logins prove that someone knew a shared secret, not who
  they are. Treat them like API keys.
- Group names that contain a comma are left out of `X-NetBird-Groups`. Where
  NetBird has no name for a group, you get its ID instead.

## Headers or JWT, which should I pick?

| | Headers | JWT |
| --- | --- | --- |
| Code in your app | 5 lines, any language | A JWT library and a key setting |
| Safe if someone reaches the app directly? | **No.** They can send any header. | Yes. They cannot forge a signature. |
| Carries MCP tool permissions? | Yes (`X-NetBird-MCP-Tools`), unsigned | Yes (`mcp_tools`), signed |
| Tied to one service? | No | Yes (`aud` is the service domain) |
| Good for | Internal dashboards on a locked-down network | MCP servers, anything with delete buttons, anything on a shared network or host |

**When in doubt, pick JWT.** It turns "I hope nobody can reach my app
directly" into "it does not matter if they do". Headers are fine when the app
listens on `127.0.0.1` on a machine only you control.

## For MCP servers

[`tickets-mcp/`](tickets-mcp/) is a complete example. The short version:

1. **Do not implement OAuth.** No authorization server, no
   `/.well-known/oauth-protected-resource`, no auth provider that adds one.
   If your server advertises OAuth, MCP clients will try to run an OAuth flow
   against it instead of using NetBird.
2. **Use JWT mode and verify the token on every HTTP request.** Tokens live
   60 seconds and every request gets a new one, so read the identity per
   request. Do not store it in the MCP session.
3. **Filter `tools/list` by the `mcp_tools` claim.** NetBird blocks forbidden
   tool calls, but it does not hide tools from the list yet. If you skip this,
   agents see tools they cannot call and waste turns on refusals.
4. **Re-check on `tools/call`.** The proxy already blocks forbidden calls; the
   second check costs one line and protects you if the proxy setting is ever
   turned off.
5. **Serve Streamable HTTP in stateless mode** at a fixed path such as `/mcp`.
6. **Turn on MCP enforcement** in the service's roles settings, and use your
   real tool names in the role patterns.

The heart of `tickets-mcp/server.py`:

```python
class ToolPermissions(Middleware):
    async def on_list_tools(self, context, call_next):
        tools = await call_next(context)
        return [t for t in tools if caller().tool_allowed(t.name)]

    async def on_call_tool(self, context, call_next):
        if not caller().tool_allowed(context.message.name):
            raise ToolError(f"your NetBird roles do not allow '{context.message.name}'")
        return await call_next(context)
```

How MCP clients connect: SSO is a browser cookie, which most MCP clients
cannot do. Give agents an **API key** (dashboard: Authentication, HTTP
Headers) or run them on a machine that is a **NetBird peer**. For example:

```bash
claude mcp add --transport http tickets https://tickets.example.com/mcp \
  --header "X-API-Key: $TICKETS_API_KEY"
```

```json
{ "mcpServers": { "tickets": {
    "url": "https://tickets.example.com/mcp",
    "headers": { "X-API-Key": "<your API key>" } } } }
```

Use the header name you chose in the dashboard, and keep files that hold the
key out of git. A forbidden tool call comes back from NetBird as a normal
MCP tool result with `"isError": true` and the text "NetBird denied this tool
call: your roles do not allow the MCP tool "delete_ticket".", so the agent
reads the refusal instead of seeing a broken connection. A body NetBird
cannot read gets HTTP 403.

The examples verify the token with a small PyJWT helper,
[`netbird_identity.py`](tickets-mcp/netbird_identity.py), because it reads
`X-NetBird-Identity`, requires `exp`, `nbf` and `iat`, and works the same in
Flask and FastMCP. FastMCP's own `JWTVerifier(algorithm="EdDSA", ...)` also
verifies NetBird tokens, but it only reads `Authorization: Bearer`, so pick
that header in the dashboard if you use it.

## Copy-paste prompts

Paste one of these into Cursor, Claude Code, Lovable, Bolt, Windsurf or
whatever you use. Replace the parts in `<angle brackets>`.

### Web app, headers mode

```text
This app will run behind the NetBird reverse proxy. NetBird handles login
(SSO or API keys) before any request reaches the app, and adds headers that
say who the user is. Change the app to rely on NetBird for identity:

1. Remove all login, signup, logout, password reset, session and OAuth code,
   any users/passwords table, and any default or seeded admin accounts. Do not
   add a new auth library.
2. Add one helper, getCurrentUser(request), that reads ONLY these headers:
   - X-NetBird-User-Id: stable user id. If missing or empty, the request is
     not authenticated: respond 401 and stop.
   - X-NetBird-User: email, may be missing. Use for display, fall back to the
     user id.
   - X-NetBird-Groups: comma-separated group names, may be missing.
   - X-NetBird-Roles: comma-separated roles, may be missing (= no roles).
   - X-NetBird-Auth-Method: oidc, header, password or pin.
   Never take identity or roles from cookies, query parameters, the request
   body or any other header. Use the helper on every route except /healthz.
3. Key per-user data by X-NetBird-User-Id, not by email.
4. On the server, require the role "<editor>" for every create, update and
   delete route, and the role "<admin>" for admin pages. Return 403
   otherwise. You may also hide buttons the user cannot use, but the server
   check is required.
5. Keep CSRF protection: for POST, PUT, PATCH and DELETE, reject the request
   when the Sec-Fetch-Site header is present and is not "same-origin". The
   NetBird login is a cookie, so cross-site requests are still a risk.
6. These headers can be forged by anyone who reaches the app without going
   through NetBird. Make the server listen on 127.0.0.1 by default
   (configurable with a HOST environment variable), remove public port
   mappings, and add a comment above getCurrentUser that says the headers are
   only trustworthy when the NetBird proxy is the only way in.
7. Do not log request headers.

Show me the diff, and list any routes where you were unsure which role to
require.
```

### Web app, JWT mode

```text
This app will run behind the NetBird reverse proxy in JWT mode. NetBird
handles login and sends a signed token with every request. Change the app:

1. Remove all login, signup, logout, password reset, session and OAuth code,
   any users/passwords table, and any default admin accounts.
2. Add one helper, getCurrentUser(request), that verifies the JWT in the
   X-NetBird-Identity header with a maintained JWT library (Python: PyJWT
   with cryptography; Node: jose). Never hand-write the crypto. Rules:
   - accept only the EdDSA algorithm (Ed25519); reject "none", HS256 and
     everything else
   - key: JWKS from the NETBIRD_JWKS_URL environment variable, or a PEM public
     key from NETBIRD_PUBLIC_KEY_PEM (the PEM text or a file path). Refuse to
     start if neither is set or NETBIRD_AUDIENCE is not set.
   - aud must equal NETBIRD_AUDIENCE; iss must equal "https://" +
     NETBIRD_AUDIENCE
   - require exp, nbf, iat and sub; allow at most 10 seconds of clock skew
   If the header is missing or anything fails, respond 401. Never fall back to
   other headers such as X-NetBird-User, and never skip verification because
   of a configuration problem.
3. Claims: sub (user id, use as the key for per-user data), email (may be
   missing), groups (array of names), roles (array, may be empty),
   auth_method.
4. On the server, require the role "<editor>" for create, update and delete
   routes and "<admin>" for admin pages. Return 403 otherwise.
5. Keep CSRF protection: reject POST, PUT, PATCH and DELETE when Sec-Fetch-Site
   is present and not "same-origin".
6. Listen on 127.0.0.1 by default (HOST environment variable to change it).
7. Never log the token.

Add tests: no token -> 401, expired token -> 401, token for another audience
-> 401, valid token without the role -> 403 on a delete route.
```

### MCP server

```text
This MCP server will run behind the NetBird reverse proxy over Streamable
HTTP. NetBird authenticates callers (API keys or NetBird peers) and sends a
signed JWT with every request. Change the server:

1. Do NOT implement OAuth. Remove any OAuth or authorization-server code, do
   not serve /.well-known/oauth-* or protected resource metadata, and do not
   configure an auth provider that adds them.
2. Serve Streamable HTTP at /mcp in stateless mode, listening on 127.0.0.1 by
   default (HOST environment variable to change it).
3. Before any MCP handling, verify the JWT in the X-NetBird-Identity header on
   every HTTP request with a maintained JWT library (Python: PyJWT with
   cryptography):
   - accept only the EdDSA algorithm (Ed25519)
   - key from NETBIRD_JWKS_URL (JWKS) or NETBIRD_PUBLIC_KEY_PEM (PEM text or
     file path); refuse to start if neither is set or NETBIRD_AUDIENCE is
     missing
   - aud must equal NETBIRD_AUDIENCE; iss must equal "https://" +
     NETBIRD_AUDIENCE; require exp, nbf, iat and sub; max 10 seconds skew
   Missing or invalid token: HTTP 401 with a JSON body. Never skip this check.
4. tools/list returns only tools whose name matches at least one pattern in
   the token's mcp_tools claim. Matching: "*" matches any run of characters
   (including none), every other character matches itself, the whole name
   must match, case-sensitive. A missing or empty claim means no tools.
5. tools/call checks the same rule again and returns an MCP tool error when
   the tool is not allowed.
6. Read the caller from the verified claims on each request (tokens live 60
   seconds). Do not cache identity in the MCP session. Record who created or
   changed things using sub, and email when present.
7. Never log the token.
For Python, use FastMCP: an ASGI middleware passed to mcp.http_app() for step
3, and a FastMCP Middleware with on_list_tools and on_call_tool for steps 4
and 5.

Add tests: no token -> 401; expired token -> 401; a token with mcp_tools
["list_*"] sees only list_ tools and gets an error calling any other tool.
```

### Review before going live

```text
Review this app for running behind the NetBird reverse proxy. Do not change
code; report findings as a list with file and line:
- every place that decides who the user is, and whether it uses only the
  X-NetBird-* headers or the verified X-NetBird-Identity JWT
- leftover login, signup or session code, default accounts, debug or test
  routes that skip the identity check
- every route that creates, changes or deletes data, and whether it checks a
  role on the server
- whether the server listens on 127.0.0.1 or a private address, and any
  Dockerfile, compose file or platform config that publishes it to the
  internet
- any logging of request headers, cookies or tokens
```

## Checklist before going live

- [ ] The app is not reachable except through NetBird: it listens on
      `127.0.0.1` or a private network, has no published ports, and no cloud
      firewall or security group opens it to the internet.
- [ ] If NetBird reaches the app through a routing peer and a network
      resource, the access policy for that resource allows the reverse proxy
      only, not your users' peers. A peer that can reach the app directly can
      send any header it likes.
- [ ] On a shared Docker host, remember that anyone with a shell on the host
      can reach container IPs. Use JWT mode if that matters.
- [ ] Old login, signup and password code and default accounts are deleted.
- [ ] Every destructive route checks a role on the server.
- [ ] Tested with `dev/`: no identity gives 401, the wrong role gives 403.
- [ ] JWT mode: the key and `NETBIRD_AUDIENCE` are set, and an expired token
      is rejected (`dev/mint_token.py token --ttl -30 ...`).
- [ ] MCP: `tools/list` is filtered, enforcement is on in the dashboard, and
      the role patterns match your real tool names.
- [ ] Logs do not contain tokens, API keys or full request headers.
- [ ] Production uses the service's public key from NetBird, not the key in
      `dev/keys/`.
- [ ] You know who is in each group you mapped to a role.

## Set it up in the dashboard

1. **Create the service.** Reverse proxy, Services, add a service. Pick its
   domain (for example `tickets.example.com`) and point the target at your
   app's private address (for example `http://172.30.0.12:8002`, path `/mcp`
   for an MCP server).
2. **Turn on authentication.** In the Authentication tab:
   - **SSO (Single Sign-On)** for people using a browser.
   - **HTTP Headers** for API keys, for scripts and AI agents. Pick a header
     name such as `X-API-Key` and keep the value somewhere safe.
   - **NetBird-Only Access** if callers are NetBird peers.
3. **Roles & authorization.** Add roles and map groups to them, for example:

   | Role | Groups | MCP tools |
   | --- | --- | --- |
   | `admin` | `ops` | `*` |
   | `viewer` | `eng` | `list_*`, `get_ticket` |
   | `agent` | | `list_*` |

   Set **API key roles** to `agent` so API key callers get that role. For an
   MCP server, turn on **MCP enforcement**.
4. **Pick how identity is forwarded:** headers, or JWT. For JWT, keep the
   default header `X-NetBird-Identity` unless your framework wants
   `Authorization: Bearer`, then copy the public key PEM or use the JWKS URL
   in your app's settings.
5. Open the service URL, sign in, and check that `whoami` shows what you
   expect.

## Testing locally with dev/

You do not need NetBird running to build and test your app. The tools in
[`dev/`](dev/) need Python 3.10+ and `pip install -r dev/requirements.txt`.

**Fake proxy.** Stands in for NetBird, stamps the identity you choose, and
strips client-sent `X-NetBird-*` headers like the real proxy:

```bash
# your app on 127.0.0.1:8001, headers mode, as the example "viewer" user
python3 dev/fake_proxy.py --upstream http://127.0.0.1:8001 --preset viewer
# open http://127.0.0.1:9000

# JWT mode with MCP enforcement, as the example "admin" user
python3 dev/fake_proxy.py --upstream http://127.0.0.1:8002 --listen 127.0.0.1:9002 \
  --mode jwt --domain tickets.localhost --preset admin --enforce-mcp

# anyone you like
python3 dev/fake_proxy.py --upstream http://127.0.0.1:8003 --sub usr_1 \
  --email me@example.com --groups eng --roles editor
```

Presets: `admin`, `viewer`, `agent` (an API key caller) and `nobody` (signed
in, no roles). In JWT mode the fake proxy serves its JWKS at
`/.well-known/netbird/jwks.json`, just like NetBird, so your app can use
`NETBIRD_JWKS_URL=http://127.0.0.1:9002/.well-known/netbird/jwks.json`.

**Token minter.** Prints the public key and mints tokens to call your app
directly:

```bash
python3 dev/mint_token.py pem      # PEM for NETBIRD_PUBLIC_KEY_PEM (also in dev/keys/public-key.pem)
python3 dev/mint_token.py token --preset viewer --domain tickets.localhost
python3 dev/mint_token.py token --preset admin --domain tickets.localhost --ttl -30  # expired
```

The key is created on first use in `dev/keys/`, which is gitignored. It is a
test key; never deploy it.

**MCP test client.** Runs initialize, `tools/list` and any `tools/call` you ask
for:

```bash
python3 dev/try_mcp.py http://127.0.0.1:9002/mcp --call get_ticket '{"ticket_id": 1}'
python3 dev/try_mcp.py http://127.0.0.1:8002/mcp \
  -H "X-NetBird-Identity: $(python3 dev/mint_token.py token --preset viewer --domain tickets.localhost)"
```

### Run the examples

```bash
# whoami, headers mode
pip install -r whoami/requirements.txt
(cd whoami && NETBIRD_IDENTITY_MODE=headers python3 app.py)        # 127.0.0.1:8001
python3 dev/fake_proxy.py --upstream http://127.0.0.1:8001 --preset admin

# tickets-mcp, JWT mode
pip install -r tickets-mcp/requirements.txt
python3 dev/mint_token.py pem       # creates dev/keys/ on first run
(cd tickets-mcp && NETBIRD_AUDIENCE=tickets.localhost \
  NETBIRD_PUBLIC_KEY_PEM=../dev/keys/public-key.pem python3 server.py)   # 127.0.0.1:8002
python3 dev/fake_proxy.py --upstream http://127.0.0.1:8002 --listen 127.0.0.1:9002 \
  --mode jwt --domain tickets.localhost --preset viewer --enforce-mcp
python3 dev/try_mcp.py http://127.0.0.1:9002/mcp --call delete_ticket '{"ticket_id": 1}'

# everything in Docker, with fake proxies on 127.0.0.1:9001-9003
python3 dev/mint_token.py pem
docker compose --profile dev up --build
```

### Behind your NetBird server

[`docker-compose.netbird.yml`](docker-compose.netbird.yml) runs the three
apps inside the network of a NetBird peer container. They are reachable only
over NetBird and publish no ports on the host.

1. Create a setup key in the NetBird dashboard.
2. `cp .env.netbird.example .env` and fill in `NB_SETUP_KEY`,
   `NB_MANAGEMENT_URL` and the service domains.
3. `docker compose -f docker-compose.netbird.yml up -d --build`
4. In the dashboard, create a service per app and point its target at the
   `app-authz-examples` peer: whoami on port 8001, tickets-mcp on 8002
   (endpoint `/mcp`, JWT mode required), notes-app on 8003.

The domains in `.env` must match the services exactly: JWT mode checks that
the token's audience is the service domain. tickets-mcp fetches the JWKS from
`https://<TICKETS_DOMAIN>/.well-known/netbird/jwks.json` on its first request.

`whoami` and `tickets-mcp` share `netbird_identity.py`, a single-file helper
you can drop into any Python app: `IdentityVerifier.from_env().identify(headers)`
returns the caller or raises `IdentityError`.
