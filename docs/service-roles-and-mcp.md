# Service roles and MCP tool authorization ("Protect that slop")

Started as a hackathon proof of concept on 2026-11-07, and hardened for review as a
stack of pull requests.

Internal apps and MCP servers get built fast, and authentication is the part that
gets skipped or hand-rolled. This work turns the NetBird reverse proxy into the
place that answers three questions for any service behind it:

1. **Who is calling?** SSO, an API key, or a NetBird peer, as before.
2. **Which roles do they have?** Mapped per service from NetBird groups.
3. **Which MCP tools may they call?** Enforced by the proxy on every `tools/call`.

The app behind the proxy receives the answer as headers or as a short-lived signed
JWT, and no longer needs its own login, user table or OAuth server. MCP clients such
as Claude Code sign in with SSO through management's OAuth 2.1 broker, with nothing
configured on the client but the URL.

## Contents

- [How a request flows](#how-a-request-flows)
- [Configuration model](#configuration-model)
- [What the upstream receives](#what-the-upstream-receives)
- [MCP tool enforcement](#mcp-tool-enforcement)
- [MCP clients signing in with SSO](#mcp-clients-signing-in-with-sso)
- [Dashboard](#dashboard)
- [Example apps](#example-apps)
- [Setting it up](#setting-it-up)
- [Testing](#testing)
- [Troubleshooting](#troubleshooting)
- [Security notes](#security-notes)
- [Known limitations and follow-ups](#known-limitations-and-follow-ups)
- [Where the code is](#where-the-code-is)

## How a request flows

```text
client ──► proxy auth ──────────► app_authz middleware ─────────────► upstream app
           (exists)                (new)
           SSO cookie              resolve roles from group IDs        reads headers or
           Bearer token (new)      on tools/call: allow or deny        verifies the JWT
           API key header          strip spoofed X-NetBird-* headers   (JWKS on the
           NetBird peer            stamp headers or sign a 60s JWT      service domain)
```

- Authentication is unchanged except for one new path: an `Authorization: Bearer`
  token minted by the MCP broker (see [below](#mcp-clients-signing-in-with-sso)).
- Everything else is one new per-target middleware, `app_authz`, built on the existing
  middleware chain. Management attaches it to every HTTP target of a service that has an
  authorization block, when it builds the proxy mapping. It is never stored on targets,
  because a service update rebuilds targets from the API.
- The config travels as the middleware's `config_json`, so there is **no proto change
  and no store migration**: the block lives inside the service's existing `auth` JSON
  column.

## Configuration model

`auth.authorization` on a service (`ServiceAuthorizationConfig` in
`shared/management/http/api/openapi.yml`):

```json
"authorization": {
  "roles": [
    { "name": "admin",  "groups": ["<Coders group id>"], "mcp_tools": ["*"] },
    { "name": "viewer", "groups": ["<Users group id>"],  "mcp_tools": ["list_*", "get_ticket"] },
    { "name": "agent",  "mcp_tools": ["list_*"] }
  ],
  "api_key_roles": ["agent"],
  "enforce_mcp": true,
  "forwarding": "jwt",
  "jwt_header": "X-NetBird-Identity",
  "public_key_pem": "<read-only>",
  "key_id": "<read-only>"
}
```

| Field | Meaning |
| --- | --- |
| `roles` | A caller gets every role whose `groups` include one of the caller's group IDs. |
| `mcp_tools` | Tool names or patterns; `*` matches any run of characters. Unlisted tools are denied. |
| `api_key_roles` | Roles for callers authenticated with header auth (API keys), which carry no groups. Each must name a role in `roles`. |
| `enforce_mcp` | The proxy denies `tools/call` for tools the caller's roles do not grant. |
| `forwarding` | `headers` or `jwt`. |
| `jwt_header` | `X-NetBird-Identity` (default) or `Authorization`. |
| `public_key_pem`, `key_id` | Returned in JWT mode, never accepted. Upstreams verify the JWT with them. |

Validation (management and dashboard):

- Role names match `^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$` and are unique. A comma would
  break the roles header.
- Tool patterns match `^[A-Za-z0-9_.*/:-]{1,128}$`, with at most four `*`.
- At most 64 roles and 256 patterns per role.
- HTTP services only.
- JWT forwarding in `Authorization` is refused while an enabled header auth checks
  `Authorization`. The proxy strips the header-auth header before forwarding, so the
  token would be lost.
- Every role group must exist in the service's account. Deleting a group a role maps
  from is refused, like other linked groups.

## What the upstream receives

**Headers mode.** The proxy already sent `X-NetBird-User` (email) and
`X-NetBird-Groups` (group names). `app_authz` adds:

| Header | Value |
| --- | --- |
| `X-NetBird-User-Id` | Stable user ID. `header-user` for API key callers. |
| `X-NetBird-Roles` | Roles, comma-separated. Absent when there are none. |
| `X-NetBird-Auth-Method` | `oidc`, `header`, `password` or `pin`. |
| `X-NetBird-MCP-Tools` | Tool patterns the roles allow, comma-separated. Absent when there are none. |

**JWT mode.** An EdDSA (Ed25519) token in `X-NetBird-Identity` or
`Authorization: Bearer`, minted per request and valid for 60 seconds:

```json
{
  "iss": "https://tickets.example.com",
  "aud": "tickets.example.com",
  "sub": "<user id>",
  "email": "alice@example.com",
  "groups": ["Users"],
  "roles": ["viewer"],
  "mcp_tools": ["list_*", "get_ticket"],
  "auth_method": "oidc",
  "jti": "…", "iat": 0, "nbf": 0, "exp": 0
}
```

- `aud` is a single string, not an array.
- The header carries a `kid`.
- `X-NetBird-User` and `X-NetBird-Groups` are still sent in JWT mode, so apps that read
  them keep working. JWT-mode apps should read identity from the verified token only.

**Signing key.** Management derives a separate Ed25519 key from the service's session
key with HKDF (`netbird-upstream-identity-v1`) and sends the seed to the proxy. The
session key itself never leaves management, and a leak of the upstream key cannot forge
proxy sessions. If the key cannot be derived, the middleware is sent without one; the
proxy then refuses to build it and serves the target as unavailable rather than
unchecked.

**JWKS.** The proxy serves `GET /.well-known/netbird/jwks.json` on every JWT-mode
service domain, ahead of authentication. Other domains and methods pass through to the
upstream.

**Anti-spoofing.** `app_authz` removes client-sent `X-NetBird-User-Id`,
`X-NetBird-Roles`, `X-NetBird-Auth-Method`, `X-NetBird-Identity` and
`X-NetBird-MCP-Tools` on every request, before stamping its own. The proxy already
stripped `X-NetBird-User` and `X-NetBird-Groups`. The middleware framework's header
policy blocks these names for every other middleware.

## MCP tool enforcement

With `enforce_mcp` on, management makes the target capture JSON request bodies (up to
256 KiB), and `app_authz` parses every POST as JSON-RPC.

| Request | Proxy does |
| --- | --- |
| `tools/call` for a tool the roles allow | Forwards it |
| `tools/call` for any other tool, or one with no name | Answers in protocol: HTTP 200 with a tool result flagged `isError`, saying "NetBird denied this tool call: your roles do not allow the MCP tool …". The upstream never sees it. |
| A batch with any denied call | Denies the whole batch: denied calls get the tool error, the others a JSON-RPC error |
| A truncated, uncaptured or unparseable body | HTTP 403 (fails closed) |
| JSON with duplicate `method`/`params`/`name`/`id`/`jsonrpc` keys, or keys that only fold to one (such as `Method`, or `paramſ` with U+017F) | HTTP 403. `encoding/json` and other upstream decoders could read such a body differently. A fuzz test checks that every body the parser accepts names the same tool for the proxy and for an `encoding/json` upstream. |
| `GET` (the SSE stream), `initialize`, `tools/list` and other methods | Forwards them |

The proxy does not filter `tools/list` responses. The MCP server does that itself, from
the `mcp_tools` claim or the `X-NetBird-MCP-Tools` header.

## MCP clients signing in with SSO

The proxy's SSO is a browser redirect ending in a session cookie, which MCP clients
cannot complete. Management already runs an OAuth 2.1 broker for its own `/api/mcp`
endpoint, and it now serves reverse proxy services too.

**Which services.** A service qualifies when it is an enabled HTTP service with SSO and
an authorization block, and management knows its public URL: from `NB_MCP_BASE_URL`, or
from the embedded IdP. Its mapping then carries the broker's issuer in the `app_authz`
config.

**Proxy, for a qualifying domain:**

- **Metadata.** Serves `/.well-known/oauth-protected-resource` (and the same path with a
  suffix) after IP restrictions. `resource` is `https://<domain>` and
  `authorization_servers` names the broker.
- **Challenge.** Answers a request with no credentials, or with a bearer token that does
  not verify, with `401` and `WWW-Authenticate: Bearer resource_metadata="…"`, unless
  its `Accept` header includes `text/html`. Browsers still get the SSO redirect.
- **Bearer tokens.** Accepts `Authorization: Bearer <token>` and verifies it like the
  session cookie: signature with the service key, audience, expiry, SSO method and
  allowed groups. It removes the header before forwarding. A token that does not verify
  is left for header auth, which may also use `Authorization`.
- **Token types stay apart.** Broker tokens carry `use: "mcp"` and session cookies carry
  no use claim. The proxy accepts each only where it belongs, so an MCP access token
  never opens a browser session and a session cookie is never a bearer token.

**Broker:**

- **Resource.** `authorize` accepts `resource=https://<domain>/<any path>` when the
  proxy service reports that the domain qualifies. It stores the resource as
  `https://<domain>`, and the code and refresh token stay bound to it.
- **Consent page.** Names the service. Read and write scopes do not apply to services.
- **Access token.** For a service it is not sealed: it is a session token signed with
  the service key by `IssueServiceToken`, the same account, user status and group checks
  as a browser login (`GenerateSessionToken`), valid for 15 minutes.
- **Refresh.** Rotation, replay detection and revocation are unchanged, and each refresh
  checks the user and groups again.
- **Separation.** A service token is never accepted on `/api/mcp`, and a management
  token is never accepted by a service.

**Client setup:**

```bash
claude mcp add --transport http tickets https://tickets.example.com/mcp
```

Run `/mcp`, pick the server, authenticate, approve on the NetBird consent page and log
in with SSO.

## Dashboard

In the dashboard repository, as a separate change:

- **Where it is:** a "Roles & Authorization" card in a service's Authentication tab, for
  HTTP services that are not NetBird-only.
- **What it edits:**
  - role rows: name, groups and MCP tools;
  - API key roles, shown when header auth is on;
  - "Enforce MCP Tool Permissions";
  - Identity Forwarding: Headers or Signed JWT, and the JWT header.
- **For a saved JWT service:** the JWKS URL and public key with copy buttons, and a
  preview of what the upstream receives.
- **Validation** mirrors the server's.
- **Groups** typed into a role are created on save.
- **Services table:** the auth hover lists the roles.

## Example apps

Example upstreams (a whoami page, an MCP server that verifies the JWT and filters
`tools/list` by `mcp_tools`, and a CRUD app moved off its own login), together with
copy-paste prompts for people building apps with AI assistants, are kept outside this
repository.

## Setting it up

1. **Deploy** management and a reverse proxy built from this change, and a dashboard with
   the Roles & Authorization editor.
2. **MCP sign-in (optional).** Set `NB_MCP_ENABLED=true` on management. With the
   embedded IdP the broker URL is known; otherwise also set `NB_MCP_BASE_URL` to
   management's public URL, such as `https://netbird.example.com`.
3. **Create a service** with an HTTP target. Turn on SSO, open "Roles & Authorization",
   add roles, choose the forwarding mode, and for MCP servers turn on "Enforce MCP Tool
   Permissions" and choose Signed JWT.
4. **Check the stored roles:**

   ```bash
   curl -s -H "Authorization: Token $NB_PAT" https://<management>/api/reverse-proxies/services | jq '.[] | {domain, roles: .auth.authorization.roles}'
   ```

## Testing

**Unit tests:**

```bash
go test -race ./proxy/appauthz/ ./proxy/internal/middleware/... ./proxy/internal/auth/ ./proxy/
```

```bash
go test ./management/internals/modules/reverseproxy/service/ ./management/internals/modules/mcpapi/ ./management/internals/shared/grpc/
```

**Manual tests.** Run on a test deployment during the proof of concept:

| Test | Expected |
| --- | --- |
| whoami, headers mode, Users / Coders member | Roles `viewer` / `admin`; `/admin` 403 / 200 |
| whoami, JWT mode | Same roles, claims verified, `aud` a string |
| tickets-mcp via Claude Code, SSO, Users member | Lists only `list_tickets` and `get_ticket` |
| `delete_ticket` called directly as a Users member | "NetBird denied this tool call"; the upstream never sees it |
| tickets-mcp, Coders member | All four tools, delete works |
| tickets-mcp with an API key and `api_key_roles: [agent]` | Only `list_*`; other calls denied; a wrong key gets 401 |
| Forged `X-NetBird-*` headers or a fake `X-NetBird-Identity` | Ignored; the real identity is shown |
| User removed from the SSO groups | Refresh refused within 15 minutes; signing in again is refused |


## Troubleshooting

| Symptom | Cause and fix |
| --- | --- |
| A role is granted to the wrong group | Check the stored roles with the `curl` above. Once, the dashboard saved the same group on two roles; re-saving fixed it and the cause was not found. |
| `/.well-known/oauth-protected-resource` returns a login page | The service has no roles or no SSO, the proxy runs an old image, or `NB_MCP_ENABLED` is not set. Re-save the service after changing any of these. |
| MCP client gets new credentials, then times out | The proxy cannot reach the target peer. With the apps in Docker Desktop on a laptop, the tunnel between the proxy and the container did not come up (`netbird status -d` showed `0/3 Connected`). |
| tickets-mcp answers 401 after sign-in | `NETBIRD_AUDIENCE` differs from the service domain, or the JWT header differs between the dashboard and the app. |

**Proxy debugging.** Set these on the proxy container:

```yaml
NB_PROXY_LOG_LEVEL: debug
NB_PROXY_DEBUG_ENDPOINT: "true"
NB_PROXY_DEBUG_ENDPOINT_ADDRESS: localhost:8444
NB_PROXY_MAX_DIAL_TIMEOUT: 10s
```

Then:

```bash
docker compose exec proxy /usr/bin/netbird-proxy debug clients
```

```bash
docker compose exec proxy /usr/bin/netbird-proxy debug status <account-id>
```

```bash
docker compose exec proxy /usr/bin/netbird-proxy debug ping <account-id> <peer NetBird IP> <port>
```

## Security notes

- **Fail closed.** Every deny path refuses rather than forwards:
  - a malformed or keyless `app_authz` config does not build, and the target answers 503;
  - a body the MCP check cannot read is denied;
  - the middleware runs with fail mode closed;
  - an unparseable or unknown issuer leaves MCP sign-in off.
- **Headers mode is only as safe as the network.** Headers can be forged by anything
  that reaches the app without going through the proxy. JWT mode is safe anywhere. The
  example compose file keeps the apps reachable only over NetBird.
- **Revocation lag.** Bearer tokens for services are verified by the proxy alone, so
  revoking a session stops refreshes at once, but an issued access token works for up
  to 15 minutes.
- **Old proxies.** A proxy without `app_authz` would drop the unknown middleware and
  forward unchecked. Proxies report `supports_app_authz`, and management holds a mapping
  that uses `app_authz` back from any proxy that does not, so such a service is not
  served by an old proxy at all.
- **Signing key on the proxy.** The proxy holds a per-service signing key for upstream
  JWTs. It is derived and separate from the session key, but bring-your-own proxies
  should be weighed against this.

## Known limitations and follow-ups

- The proxy does not filter `tools/list`. That needs a response hook like
  `discovery_filter.go`, plus SSE handling.
- Every API key shows up as the same identity, `header-user`. Roles per API key would
  need header auth to report which key matched.
- Tools cannot be discovered from the upstream. The dashboard takes tool names as text.
- A visual groups → roles → tools map in the dashboard.
- The proxy tells MCP clients from browsers by the `Accept` header.
- `X-NetBird-User` and `X-NetBird-Groups` are still sent in JWT mode, by design.
- The dashboard bug that saved the same group on two roles was not reproduced.
- Rotating a service's session key changes the JWT signing key at once. The JWKS should
  publish the old and new keys for an overlap period.
- The MCP body limit (256 KiB) is fixed.

## Where the code is

**netbird**

| Area | Files |
| --- | --- |
| Shared config model, validation, key derivation | `proxy/appauthz/` |
| Capability flag | `shared/management/proto/proxy_service.proto` (`supports_app_authz`), `proxy/server.go`, `proxyAcceptsMapping` in `management/internals/shared/grpc/proxy.go` |
| Role group checks | `management/internals/modules/reverseproxy/service/manager/authorization.go`, `management/server/group.go` |
| Token use claim | `proxy/auth/auth.go`, `management/internals/modules/reverseproxy/sessionkey/` |
| Middleware: roles, MCP enforcement, headers, JWT | `proxy/internal/middleware/builtin/app_authz/` |
| In-protocol MCP denial | `proxy/internal/middleware/decision_mcp.go` |
| Header policy for `app_authz` | `proxy/internal/middleware/headerpolicy.go` |
| JWKS route and MCP issuer extraction | `proxy/jwks.go`, `proxy/server.go` |
| Bearer tokens, metadata, challenge | `proxy/internal/auth/mcp_oauth.go`, `proxy/internal/auth/middleware.go` |
| Service model, validation, mapping | `management/internals/modules/reverseproxy/service/authorization.go`, `service.go` |
| REST API | `shared/management/http/api/openapi.yml`, `types.gen.go` |
| Broker serving services | `management/internals/modules/mcpapi/services.go`, `broker.go`, `templates/consent.html` |
| Service tokens and issuer advertisement | `management/internals/shared/grpc/proxy.go`, `management/internals/server/mcp.go` |

**dashboard**

| Area | Files |
| --- | --- |
| Roles editor and validation | `src/modules/reverse-proxy/auth/AuthRolesModal.tsx`, `authorization.ts` |
| Wiring | `src/modules/reverse-proxy/ReverseProxyModal.tsx`, `table/ReverseProxyAuthCell.tsx`, `src/interfaces/ReverseProxy.ts` |
| Stories and fixtures | `ReverseProxyServices.stories.tsx`, `.storybook/mocks/fixtures/platform-reverse-proxy.ts` |
