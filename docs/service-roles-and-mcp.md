# Service roles and MCP tool authorization ("Protect that slop")

Hackathon proof of concept, 2026-11-07. Branch `work/peaceful-bardeen-o95esc` in
`test-mls/netbird` and `test-mls/dashboard`.

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

This is a PoC. It touches authentication, the public API and a persisted model, which
`AGENTS.md` lists as high-risk areas: upstreaming it needs a discussion and an agreed
design first.

## Contents

- [How a request flows](#how-a-request-flows)
- [Configuration model](#configuration-model)
- [What the upstream receives](#what-the-upstream-receives)
- [MCP tool enforcement](#mcp-tool-enforcement)
- [MCP clients signing in with SSO](#mcp-clients-signing-in-with-sso)
- [Dashboard](#dashboard)
- [Example apps](#example-apps)
- [PoC images](#poc-images)
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
| JSON with duplicate keys, or `method`/`params`/`name`/`id`/`jsonrpc` keys that differ only in case | HTTP 403. `encoding/json` and upstream decoders could read such a body differently. |
| `GET` (the SSE stream), `initialize`, `tools/list` and other methods | Forwards them |

The proxy does not filter `tools/list` responses. The MCP server does that itself, from
the `mcp_tools` claim or the `X-NetBird-MCP-Tools` header. `examples/app-authz/tickets-mcp`
shows how.

## MCP clients signing in with SSO

The proxy's SSO is a browser redirect ending in a session cookie, which MCP clients
cannot complete. Management already runs an OAuth 2.1 broker for its own `/api/mcp`
endpoint, and it now serves reverse proxy services too.

**Which services.** A service qualifies when it is an enabled HTTP service with SSO and
an authorization block, and management knows its public URL (it does with the embedded
IdP). Its mapping then carries the broker's issuer in the `app_authz` config.

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

`test-mls/dashboard`, same branch:

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

`examples/app-authz/` holds:

| App | Shows |
| --- | --- |
| `whoami/` | The forwarded identity in headers or JWT mode, and a page gated on the `admin` role |
| `tickets-mcp/` | A FastMCP server with no OAuth of its own: verifies the JWT, filters `tools/list` by `mcp_tools`, and re-checks on call |
| `notes-app/` | A typical generated CRUD app moved off its own login, with a delete button gated on the `editor` role |
| `dev/` | A token minter, a fake proxy and an MCP test client, for building apps without a NetBird stack |

`README.md` there is written for people building apps with AI assistants. It covers the
rules an app must follow, headers versus JWT, copy-paste prompts for coding assistants,
and a checklist before going live.

Two compose files:

- `docker-compose.yml`: local development with fake proxies.
- `docker-compose.netbird.yml`: the apps inside the network of a NetBird peer container,
  reachable only over NetBird. Point services at the `app-authz-examples` peer on ports
  8001 (whoami), 8002 (tickets-mcp) and 8003 (notes-app).

## PoC images

`.github/workflows/poc-images.yml`, in both repositories, builds images from `work/**`
branches of a fork and pushes them to the fork's GHCR. They are tagged with the branch,
`sha-<short>` and `poc`, for `linux/amd64` by default, and never published from
`netbirdio`.

| Image | Built from |
| --- | --- |
| `ghcr.io/test-mls/netbird-server` | `combined/Dockerfile.multistage` |
| `ghcr.io/test-mls/reverse-proxy` | `proxy/Dockerfile.multistage` |
| `ghcr.io/test-mls/management` | `management/Dockerfile.multistage` |
| `ghcr.io/test-mls/dashboard` | `docker/Dockerfile` in the dashboard repository |

The names match the self-hosted getting-started setup, so only the registry prefix and
tag change.

## Setting it up

1. **Images.** Deploy the `:poc` images of `netbird-server`, `reverse-proxy` and
   `dashboard`.
2. **MCP sign-in (optional).** Set `NB_MCP_ENABLED=true` on the management (or
   netbird-server) container. With the embedded IdP the broker URL is known and is
   advertised to proxies.
3. **Example apps.** Run them behind NetBird from `examples/app-authz`:

   ```bash
   cp .env.netbird.example .env
   ```

   Fill in the setup key, the management URL and the service domains, then:

   ```bash
   docker compose -f docker-compose.netbird.yml up -d --build
   ```

4. **Create a service.** Point it at the `app-authz-examples` peer. Turn on SSO, open
   "Roles & Authorization", add roles, choose the forwarding mode, and for MCP servers
   turn on "Enforce MCP Tool Permissions" and choose Signed JWT.
5. **Check the stored roles:**

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

**Manual tests.** Each was run on a test deployment except where noted:

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

The step-by-step versions are in `examples/app-authz/README.md`.

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
- **Old proxies.** A proxy without `app_authz` drops the unknown middleware with a
  warning and forwards unchecked. Production needs a capability flag checked before the
  mapping is sent.
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
- MCP sign-in needs management's public URL, which is known only with the embedded IdP.
- The proxy tells MCP clients from browsers by the `Accept` header.
- `X-NetBird-User` and `X-NetBird-Groups` are still sent in JWT mode, by design.
- The dashboard bug that saved the same group on two roles was not reproduced.

## Where the code is

**netbird**

| Area | Files |
| --- | --- |
| Shared config model, validation, key derivation | `proxy/appauthz/` |
| Middleware: roles, MCP enforcement, headers, JWT | `proxy/internal/middleware/builtin/app_authz/` |
| In-protocol MCP denial | `proxy/internal/middleware/decision_mcp.go` |
| Header policy for `app_authz` | `proxy/internal/middleware/headerpolicy.go` |
| JWKS route and MCP issuer extraction | `proxy/jwks.go`, `proxy/server.go` |
| Bearer tokens, metadata, challenge | `proxy/internal/auth/mcp_oauth.go`, `proxy/internal/auth/middleware.go` |
| Service model, validation, mapping | `management/internals/modules/reverseproxy/service/authorization.go`, `service.go` |
| REST API | `shared/management/http/api/openapi.yml`, `types.gen.go` |
| Broker serving services | `management/internals/modules/mcpapi/services.go`, `broker.go`, `templates/consent.html` |
| Service tokens and issuer advertisement | `management/internals/shared/grpc/proxy.go`, `management/internals/server/mcp.go` |
| Examples | `examples/app-authz/` |
| Image workflow | `.github/workflows/poc-images.yml` |

**dashboard**

| Area | Files |
| --- | --- |
| Roles editor and validation | `src/modules/reverse-proxy/auth/AuthRolesModal.tsx`, `authorization.ts` |
| Wiring | `src/modules/reverse-proxy/ReverseProxyModal.tsx`, `table/ReverseProxyAuthCell.tsx`, `src/interfaces/ReverseProxy.ts` |
| Stories and fixtures | `ReverseProxyServices.stories.tsx`, `.storybook/mocks/fixtures/platform-reverse-proxy.ts` |
| Image workflow | `.github/workflows/poc-images.yml` |
