# Service roles and MCP tool authorization: PR stack

Open in order. Each PR targets the branch of the one above it; PR 1 targets `main`.

| # | Branch | Base | Title |
| - | ------ | ---- | ----- |
| 1 | `stack/app-authz-1-middleware` | `main` | [proxy] Add app_authz middleware for service roles and identity forwarding |
| 2 | `stack/app-authz-2-mcp` | `stack/app-authz-1-middleware` | [proxy] Enforce MCP tool permissions in app_authz |
| 3 | `stack/app-authz-3-jwks` | `stack/app-authz-2-mcp` | [proxy] Serve the identity JWKS on each JWT-mode service domain |
| 4 | `stack/app-authz-4-management` | `stack/app-authz-3-jwks` | [management,proxy] Configure service roles and MCP tool authorization |
| 5 | `stack/app-authz-5-mcp-sso` | `stack/app-authz-4-management` | [management,proxy] Let MCP clients sign in to SSO services through the OAuth broker |

---

## PR 1

**Title:** [proxy] Add app_authz middleware for service roles and identity forwarding

```markdown
## Describe your changes

Part 1 of 5 of service roles and MCP tool authorization for reverse proxy services.

Services behind the proxy receive identity as X-NetBird-User and X-NetBird-Groups, but have no notion of roles, so every app ends up mapping group IDs to permissions on its own. The app_authz middleware runs after authentication, resolves the caller's roles from their group IDs (or fixed roles for API key callers), and forwards the identity either as headers (X-NetBird-User-Id, X-NetBird-Roles, X-NetBird-Auth-Method) or as a 60-second EdDSA JWT carrying user, groups, roles and the MCP tool patterns those roles grant. The existing X-NetBird-User and X-NetBird-Groups headers are kept in both modes.

Client-sent copies of every identity header are stripped on each request, and the header policy lets app_authz, and only app_authz, write these names and Authorization. The middleware fails closed: a config that does not validate, or JWT mode without a signing key, does not build, so the target answers 503 instead of forwarding unchecked.

The config model, validation and key derivation live in `proxy/appauthz` so management (PR 4) builds and validates the same config. Nothing produces this middleware until PR 4, so this PR has no behavior change on its own.

## Issue ticket number and link

No ticket yet.

## Stack

<!-- branch-stack -->

### Checklist
- [ ] Is it a bug fix
- [ ] Is a typo/documentation fix
- [x] Is a feature enhancement
- [ ] It is a refactor
- [x] Created tests that fail without the change (if possible)
- [x] I ran and tested this change locally — I did not rely on CI to find out whether it works
- [x] This PR has a single purpose (not a fix + refactor + feature in one)
- [ ] This change is a trivial fix, **OR** it links an issue the NetBird team agreed on beforehand. Changes to the public API, gRPC protocols, functionality behavior, CLI / service flags, or new features always need that agreement first. See [CONTRIBUTING.md](https://github.com/netbirdio/netbird/blob/main/CONTRIBUTING.md#ticket-first-pr-second).

> By submitting this pull request, you confirm that you have read and agree to the terms of the [Contributor License Agreement](https://github.com/netbirdio/netbird/blob/main/CONTRIBUTOR_LICENSE_AGREEMENT.md).

## Documentation
Select exactly one:

- [ ] I added/updated documentation for this change
- [x] Documentation is **not needed** for this change (explain why)

The middleware cannot be configured until PR 4; the feature is documented in PR 5.

### Docs PR URL (required if "docs added" is checked)
Paste the PR link from https://github.com/netbirdio/docs here:

https://github.com/netbirdio/docs/pull/__
```

---

## PR 2

**Title:** [proxy] Enforce MCP tool permissions in app_authz

```markdown
## Describe your changes

Part 2 of 5. Builds on #<PR 1>.

Role checks at the HTTP layer cannot tell one MCP tool from another: every call is a POST to the same path. With `enforce_mcp` on, app_authz parses JSON-RPC POST bodies and stops a `tools/call` for a tool the caller's roles do not grant before it reaches the MCP server. A denied call is answered in protocol, as HTTP 200 with a tool result flagged `isError` and the request id echoed, because MCP clients treat a non-2xx answer to a POST as a transport failure and the model would never learn why. A batch containing a denied call is refused as a whole. Headers mode also sends X-NetBird-MCP-Tools so a server can filter `tools/list` itself.

The check fails closed. A truncated, uncaptured or unparseable body is denied with 403, and so is any body the proxy and the upstream could read differently: duplicate reserved keys, or keys that only fold to one. Folding uses Unicode simple case folding, because encoding/json maps U+017F to "s", so `"paramſ"` would otherwise reach a Go server as `"params"` while the proxy checked the real one. A fuzz test checks that every body the parser accepts names the same tool for the proxy and for an encoding/json upstream.

## Issue ticket number and link

No ticket yet.

## Stack

<!-- branch-stack -->

### Checklist
- [ ] Is it a bug fix
- [ ] Is a typo/documentation fix
- [x] Is a feature enhancement
- [ ] It is a refactor
- [x] Created tests that fail without the change (if possible)
- [x] I ran and tested this change locally — I did not rely on CI to find out whether it works
- [x] This PR has a single purpose (not a fix + refactor + feature in one)
- [ ] This change is a trivial fix, **OR** it links an issue the NetBird team agreed on beforehand. Changes to the public API, gRPC protocols, functionality behavior, CLI / service flags, or new features always need that agreement first. See [CONTRIBUTING.md](https://github.com/netbirdio/netbird/blob/main/CONTRIBUTING.md#ticket-first-pr-second).

> By submitting this pull request, you confirm that you have read and agree to the terms of the [Contributor License Agreement](https://github.com/netbirdio/netbird/blob/main/CONTRIBUTOR_LICENSE_AGREEMENT.md).

## Documentation
Select exactly one:

- [ ] I added/updated documentation for this change
- [x] Documentation is **not needed** for this change (explain why)

Not configurable until PR 4; the feature is documented in PR 5.

### Docs PR URL (required if "docs added" is checked)
Paste the PR link from https://github.com/netbirdio/docs here:

https://github.com/netbirdio/docs/pull/__
```

---

## PR 3

**Title:** [proxy] Serve the identity JWKS on each JWT-mode service domain

```markdown
## Describe your changes

Part 3 of 5. Builds on #<PR 2>.

Upstreams that verify app_authz tokens need the public key, and must be able to fetch it without a NetBird session. The proxy now answers GET and HEAD for `/.well-known/netbird/jwks.json` ahead of authentication on domains whose app_authz middleware signs JWTs, built from the mapping it already receives. Other domains and other methods pass through, so an upstream serving its own file at that path is unaffected.

## Issue ticket number and link

No ticket yet.

## Stack

<!-- branch-stack -->

### Checklist
- [ ] Is it a bug fix
- [ ] Is a typo/documentation fix
- [x] Is a feature enhancement
- [ ] It is a refactor
- [x] Created tests that fail without the change (if possible)
- [x] I ran and tested this change locally — I did not rely on CI to find out whether it works
- [x] This PR has a single purpose (not a fix + refactor + feature in one)
- [ ] This change is a trivial fix, **OR** it links an issue the NetBird team agreed on beforehand. Changes to the public API, gRPC protocols, functionality behavior, CLI / service flags, or new features always need that agreement first. See [CONTRIBUTING.md](https://github.com/netbirdio/netbird/blob/main/CONTRIBUTING.md#ticket-first-pr-second).

> By submitting this pull request, you confirm that you have read and agree to the terms of the [Contributor License Agreement](https://github.com/netbirdio/netbird/blob/main/CONTRIBUTOR_LICENSE_AGREEMENT.md).

## Documentation
Select exactly one:

- [ ] I added/updated documentation for this change
- [x] Documentation is **not needed** for this change (explain why)

Not configurable until PR 4; the feature is documented in PR 5.

### Docs PR URL (required if "docs added" is checked)
Paste the PR link from https://github.com/netbirdio/docs here:

https://github.com/netbirdio/docs/pull/__
```

---

## PR 4

**Title:** [management,proxy] Configure service roles and MCP tool authorization

```markdown
## Describe your changes

Part 4 of 5. Builds on #<PR 3>. This is where the feature becomes configurable.

Adds an `authorization` block to service auth in the REST API: role mappings from group IDs, roles for API key callers, MCP tool allowlists per role, MCP enforcement, and headers or JWT forwarding. It is stored in the existing auth JSON column, so there is no migration. Management attaches the app_authz middleware to every HTTP target when it builds the proxy mapping rather than persisting it, because a service update rebuilds targets from the API. In JWT mode the signing key is derived from the service session key with HKDF, so the session key never leaves management, and the API returns the matching public key and kid.

An older proxy drops unknown middlewares and would forward the service unchecked. Proxies now report `supports_app_authz` (a new capability field, additive), and management holds a mapping that uses app_authz back from any proxy that does not report it. Removals still reach every proxy.

Role groups must exist in the service's account, and deleting a group that a role maps from is refused, like other linked groups. A store test runs every loader that feeds proxy mappings with field encryption on, on SQLite and Postgres, and checks the session key comes back usable.

The OpenAPI and proto changes are additive only; generated code was regenerated with the repository scripts.

## Issue ticket number and link

No ticket yet.

## Stack

<!-- branch-stack -->

### Checklist
- [ ] Is it a bug fix
- [ ] Is a typo/documentation fix
- [x] Is a feature enhancement
- [ ] It is a refactor
- [x] Created tests that fail without the change (if possible)
- [x] I ran and tested this change locally — I did not rely on CI to find out whether it works
- [x] This PR has a single purpose (not a fix + refactor + feature in one)
- [ ] This change is a trivial fix, **OR** it links an issue the NetBird team agreed on beforehand. Changes to the public API, gRPC protocols, functionality behavior, CLI / service flags, or new features always need that agreement first. See [CONTRIBUTING.md](https://github.com/netbirdio/netbird/blob/main/CONTRIBUTING.md#ticket-first-pr-second).

> By submitting this pull request, you confirm that you have read and agree to the terms of the [Contributor License Agreement](https://github.com/netbirdio/netbird/blob/main/CONTRIBUTOR_LICENSE_AGREEMENT.md).

## Documentation
Select exactly one:

- [x] I added/updated documentation for this change
- [ ] Documentation is **not needed** for this change (explain why)

In-repo reference: `docs/service-roles-and-mcp.md` (PR 5).

### Docs PR URL (required if "docs added" is checked)
Paste the PR link from https://github.com/netbirdio/docs here:

https://github.com/netbirdio/docs/pull/__
```

---

## PR 5

**Title:** [management,proxy] Let MCP clients sign in to SSO services through the OAuth broker

```markdown
## Describe your changes

Part 5 of 5. Builds on #<PR 4>.

MCP clients cannot complete the proxy's browser SSO redirect, so an MCP server behind the proxy was only reachable with an API key, which loses the user identity that roles map from. Management already runs an OAuth 2.1 broker for its own MCP endpoint; this lets it serve reverse proxy services too.

For an enabled HTTP service with SSO and roles, the mapping carries the broker's issuer. The proxy then serves RFC 9728 protected resource metadata on the service domain, answers non-browser requests without credentials with a 401 challenge instead of the login redirect, and accepts `Authorization: Bearer` tokens, which are verified like the session cookie and stripped before forwarding.

The broker accepts `https://<service domain>` as the resource when the service qualifies. Registration, consent, the SSO login and refresh rotation are unchanged. For a service the access token is a 15-minute token signed with the service key, with the same account, user status and group checks as a browser login, repeated on every refresh. It carries `use=mcp`, which session cookies never do, so the proxy accepts it only as a bearer token and never as a cookie, and a session cookie is never accepted as a bearer token.

The broker URL comes from `NB_MCP_BASE_URL` or, failing that, the embedded IdP; without either, services do not advertise MCP sign-in. `docs/service-roles-and-mcp.md` describes the whole feature.

The flow was tested end to end on a staging deployment with Claude and an example MCP server before the `use=mcp` separation was added; that change is covered by unit tests.

## Issue ticket number and link

No ticket yet.

## Stack

<!-- branch-stack -->

### Checklist
- [ ] Is it a bug fix
- [ ] Is a typo/documentation fix
- [x] Is a feature enhancement
- [ ] It is a refactor
- [x] Created tests that fail without the change (if possible)
- [x] I ran and tested this change locally — I did not rely on CI to find out whether it works
- [x] This PR has a single purpose (not a fix + refactor + feature in one)
- [ ] This change is a trivial fix, **OR** it links an issue the NetBird team agreed on beforehand. Changes to the public API, gRPC protocols, functionality behavior, CLI / service flags, or new features always need that agreement first. See [CONTRIBUTING.md](https://github.com/netbirdio/netbird/blob/main/CONTRIBUTING.md#ticket-first-pr-second).

> By submitting this pull request, you confirm that you have read and agree to the terms of the [Contributor License Agreement](https://github.com/netbirdio/netbird/blob/main/CONTRIBUTOR_LICENSE_AGREEMENT.md).

## Documentation
Select exactly one:

- [x] I added/updated documentation for this change
- [ ] Documentation is **not needed** for this change (explain why)

In-repo reference: `docs/service-roles-and-mcp.md`. A netbirdio/docs PR is still to be written.

### Docs PR URL (required if "docs added" is checked)
Paste the PR link from https://github.com/netbirdio/docs here:

https://github.com/netbirdio/docs/pull/__
```
