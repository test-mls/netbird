package app_authz

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/proxy/appauthz"
	"github.com/netbirdio/netbird/proxy/internal/middleware"
)

func baseConfig() appauthz.Config {
	return appauthz.Config{
		Roles: []appauthz.Role{
			{Name: "admin", Groups: []string{"grp-ops"}, MCPTools: []string{"*"}},
			{Name: "viewer", Groups: []string{"grp-eng"}, MCPTools: []string{"list_*", "get_ticket"}},
			{Name: "agent", MCPTools: []string{"list_*"}},
		},
		APIKeyRoles: []string{"agent"},
		EnforceMCP:  true,
		Forwarding:  appauthz.Forwarding{Mode: appauthz.ForwardHeaders},
	}
}

func build(t *testing.T, cfg appauthz.Config) middleware.Middleware {
	t.Helper()
	raw, err := json.Marshal(cfg)
	require.NoError(t, err)
	m, err := Factory{}.New(raw)
	require.NoError(t, err)
	return m
}

func toolCallBody(tool string) []byte {
	return []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"` + tool + `","arguments":{}}}`)
}

func postInput(userID, method string, groups []string, body []byte) *middleware.Input {
	return &middleware.Input{
		Method:     http.MethodPost,
		Headers:    []middleware.KV{{Key: "Content-Type", Value: "application/json"}},
		Body:       body,
		UserID:     userID,
		UserEmail:  userID + "@acme.io",
		AuthMethod: method,
		UserGroups: groups,
	}
}

func headerValue(kvs []middleware.KV, name string) string {
	for _, kv := range kvs {
		if strings.EqualFold(kv.Key, name) {
			return kv.Value
		}
	}
	return ""
}

func TestToolCallDecisions(t *testing.T) {
	m := build(t, baseConfig())

	cases := []struct {
		name   string
		in     *middleware.Input
		allow  bool
		reason string
	}{
		{"admin may call anything", postInput("alice", "oidc", []string{"grp-ops"}, toolCallBody("delete_ticket")), true, ""},
		{"viewer may list", postInput("bob", "oidc", []string{"grp-eng"}, toolCallBody("list_tickets")), true, ""},
		{"viewer may not delete", postInput("bob", "oidc", []string{"grp-eng"}, toolCallBody("delete_ticket")), false, denyCodeToolForbidden},
		{"unmapped group gets nothing", postInput("eve", "oidc", []string{"grp-other"}, toolCallBody("list_tickets")), false, denyCodeToolForbidden},
		{"api key may list", postInput("header-user", "header", nil, toolCallBody("list_tickets")), true, ""},
		{"api key may not create", postInput("header-user", "header", nil, toolCallBody("create_ticket")), false, denyCodeToolForbidden},
		{"anonymous caller is denied a call", postInput("", "", nil, toolCallBody("list_tickets")), false, denyCodeToolForbidden},
		{"tools/list passes", postInput("bob", "oidc", []string{"grp-eng"}, []byte(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)), true, ""},
		{"initialize passes", postInput("bob", "oidc", []string{"grp-eng"}, []byte(`{"jsonrpc":"2.0","id":0,"method":"initialize","params":{}}`)), true, ""},
		{"batch with one forbidden call is denied", postInput("bob", "oidc", []string{"grp-eng"},
			[]byte(`[`+string(toolCallBody("list_tickets"))+`,`+string(toolCallBody("delete_ticket"))+`]`)), false, denyCodeToolForbidden},
		{"call without a name is denied", postInput("alice", "oidc", []string{"grp-eng"}, []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{}}`)), false, denyCodeToolForbidden},
		{"unparseable body is denied", postInput("alice", "oidc", []string{"grp-ops"}, []byte(`{"method":`)), false, denyCodeUninspectable},
		{"case-variant name key is denied", postInput("bob", "oidc", []string{"grp-eng"},
			[]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_tickets","Name":"delete_ticket"}}`)), false, denyCodeUninspectable},
		{"case-variant method key is denied", postInput("bob", "oidc", []string{"grp-eng"},
			[]byte(`{"jsonrpc":"2.0","id":1,"Method":"tools/call","params":{"name":"delete_ticket"}}`)), false, denyCodeUninspectable},
		{"duplicate method key is denied", postInput("bob", "oidc", []string{"grp-eng"},
			[]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list","method":"tools/call","params":{"name":"delete_ticket"}}`)), false, denyCodeUninspectable},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out, err := m.Invoke(context.Background(), c.in)
			require.NoError(t, err)
			if c.allow {
				assert.Equal(t, middleware.DecisionAllow, out.Decision, "expected allow")
				return
			}
			require.Equal(t, middleware.DecisionDeny, out.Decision, "expected deny")
			assert.Equal(t, http.StatusForbidden, out.DenyStatus, "deny status")
			assert.Equal(t, c.reason, out.DenyReason.Code, "deny code")
		})
	}
}

func TestUninspectableBodies(t *testing.T) {
	m := build(t, baseConfig())

	truncated := postInput("alice", "oidc", []string{"grp-ops"}, toolCallBody("list_tickets"))
	truncated.BodyTruncated = true
	out, err := m.Invoke(context.Background(), truncated)
	require.NoError(t, err)
	assert.Equal(t, middleware.DecisionDeny, out.Decision, "a truncated body cannot be authorized")

	// The body was not captured (wrong content type, over the cap, or no
	// capture budget) but the request has one.
	uncaptured := postInput("alice", "oidc", []string{"grp-ops"}, nil)
	uncaptured.Headers = []middleware.KV{{Key: "Content-Length", Value: "512"}}
	out, err = m.Invoke(context.Background(), uncaptured)
	require.NoError(t, err)
	assert.Equal(t, middleware.DecisionDeny, out.Decision, "an uncaptured body cannot be authorized")

	empty := postInput("alice", "oidc", []string{"grp-ops"}, nil)
	empty.Headers = []middleware.KV{{Key: "Content-Length", Value: "0"}}
	out, err = m.Invoke(context.Background(), empty)
	require.NoError(t, err)
	assert.Equal(t, middleware.DecisionAllow, out.Decision, "an empty POST carries no tool call")

	get := &middleware.Input{Method: http.MethodGet, UserID: "alice", AuthMethod: "oidc", UserGroups: []string{"grp-ops"}}
	out, err = m.Invoke(context.Background(), get)
	require.NoError(t, err)
	assert.Equal(t, middleware.DecisionAllow, out.Decision, "GET opens the SSE stream and carries no body")
}

func TestEnforcementOff(t *testing.T) {
	cfg := baseConfig()
	cfg.EnforceMCP = false
	m := build(t, cfg)

	out, err := m.Invoke(context.Background(), postInput("bob", "oidc", []string{"grp-eng"}, toolCallBody("delete_ticket")))
	require.NoError(t, err)
	assert.Equal(t, middleware.DecisionAllow, out.Decision, "with enforcement off the upstream decides")
}

func TestHeadersMode(t *testing.T) {
	m := build(t, baseConfig())

	out, err := m.Invoke(context.Background(), postInput("alice", "oidc", []string{"grp-ops", "grp-eng"}, toolCallBody("list_tickets")))
	require.NoError(t, err)
	require.NotNil(t, out.Mutations)

	assert.Equal(t, "alice", headerValue(out.Mutations.HeadersAdd, appauthz.HeaderUserID), "user id header")
	assert.Equal(t, "admin,viewer", headerValue(out.Mutations.HeadersAdd, appauthz.HeaderRoles), "roles header")
	assert.Equal(t, "oidc", headerValue(out.Mutations.HeadersAdd, appauthz.HeaderAuthMethod), "auth method header")
	assert.Subset(t, out.Mutations.HeadersRemove,
		[]string{appauthz.HeaderUserID, appauthz.HeaderRoles, appauthz.HeaderAuthMethod, appauthz.HeaderIdentity},
		"client-sent identity headers must be stripped")

	// Every header the middleware writes must pass the framework's header
	// policy, otherwise the chain would silently drop it.
	add, remove, blocked := middleware.FilterHeaderMutationsFor(out.Mutations, ID)
	assert.Empty(t, blocked, "no app_authz header may be blocked")
	assert.Len(t, add, len(out.Mutations.HeadersAdd), "all adds survive the policy")
	assert.Len(t, remove, len(out.Mutations.HeadersRemove), "all removes survive the policy")
}

func TestAnonymousGetsStripOnly(t *testing.T) {
	cfg := baseConfig()
	cfg.EnforceMCP = false
	m := build(t, cfg)

	out, err := m.Invoke(context.Background(), &middleware.Input{Method: http.MethodGet})
	require.NoError(t, err)
	assert.Empty(t, out.Mutations.HeadersAdd, "nothing is stamped without a user")
	assert.Contains(t, out.Mutations.HeadersRemove, appauthz.HeaderRoles, "spoofed roles are still stripped")
}

func jwtConfig(t *testing.T, header string) (appauthz.Config, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	cfg := baseConfig()
	cfg.Forwarding = appauthz.Forwarding{
		Mode:       appauthz.ForwardJWT,
		Header:     header,
		Issuer:     "https://tickets.acme.io",
		Audience:   "tickets.acme.io",
		SigningKey: appauthz.EncodeSeed(priv),
	}
	return cfg, pub
}

func TestJWTMode(t *testing.T) {
	cfg, pub := jwtConfig(t, "")
	m := build(t, cfg)

	in := postInput("alice", "oidc", []string{"grp-ops"}, toolCallBody("delete_ticket"))
	in.UserGroupNames = []string{"ops"}
	out, err := m.Invoke(context.Background(), in)
	require.NoError(t, err)
	require.Equal(t, middleware.DecisionAllow, out.Decision)

	raw := headerValue(out.Mutations.HeadersAdd, appauthz.HeaderIdentity)
	require.NotEmpty(t, raw, "token goes in X-NetBird-Identity by default")
	assert.Empty(t, headerValue(out.Mutations.HeadersAdd, appauthz.HeaderRoles), "jwt mode does not add the roles header")

	var c claims
	tok, err := jwt.ParseWithClaims(raw, &c, func(*jwt.Token) (any, error) { return pub, nil },
		jwt.WithValidMethods([]string{"EdDSA"}),
		jwt.WithAudience("tickets.acme.io"),
		jwt.WithIssuer("https://tickets.acme.io"),
		jwt.WithExpirationRequired(),
	)
	require.NoError(t, err, "token must verify with the service public key")
	assert.True(t, tok.Valid)
	assert.Equal(t, appauthz.KeyID(pub), tok.Header["kid"], "kid identifies the key")
	assert.Equal(t, "alice", c.Subject)
	assert.Equal(t, "alice@acme.io", c.Email)
	assert.Equal(t, []string{"ops"}, c.Groups, "groups carry display names")
	assert.Equal(t, []string{"admin"}, c.Roles)
	assert.Equal(t, []string{"*"}, c.MCPTools)
	assert.Equal(t, "oidc", c.AuthMethod)
	assert.NotEmpty(t, c.ID, "jti is set")
	assert.Equal(t, tokenLifetime, c.ExpiresAt.Sub(c.IssuedAt.Time), "token lifetime")

	_, err = jwt.ParseWithClaims(raw, &claims{}, func(*jwt.Token) (any, error) { return pub, nil },
		jwt.WithValidMethods([]string{"EdDSA"}), jwt.WithAudience("other.acme.io"))
	assert.Error(t, err, "token is bound to the service audience")
}

func TestJWTInAuthorizationHeader(t *testing.T) {
	cfg, _ := jwtConfig(t, appauthz.HeaderAuthorize)
	m := build(t, cfg)

	out, err := m.Invoke(context.Background(), postInput("alice", "oidc", []string{"grp-ops"}, toolCallBody("list_tickets")))
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(headerValue(out.Mutations.HeadersAdd, appauthz.HeaderAuthorize), "Bearer "), "bearer prefix")
	assert.Contains(t, out.Mutations.HeadersRemove, appauthz.HeaderAuthorize, "the client's Authorization is replaced")

	_, _, blocked := middleware.FilterHeaderMutationsFor(out.Mutations, ID)
	assert.Empty(t, blocked, "Authorization is allowed for app_authz")
	_, _, blocked = middleware.FilterHeaderMutationsFor(out.Mutations, "some_other_middleware")
	assert.Contains(t, blocked, appauthz.HeaderAuthorize, "other middlewares still may not touch Authorization")
}

func TestFactoryRejectsBadConfig(t *testing.T) {
	_, err := Factory{}.New([]byte(`{`))
	assert.Error(t, err, "malformed JSON")

	_, err = Factory{}.New([]byte(`{"forwarding":{"mode":"jwt"}}`))
	assert.ErrorContains(t, err, "signing key", "jwt mode without a key must not build")

	_, err = Factory{}.New([]byte(`{"forwarding":{"mode":"nope"}}`))
	assert.Error(t, err, "unknown mode")

	_, err = Factory{}.New([]byte(`{}`))
	assert.Error(t, err, "an empty config has no forwarding mode and must not build")
}
