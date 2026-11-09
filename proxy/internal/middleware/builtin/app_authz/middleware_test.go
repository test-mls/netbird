package app_authz

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
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

func getInput(userID, method string, groups []string) *middleware.Input {
	return &middleware.Input{
		Method:     http.MethodGet,
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

func TestHeadersMode(t *testing.T) {
	m := build(t, baseConfig())

	out, err := m.Invoke(context.Background(), getInput("alice", "oidc", []string{"grp-ops", "grp-eng"}))
	require.NoError(t, err)
	require.Equal(t, middleware.DecisionAllow, out.Decision)
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

func TestRolesPerCaller(t *testing.T) {
	m := build(t, baseConfig())
	cases := []struct {
		name  string
		in    *middleware.Input
		roles string
	}{
		{"eng member is viewer", getInput("bob", "oidc", []string{"grp-eng"}), "viewer"},
		{"unmapped group has no roles", getInput("eve", "oidc", []string{"grp-other"}), ""},
		{"api key caller gets api_key_roles", getInput("header-user", "header", nil), "agent"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out, err := m.Invoke(context.Background(), c.in)
			require.NoError(t, err)
			assert.Equal(t, c.roles, headerValue(out.Mutations.HeadersAdd, appauthz.HeaderRoles))
		})
	}
}

func TestAnonymousGetsStripOnly(t *testing.T) {
	m := build(t, baseConfig())

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

	in := getInput("alice", "oidc", []string{"grp-ops"})
	in.UserGroupNames = []string{"ops"}
	out, err := m.Invoke(context.Background(), in)
	require.NoError(t, err)

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

func TestJWTAudienceIsAString(t *testing.T) {
	cfg, _ := jwtConfig(t, "")
	m := build(t, cfg)

	out, err := m.Invoke(context.Background(), getInput("alice", "oidc", []string{"grp-ops"}))
	require.NoError(t, err)
	parts := strings.Split(headerValue(out.Mutations.HeadersAdd, appauthz.HeaderIdentity), ".")
	require.Len(t, parts, 3)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	var generic map[string]any
	require.NoError(t, json.Unmarshal(payload, &generic))
	assert.Equal(t, "tickets.acme.io", generic["aud"], "aud is a plain string, not an array")
}

func TestJWTInAuthorizationHeader(t *testing.T) {
	cfg, _ := jwtConfig(t, appauthz.HeaderAuthorize)
	m := build(t, cfg)

	out, err := m.Invoke(context.Background(), getInput("alice", "oidc", []string{"grp-ops"}))
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
