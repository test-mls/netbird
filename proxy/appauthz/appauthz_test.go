package appauthz

import (
	"crypto/ed25519"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testConfig() Config {
	return Config{
		Roles: []Role{
			{Name: "admin", Groups: []string{"grp-ops"}, MCPTools: []string{"*"}},
			{Name: "viewer", Groups: []string{"grp-eng", "grp-ops"}, MCPTools: []string{"list_*", "get_ticket"}},
			{Name: "agent", MCPTools: []string{"list_*"}},
		},
		APIKeyRoles: []string{"agent"},
		Forwarding:  Forwarding{Mode: ForwardHeaders},
	}
}

func TestResolveRoles(t *testing.T) {
	cfg := testConfig()

	assert.Equal(t, []string{"admin", "viewer"}, cfg.ResolveRoles("oidc", []string{"grp-ops"}), "ops member gets every role that lists grp-ops, in config order")
	assert.Equal(t, []string{"viewer"}, cfg.ResolveRoles("oidc", []string{"grp-eng", "grp-other"}), "eng member gets viewer only")
	assert.Empty(t, cfg.ResolveRoles("oidc", []string{"grp-other"}), "unmapped group gets no roles")
	assert.Empty(t, cfg.ResolveRoles("oidc", nil), "no groups means no roles")
	assert.Equal(t, []string{"agent"}, cfg.ResolveRoles("header", nil), "API key callers get api_key_roles")
	assert.Empty(t, cfg.ResolveRoles("password", nil), "password callers have no groups and no key roles")
}

func TestToolAllowed(t *testing.T) {
	cfg := testConfig()

	viewer := cfg.ToolPatterns([]string{"viewer"})
	assert.True(t, ToolAllowed(viewer, "list_tickets"), "glob prefix matches")
	assert.True(t, ToolAllowed(viewer, "get_ticket"), "exact name matches")
	assert.False(t, ToolAllowed(viewer, "delete_ticket"), "unlisted tool is denied")
	assert.False(t, ToolAllowed(viewer, "get_ticket_extra"), "exact pattern does not prefix-match")
	assert.False(t, ToolAllowed(viewer, ""), "empty tool name never matches")

	admin := cfg.ToolPatterns([]string{"admin"})
	assert.True(t, ToolAllowed(admin, "delete_ticket"), "star allows everything")

	assert.False(t, ToolAllowed(cfg.ToolPatterns(nil), "list_tickets"), "no roles allows nothing")
}

func TestGlobMatch(t *testing.T) {
	cases := []struct {
		pattern, name string
		want          bool
	}{
		{"*", "", true},
		{"a*c", "abc", true},
		{"a*c", "ac", true},
		{"a*c", "abd", false},
		{"*_ticket", "get_ticket", true},
		{"git/*/read", "git/repo/read", true},
		{"git/*/read", "git/repo/write", false},
		{"a*b*c", "aXbYc", true},
		{"a*b*c", "aXcYb", false},
	}
	for _, c := range cases {
		assert.Equal(t, c.want, globMatch(c.pattern, c.name), "globMatch(%q, %q)", c.pattern, c.name)
	}
}

func TestValidate(t *testing.T) {
	cfg := testConfig()
	require.NoError(t, cfg.Validate())

	bad := testConfig()
	bad.Roles = append(bad.Roles, Role{Name: "admin"})
	assert.ErrorContains(t, bad.Validate(), "duplicate role")

	bad = testConfig()
	bad.Roles[0].Name = "admin,viewer"
	assert.ErrorContains(t, bad.Validate(), "invalid role name", "commas would break the roles header")

	bad = testConfig()
	bad.APIKeyRoles = []string{"ghost"}
	assert.ErrorContains(t, bad.Validate(), "not a defined role")

	bad = testConfig()
	bad.Roles[0].MCPTools = []string{"bad tool"}
	assert.ErrorContains(t, bad.Validate(), "invalid MCP tool pattern")

	bad = testConfig()
	bad.Forwarding = Forwarding{Mode: "carrier-pigeon"}
	assert.ErrorContains(t, bad.Validate(), "unknown forwarding mode")

	bad = testConfig()
	bad.Forwarding = Forwarding{Mode: ForwardJWT, Header: "Cookie"}
	assert.ErrorContains(t, bad.Validate(), "jwt header must be")

	ok := testConfig()
	ok.Forwarding = Forwarding{Mode: ForwardJWT, Header: HeaderAuthorize}
	assert.NoError(t, ok.Validate())
}

func TestDeriveSigningKey(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	sessionKey := base64.StdEncoding.EncodeToString(priv)

	k1, err := DeriveSigningKey(sessionKey)
	require.NoError(t, err)
	k2, err := DeriveSigningKey(sessionKey)
	require.NoError(t, err)

	assert.Equal(t, k1, k2, "derivation must be deterministic so every proxy replica signs with the same key")
	assert.NotEqual(t, pub, k1.Public(), "derived key must differ from the session key")

	decoded, err := DecodeSeed(EncodeSeed(k1))
	require.NoError(t, err)
	assert.Equal(t, k1, decoded, "seed round-trips")

	_, err = DeriveSigningKey("not base64!")
	assert.Error(t, err)
	_, err = DeriveSigningKey(base64.StdEncoding.EncodeToString([]byte("encrypted-looking-value")))
	assert.Error(t, err, "a value that is not a raw Ed25519 key must be rejected")
}

func TestPublicKeyEncodings(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	pemStr, err := PublicKeyPEM(pub)
	require.NoError(t, err)
	assert.Contains(t, pemStr, "BEGIN PUBLIC KEY")

	jwk := PublicJWK(pub)
	assert.Equal(t, "OKP", jwk.Kty)
	assert.Equal(t, KeyID(pub), jwk.Kid)
	raw, err := base64.RawURLEncoding.DecodeString(jwk.X)
	require.NoError(t, err)
	assert.Equal(t, []byte(pub), raw, "JWK x is the raw public key")
}
