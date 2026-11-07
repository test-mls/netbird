package service

import (
	"crypto/ed25519"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/proxy"
	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/sessionkey"
	"github.com/netbirdio/netbird/proxy/appauthz"
	"github.com/netbirdio/netbird/shared/management/http/api"
	"github.com/netbirdio/netbird/shared/management/proto"
)

func authzService(t *testing.T, mode appauthz.ForwardingMode) *Service {
	t.Helper()
	keys, err := sessionkey.GenerateKeyPair()
	require.NoError(t, err)
	s := validProxy()
	s.ID = "svc-1"
	s.Domain = "tickets.acme.io"
	s.SessionPrivateKey = keys.PrivateKey
	s.SessionPublicKey = keys.PublicKey
	s.Auth.BearerAuth = &BearerAuthConfig{Enabled: true, DistributionGroups: []string{"grp-ops", "grp-eng"}}
	s.Auth.Authorization = &AuthorizationConfig{
		Roles: []appauthz.Role{
			{Name: "admin", Groups: []string{"grp-ops"}, MCPTools: []string{"*"}},
			{Name: "viewer", Groups: []string{"grp-eng"}, MCPTools: []string{"list_*"}},
		},
		EnforceMCP: true,
		Forwarding: mode,
	}
	return s
}

func appAuthzFrom(t *testing.T, pm *proto.PathMapping) (*proto.MiddlewareConfig, appauthz.Config) {
	t.Helper()
	require.NotNil(t, pm.Options, "path options must carry the middleware")
	for _, mw := range pm.Options.Middlewares {
		if mw.Id == appauthz.MiddlewareID {
			var cfg appauthz.Config
			require.NoError(t, json.Unmarshal(mw.ConfigJson, &cfg))
			return mw, cfg
		}
	}
	require.Fail(t, "app_authz middleware not found")
	return nil, appauthz.Config{}
}

func TestValidateAuthorization(t *testing.T) {
	s := authzService(t, appauthz.ForwardHeaders)
	require.NoError(t, s.Validate())

	bad := authzService(t, appauthz.ForwardHeaders)
	bad.Auth.Authorization.APIKeyRoles = []string{"ghost"}
	assert.ErrorContains(t, bad.Validate(), "not a defined role")

	bad = authzService(t, "smoke-signals")
	assert.ErrorContains(t, bad.Validate(), "unknown forwarding mode")

	bad = authzService(t, appauthz.ForwardJWT)
	bad.Auth.Authorization.JWTHeader = appauthz.HeaderAuthorize
	bad.Auth.HeaderAuths = []*HeaderAuthConfig{{Enabled: true, Header: "authorization", Value: "Bearer k"}}
	assert.ErrorContains(t, bad.Validate(), "Authorization header",
		"the proxy strips the header-auth header after the chain, so the JWT would be lost")

	l4 := authzService(t, appauthz.ForwardHeaders)
	l4.Mode = ModeTCP
	l4.ListenPort = 5432
	assert.ErrorContains(t, l4.Validate(), "only supported for HTTP")
}

func TestToProtoMapping_AppAuthzHeaders(t *testing.T) {
	s := authzService(t, appauthz.ForwardHeaders)
	s.Targets[0].Options.CaptureContentTypes = []string{"text/plain"}

	m := s.ToProtoMapping(Create, "", proxy.OIDCValidationConfig{})
	require.Len(t, m.Path, 1)

	mw, cfg := appAuthzFrom(t, m.Path[0])
	assert.Same(t, mw, m.Path[0].Options.Middlewares[0], "app_authz runs first in the chain")
	assert.Equal(t, proto.MiddlewareSlot_MIDDLEWARE_SLOT_ON_REQUEST, mw.Slot)
	assert.Equal(t, proto.MiddlewareConfig_FAIL_CLOSED, mw.FailMode, "a security middleware must fail closed")
	assert.True(t, mw.CanMutate, "it stamps headers")
	assert.True(t, mw.Enabled)

	assert.Equal(t, s.Auth.Authorization.Roles, cfg.Roles)
	assert.True(t, cfg.EnforceMCP)
	assert.Empty(t, cfg.Forwarding.SigningKey, "headers mode ships no key")

	assert.Equal(t, appAuthzCaptureBytes, m.Path[0].Options.CaptureMaxRequestBytes, "MCP enforcement needs the body")
	assert.ElementsMatch(t, []string{"text/plain", "application/json"}, m.Path[0].Options.CaptureContentTypes,
		"existing capture types are kept and JSON is added")
}

func TestToProtoMapping_AppAuthzJWT(t *testing.T) {
	s := authzService(t, appauthz.ForwardJWT)

	m := s.ToProtoMapping(Create, "", proxy.OIDCValidationConfig{})
	_, cfg := appAuthzFrom(t, m.Path[0])

	assert.Equal(t, "https://tickets.acme.io", cfg.Forwarding.Issuer)
	assert.Equal(t, "tickets.acme.io", cfg.Forwarding.Audience)
	require.NotEmpty(t, cfg.Forwarding.SigningKey, "jwt mode ships the derived key")

	key, err := appauthz.DecodeSeed(cfg.Forwarding.SigningKey)
	require.NoError(t, err)
	assert.NotEqual(t, s.SessionPrivateKey, cfg.Forwarding.SigningKey, "the session key itself never leaves management")

	// The public key the API shows must verify what the proxy signs.
	apiAuthz := s.ToAPIResponse().Auth.Authorization
	require.NotNil(t, apiAuthz)
	require.NotNil(t, apiAuthz.PublicKeyPem)
	require.NotNil(t, apiAuthz.KeyId)
	wantPEM, err := appauthz.PublicKeyPEM(key.Public().(ed25519.PublicKey))
	require.NoError(t, err)
	assert.Equal(t, wantPEM, *apiAuthz.PublicKeyPem, "API public key matches the proxy signing key")
	assert.Equal(t, cfg.Forwarding.KeyID, *apiAuthz.KeyId, "kid matches")
}

func TestToProtoMapping_AppAuthzKeyMissingFailsClosed(t *testing.T) {
	s := authzService(t, appauthz.ForwardJWT)
	s.SessionPrivateKey = "still-encrypted-ciphertext"

	m := s.ToProtoMapping(Create, "", proxy.OIDCValidationConfig{})
	_, cfg := appAuthzFrom(t, m.Path[0])
	assert.Empty(t, cfg.Forwarding.SigningKey,
		"without a usable key the middleware is still sent, so the proxy refuses to build it and serves 503")
}

func TestToProtoMapping_NoAuthorizationNoMiddleware(t *testing.T) {
	s := validProxy()
	m := s.ToProtoMapping(Create, "", proxy.OIDCValidationConfig{})
	require.Len(t, m.Path, 1)
	assert.Nil(t, m.Path[0].Options, "services without authorization are unchanged")
}

func TestAuthorizationAPIRoundTrip(t *testing.T) {
	groups := []string{"grp-ops"}
	tools := []string{"*"}
	keyRoles := []string{"admin"}
	enforce := true
	header := api.ServiceAuthorizationConfigJwtHeaderAuthorization
	in := &api.ServiceAuthorizationConfig{
		Roles:       &[]api.ServiceRoleMapping{{Name: "admin", Groups: &groups, McpTools: &tools}},
		ApiKeyRoles: &keyRoles,
		EnforceMcp:  &enforce,
		Forwarding:  api.ServiceAuthorizationConfigForwardingJwt,
		JwtHeader:   &header,
	}

	s := authzService(t, appauthz.ForwardJWT)
	s.Auth.Authorization = authorizationFromAPI(in)
	require.NoError(t, s.Validate())

	out := s.ToAPIResponse().Auth.Authorization
	require.NotNil(t, out)
	assert.Equal(t, *in.Roles, *out.Roles)
	assert.Equal(t, keyRoles, *out.ApiKeyRoles)
	assert.True(t, *out.EnforceMcp)
	assert.Equal(t, api.ServiceAuthorizationConfigForwardingJwt, out.Forwarding)
	assert.Equal(t, header, *out.JwtHeader)
}

func TestServiceCopy_Authorization(t *testing.T) {
	s := authzService(t, appauthz.ForwardHeaders)
	c := s.Copy()
	c.Auth.Authorization.Roles[0].Groups[0] = "changed"
	assert.Equal(t, "grp-ops", s.Auth.Authorization.Roles[0].Groups[0], "copy must not share role slices")
}

func TestToProtoMapping_AppAuthzOAuthIssuer(t *testing.T) {
	const issuer = "https://netbird.acme.io/api/mcp/auth"
	oidc := proxy.OIDCValidationConfig{MCPAuthorizationServer: issuer}

	s := authzService(t, appauthz.ForwardJWT)
	s.Enabled = true
	_, cfg := appAuthzFrom(t, s.ToProtoMapping(Create, "", oidc).Path[0])
	assert.Equal(t, issuer, cfg.OAuthIssuer, "an SSO service with roles lets MCP clients sign in through the broker")

	_, cfg = appAuthzFrom(t, s.ToProtoMapping(Create, "", proxy.OIDCValidationConfig{}).Path[0])
	assert.Empty(t, cfg.OAuthIssuer, "no broker, no MCP sign-in")

	s.Auth.BearerAuth.Enabled = false
	_, cfg = appAuthzFrom(t, s.ToProtoMapping(Create, "", oidc).Path[0])
	assert.Empty(t, cfg.OAuthIssuer, "without SSO there is no user to sign in")
}
