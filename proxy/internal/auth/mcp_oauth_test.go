package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/sessionkey"
	"github.com/netbirdio/netbird/proxy/auth"
	"github.com/netbirdio/netbird/proxy/internal/proxy"
)

const testIssuer = "https://netbird.acme.io/api/mcp/auth"

// mcpDomain registers tickets.acme.io with an SSO scheme that, like the real one,
// answers an unauthenticated request with the IdP login URL, and MCP sign-in on.
func mcpDomain(t *testing.T, issuer string, allowedGroups []string) (*Middleware, *sessionkey.KeyPair) {
	t.Helper()
	mw := NewMiddleware(log.StandardLogger(), nil, nil)
	kp := generateTestKeyPair(t)
	sso := &stubScheme{method: auth.MethodOIDC, promptID: "https://idp.acme.io/authorize?client_id=x"}
	require.NoError(t, mw.AddDomain("tickets.acme.io", []Scheme{sso}, kp.PublicKey, time.Hour, "acc", "svc",
		nil, false, allowedGroups, WithMCPOAuth(issuer)))
	return mw, kp
}

// identityBackend records what the upstream receives.
type identityBackend struct {
	called        bool
	authorization string
	userID        string
	groups        []string
}

func (b *identityBackend) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b.called = true
	b.authorization = r.Header.Get("Authorization")
	if cd := proxy.CapturedDataFromContext(r.Context()); cd != nil {
		b.userID = cd.GetUserID()
		b.groups = cd.GetUserGroups()
	}
	w.WriteHeader(http.StatusOK)
}

func mcpRequest(method, target string) *http.Request {
	req := httptest.NewRequest(method, target, nil)
	req.Header.Set("Accept", "application/json, text/event-stream")
	cd := proxy.NewCapturedData("req-1")
	return req.WithContext(proxy.WithCapturedData(req.Context(), cd))
}

func TestMCPOAuth_ProtectedResourceMetadata(t *testing.T) {
	mw, _ := mcpDomain(t, testIssuer, nil)
	backend := &identityBackend{}
	h := mw.Protect(backend)

	for _, path := range []string{"/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://tickets.acme.io"+path, nil))
		require.Equal(t, http.StatusOK, rec.Code, "metadata is public at %s", path)

		var doc protectedResource
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &doc))
		assert.Equal(t, "https://tickets.acme.io", doc.Resource, "the resource is the service origin")
		assert.Equal(t, []string{testIssuer}, doc.AuthorizationServers, "clients are sent to management's broker")
	}
	assert.False(t, backend.called, "metadata is answered by the proxy")

	plain, _ := mcpDomain(t, "", nil)
	rec := httptest.NewRecorder()
	plain.Protect(backend).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://tickets.acme.io/.well-known/oauth-protected-resource", nil))
	assert.NotEqual(t, http.StatusOK, rec.Code, "without MCP sign-in the path is not special and needs auth like any other")
}

func TestMCPOAuth_ChallengeInsteadOfRedirect(t *testing.T) {
	mw, _ := mcpDomain(t, testIssuer, nil)
	h := mw.Protect(&identityBackend{})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, mcpRequest(http.MethodPost, "https://tickets.acme.io/mcp"))
	require.Equal(t, http.StatusUnauthorized, rec.Code, "an MCP client gets 401, not a login redirect")
	assert.Equal(t, `Bearer resource_metadata="https://tickets.acme.io/.well-known/oauth-protected-resource"`,
		rec.Header().Get("WWW-Authenticate"))

	browser := httptest.NewRequest(http.MethodGet, "https://tickets.acme.io/", nil)
	browser.Header.Set("Accept", "text/html,application/xhtml+xml")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, browser)
	assert.Equal(t, http.StatusFound, rec.Code, "a browser still goes to the SSO login")

	plain, _ := mcpDomain(t, "", nil)
	rec = httptest.NewRecorder()
	plain.Protect(&identityBackend{}).ServeHTTP(rec, mcpRequest(http.MethodPost, "https://tickets.acme.io/mcp"))
	assert.Equal(t, http.StatusFound, rec.Code, "without MCP sign-in nothing changes")
}

func TestMCPOAuth_BearerToken(t *testing.T) {
	mw, kp := mcpDomain(t, testIssuer, []string{"grp-eng"})
	backend := &identityBackend{}
	h := mw.Protect(backend)

	token, err := sessionkey.SignMCPAccessToken(kp.PrivateKey, "alice", "alice@acme.io", "tickets.acme.io",
		[]string{"grp-eng"}, []string{"eng"}, 15*time.Minute)
	require.NoError(t, err)

	req := mcpRequest(http.MethodPost, "https://tickets.acme.io/mcp")
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.True(t, backend.called)
	assert.Equal(t, "alice", backend.userID, "the token's user reaches the middleware chain")
	assert.Equal(t, []string{"grp-eng"}, backend.groups, "and so do its groups, for role mapping")
	assert.Empty(t, backend.authorization, "the upstream never receives the proxy credential")
}

func TestMCPOAuth_BearerTokenRejected(t *testing.T) {
	mw, kp := mcpDomain(t, testIssuer, []string{"grp-eng"})
	other := generateTestKeyPair(t)

	sign := func(key *sessionkey.KeyPair, audience string, groups []string, ttl time.Duration) string {
		token, err := sessionkey.SignMCPAccessToken(key.PrivateKey, "alice", "", audience, groups, nil, ttl)
		require.NoError(t, err)
		return token
	}
	browserSession, err := sessionkey.SignToken(kp.PrivateKey, "alice", "", "tickets.acme.io", auth.MethodOIDC, []string{"grp-eng"}, nil, time.Hour)
	require.NoError(t, err)

	// Every token but the last case is a well-formed MCP access token, so each
	// case fails only on the condition it names.
	cases := map[string]string{
		"another service's token":  sign(kp, "other.acme.io", []string{"grp-eng"}, time.Hour),
		"another key":              sign(other, "tickets.acme.io", []string{"grp-eng"}, time.Hour),
		"expired":                  sign(kp, "tickets.acme.io", []string{"grp-eng"}, -time.Minute),
		"outside allowed groups":   sign(kp, "tickets.acme.io", []string{"grp-other"}, time.Hour),
		"a browser session cookie": browserSession,
		"not a token":              "garbage",
	}
	for name, token := range cases {
		t.Run(name, func(t *testing.T) {
			backend := &identityBackend{}
			req := mcpRequest(http.MethodPost, "https://tickets.acme.io/mcp")
			req.Header.Set("Authorization", "Bearer "+token)
			rec := httptest.NewRecorder()
			mw.Protect(backend).ServeHTTP(rec, req)

			assert.False(t, backend.called, "the request must not reach the upstream")
			assert.Equal(t, http.StatusUnauthorized, rec.Code)
			assert.Contains(t, rec.Header().Get("WWW-Authenticate"), `error="invalid_token"`, "the client is told to sign in again")
		})
	}
}

func TestMCPOAuth_BearerIgnoredWithoutMCPSignIn(t *testing.T) {
	mw, kp := mcpDomain(t, "", nil)
	backend := &identityBackend{}
	token, err := sessionkey.SignToken(kp.PrivateKey, "alice", "", "tickets.acme.io", auth.MethodOIDC, nil, nil, time.Hour)
	require.NoError(t, err)

	req := mcpRequest(http.MethodPost, "https://tickets.acme.io/mcp")
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	mw.Protect(backend).ServeHTTP(rec, req)
	assert.False(t, backend.called, "bearer tokens are only honoured where MCP sign-in is on")
}

func TestWithMCPOAuthRejectsInsecureIssuer(t *testing.T) {
	var cfg DomainConfig
	assert.Error(t, WithMCPOAuth("http://netbird.acme.io/api/mcp/auth")(&cfg), "the issuer must be https")
	assert.NoError(t, WithMCPOAuth("")(&cfg), "empty means off")
	assert.Empty(t, cfg.MCPOAuthIssuer)
}

func TestMCPOAuth_AccessTokenIsNotASessionCookie(t *testing.T) {
	mw, kp := mcpDomain(t, testIssuer, []string{"grp-eng"})
	token, err := sessionkey.SignMCPAccessToken(kp.PrivateKey, "alice", "", "tickets.acme.io", []string{"grp-eng"}, nil, time.Hour)
	require.NoError(t, err)

	backend := &identityBackend{}
	req := httptest.NewRequest(http.MethodGet, "https://tickets.acme.io/", nil)
	req.Header.Set("Accept", "text/html")
	req.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: token})
	rec := httptest.NewRecorder()
	mw.Protect(backend).ServeHTTP(rec, req)

	assert.False(t, backend.called, "an MCP access token must not open a browser session")
	assert.Equal(t, http.StatusFound, rec.Code, "the browser is sent to the SSO login instead")
}
