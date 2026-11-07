package mcpapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const serviceResource = "https://tickets.acme.io/"

// noRedirects stops at the broker's redirect, so a refusal sent to the client's
// callback can be read without a client listening there.
var noRedirects = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

// fakeServices stands in for management's proxy service: tickets.acme.io accepts broker
// tokens, and a token names the domain, user and lifetime so tests can read them back.
type fakeServices struct {
	mu     sync.Mutex
	denied bool
	issued int
}

func (f *fakeServices) ServiceAcceptsBrokerTokens(_ context.Context, domain string) bool {
	return domain == "tickets.acme.io"
}

func (f *fakeServices) IssueServiceToken(_ context.Context, domain, userID string, ttl time.Duration) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.denied {
		return "", errors.New("user not in allowed groups")
	}
	f.issued++
	return fmt.Sprintf("svc:%s:%s:%s", domain, userID, ttl), nil
}

func (f *fakeServices) deny() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.denied = true
}

func newServiceEnv(t *testing.T) (*brokerEnv, *fakeServices) {
	t.Helper()
	services := &fakeServices{}
	env := newBrokerEnvWith(t, httptest.NewServer, nil, func(cfg *BrokerConfig) { cfg.Services = services })
	return env, services
}

func (e *brokerEnv) serviceRequest(clientID string) authRequest {
	req := e.newRequest(clientID)
	req.extra = url.Values{"resource": {serviceResource}}
	return req
}

func (e *brokerEnv) exchangeFor(req authRequest, code, resource string) (int, map[string]any) {
	return e.tokenRequest(url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {req.clientID},
		"redirect_uri":  {req.redirectURI},
		"code_verifier": {req.verifier},
		"resource":      {resource},
	})
}

func TestBrokerSignsInToAService(t *testing.T) {
	env, services := newServiceEnv(t)
	clientID := env.register(clientCallback)
	req := env.serviceRequest(clientID)

	browser := env.browser()
	page, sealed := env.consent(browser, req)
	assert.Contains(t, page, "tickets.acme.io", "the consent page names the service")
	assert.NotContains(t, page, "Make changes", "management API scopes do not apply to a service")

	back := env.decide(browser, sealed, url.Values{"action": {"approve"}})
	code := back.Query().Get("code")
	require.NotEmpty(t, code)

	status, tokens := env.exchangeFor(req, code, "https://tickets.acme.io/mcp")
	require.Equal(t, http.StatusOK, status, tokens)
	assert.Equal(t, "svc:tickets.acme.io:user-1:15m0s", tokens["access_token"],
		"the access token is the service's own short-lived token, which its proxy verifies")
	assert.Equal(t, float64(900), tokens["expires_in"])
	assert.Equal(t, "mcp:read", tokens["scope"])

	assert.Equal(t, http.StatusUnauthorized, env.callMCP("/api/mcp", tokens["access_token"].(string), nil).status,
		"a service token is not a management MCP token")

	t.Run("refresh mints a new service token", func(t *testing.T) {
		before := services.issued
		status, refreshed := env.tokenRequest(url.Values{
			"grant_type": {"refresh_token"}, "refresh_token": {tokens["refresh_token"].(string)}, "client_id": {clientID},
			"resource": {serviceResource},
		})
		require.Equal(t, http.StatusOK, status, refreshed)
		assert.Equal(t, before+1, services.issued, "each refresh re-checks the user against the service")
		tokens = refreshed
	})

	t.Run("refresh for another resource is refused", func(t *testing.T) {
		status, out := env.tokenRequest(url.Values{
			"grant_type": {"refresh_token"}, "refresh_token": {tokens["refresh_token"].(string)}, "client_id": {clientID},
			"resource": {"https://other.acme.io/"},
		})
		assert.Equal(t, http.StatusBadRequest, status)
		assert.Equal(t, "invalid_grant", out["error"])
	})

	t.Run("a user who lost access cannot refresh", func(t *testing.T) {
		services.deny()
		status, out := env.tokenRequest(url.Values{
			"grant_type": {"refresh_token"}, "refresh_token": {tokens["refresh_token"].(string)}, "client_id": {clientID},
		})
		assert.Equal(t, http.StatusBadRequest, status)
		assert.Equal(t, "invalid_grant", out["error"], "the client signs in again and is refused there")
	})
}

func TestBrokerServiceCodeIsBoundToTheService(t *testing.T) {
	env, _ := newServiceEnv(t)
	clientID := env.register(clientCallback)
	req := env.serviceRequest(clientID)
	code := env.login(req, false).Query().Get("code")
	require.NotEmpty(t, code)

	status, out := env.exchangeFor(req, code, env.srv.URL+"/api/mcp")
	assert.Equal(t, http.StatusBadRequest, status, "a code for a service cannot be redeemed for management")
	assert.Equal(t, "invalid_target", out["error"])
}

func TestBrokerRefusesUnknownServiceResources(t *testing.T) {
	cases := map[string]string{
		"a domain that is not a service":  "https://unknown.acme.io/",
		"plain http":                      "http://tickets.acme.io/",
		"a query":                         "https://tickets.acme.io/?x=1",
		"two different services":          "",
		"management's own host, any path": "",
	}
	env, _ := newServiceEnv(t)
	cases["management's own host, any path"] = env.srv.URL + "/other"

	for name, resource := range cases {
		t.Run(name, func(t *testing.T) {
			req := env.newRequest(env.register(clientCallback))
			req.extra = url.Values{"resource": {resource}}
			if name == "two different services" {
				req.extra = url.Values{"resource": {serviceResource, "https://unknown.acme.io/"}}
			}
			resp, err := noRedirects.Get(env.authorizeURL(req))
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()
			require.Equal(t, http.StatusFound, resp.StatusCode, "a loopback client is told why")
			loc, err := url.Parse(resp.Header.Get("Location"))
			require.NoError(t, err)
			assert.Equal(t, "invalid_target", loc.Query().Get("error"))
		})
	}
}

func TestBrokerWithoutServicesKeepsItsOwnResourceOnly(t *testing.T) {
	env := newBrokerEnv(t)
	req := env.newRequest(env.register(clientCallback))
	req.extra = url.Values{"resource": {serviceResource}}
	resp, err := noRedirects.Get(env.authorizeURL(req))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	loc, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)
	assert.Equal(t, "invalid_target", loc.Query().Get("error"), "service sign-in needs the proxy service wired in")
}
