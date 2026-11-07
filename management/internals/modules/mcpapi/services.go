package mcpapi

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

// AuthIssuerPath is the broker's issuer path. Reverse proxies advertise
// <management URL> + AuthIssuerPath as the authorization server of SSO services.
const AuthIssuerPath = authIssuerPath

// serviceAccessTokenTTL keeps the tokens the proxy verifies on its own short. The proxy
// cannot ask management whether a session was revoked, so this bounds how long a revoked
// session keeps working. Refreshing re-checks the user and the service's groups.
const serviceAccessTokenTTL = 15 * time.Minute

// ServiceTokens lets the broker sign MCP clients in to reverse proxy services, not only to
// management's own MCP endpoint. Management's proxy service satisfies it.
type ServiceTokens interface {
	// ServiceAcceptsBrokerTokens reports whether domain is a service MCP clients may sign
	// in to: an HTTP service with SSO and roles configured.
	ServiceAcceptsBrokerTokens(ctx context.Context, domain string) bool
	// IssueServiceToken signs an access token the service's proxy verifies itself, after
	// checking the user still belongs to the service's account and SSO groups.
	IssueServiceToken(ctx context.Context, domain, userID string, ttl time.Duration) (string, error)
}

// requestedResource resolves the resource an authorization request names: management's
// own MCP endpoint (also when none is named), or a reverse proxy service. A service is
// stored as "https://<domain>" with no path; the proxy serves MCP at any path of it.
func (b *Broker) requestedResource(ctx context.Context, r *http.Request, values []string) (string, bool) {
	own := b.resourceURL(r)
	if resourceMatches(values, own) {
		return own, true
	}
	if b.services == nil || len(values) == 0 {
		return "", false
	}
	host := ""
	for _, v := range values {
		h, ok := resourceHost(v)
		if !ok || (host != "" && h != host) {
			return "", false
		}
		host = h
	}
	if ownURL, err := url.Parse(own); err == nil && strings.EqualFold(ownURL.Host, host) {
		return "", false
	}
	if !b.services.ServiceAcceptsBrokerTokens(ctx, host) {
		return "", false
	}
	return "https://" + host, true
}

// grantResourceMatches checks the resource a token request names against the one the
// code or refresh token was issued for.
func grantResourceMatches(values []string, expected string) bool {
	host, ok := serviceResourceHost(expected)
	if !ok {
		return resourceMatches(values, expected)
	}
	for _, v := range values {
		h, ok := resourceHost(v)
		if !ok || h != host {
			return false
		}
	}
	return true
}

// serviceResourceHost returns the domain of a stored service resource. Management's own
// resource always has a path, so a pathless one is a service.
func serviceResourceHost(resource string) (string, bool) {
	u, err := url.Parse(resource)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Path != "" {
		return "", false
	}
	return u.Host, true
}

// resourceHost reads the domain of a resource a client names for a service. Any path is
// accepted, since clients name the URL they connected to; anything beyond scheme, host and
// path is refused.
func resourceHost(raw string) (string, bool) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil ||
		u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return "", false
	}
	return strings.ToLower(u.Host), true
}

// accessToken mints the access token for a grant: a sealed broker token for management's
// own endpoint, or a token signed with the service's key for a reverse proxy service. It
// writes the OAuth error itself and reports whether a token was issued.
func (b *Broker) accessToken(w http.ResponseWriter, r *http.Request, access grant, now time.Time) (string, int64, bool) {
	domain, isService := serviceResourceHost(access.Resource)
	if !isService {
		token, err := b.seal.seal(purposeAccess, accessTokenPrefix, access)
		if err != nil {
			log.WithContext(r.Context()).Errorf("seal MCP access token: %v", err)
			writeOAuthError(w, http.StatusInternalServerError, "server_error", "")
			return "", 0, false
		}
		return token, access.Expires, true
	}
	if b.services == nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "sign-in to NetBird services is not available")
		return "", 0, false
	}
	expires := min(now.Add(serviceAccessTokenTTL).Unix(), access.Expires)
	token, err := b.services.IssueServiceToken(r.Context(), domain, access.Identity.UserID, time.Unix(expires, 0).Sub(now))
	if err != nil {
		log.WithContext(r.Context()).Debugf("MCP service token for %s refused: %v", domain, err)
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "you do not have access to this service")
		return "", 0, false
	}
	return token, expires, true
}
