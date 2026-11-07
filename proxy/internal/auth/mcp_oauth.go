package auth

import (
	"encoding/json"
	"net/http"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/proxy/auth"
	"github.com/netbirdio/netbird/proxy/internal/proxy"
)

// protectedResourcePath is the RFC 9728 metadata document. Clients may also ask for it
// with the path they connected to appended, such as /.well-known/oauth-protected-resource/mcp.
const protectedResourcePath = "/.well-known/oauth-protected-resource"

// protectedResource is the RFC 9728 metadata a domain serves for MCP clients.
type protectedResource struct {
	Resource               string   `json:"resource"`
	AuthorizationServers   []string `json:"authorization_servers"`
	BearerMethodsSupported []string `json:"bearer_methods_supported"`
	ResourceName           string   `json:"resource_name"`
}

// serveProtectedResourceMetadata answers the metadata request on a domain MCP clients can
// sign in to. It is public, as RFC 9728 requires: clients read it before they hold a token.
func serveProtectedResourceMetadata(w http.ResponseWriter, r *http.Request, host string, config DomainConfig) bool {
	if config.MCPOAuthIssuer == "" || (r.Method != http.MethodGet && r.Method != http.MethodHead) {
		return false
	}
	if r.URL.Path != protectedResourcePath && !strings.HasPrefix(r.URL.Path, protectedResourcePath+"/") {
		return false
	}
	doc, err := json.Marshal(protectedResource{
		Resource:               resourceURL(host),
		AuthorizationServers:   []string{config.MCPOAuthIssuer},
		BearerMethodsSupported: []string{"header"},
		ResourceName:           host,
	})
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return true
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodGet {
		_, _ = w.Write(doc)
	}
	return true
}

func resourceURL(host string) string {
	return "https://" + host
}

// bearerToken returns the token of an Authorization: Bearer header.
func bearerToken(r *http.Request) (string, bool) {
	scheme, token, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}
	token = strings.TrimSpace(token)
	return token, token != ""
}

// forwardWithBearerToken accepts a token the MCP broker signed for this domain. It is the
// same session token a browser holds as a cookie, so it gets the same checks: signature,
// audience, expiry, an OIDC method and the service's allowed groups. The header is removed
// before forwarding so the upstream never holds a credential for the proxy. A token that
// does not verify is left for the other schemes, since header auth may use Authorization.
func (mw *Middleware) forwardWithBearerToken(w http.ResponseWriter, r *http.Request, host string, config DomainConfig, next http.Handler) bool {
	if config.MCPOAuthIssuer == "" {
		return false
	}
	token, ok := bearerToken(r)
	if !ok {
		return false
	}
	userID, email, method, groups, groupNames, err := auth.ValidateSessionJWT(token, host, config.SessionPublicKey)
	if err != nil {
		return false
	}
	if method != auth.MethodOIDC.String() {
		mw.logger.WithField("host", host).Debug("bearer token rejected: not an SSO session")
		return false
	}
	if !sessionGroupsAllowed(config.AllowedGroups, auth.Method(method), groups) {
		mw.logger.WithFields(log.Fields{"host": host, "user_id": userID}).
			Debug("bearer token rejected: groups claim does not intersect the service's allowed groups")
		return false
	}

	r.Header.Del("Authorization")
	if cd := proxy.CapturedDataFromContext(r.Context()); cd != nil {
		cd.SetUserID(userID)
		cd.SetUserEmail(email)
		cd.SetUserGroups(groups)
		cd.SetUserGroupNames(groupNames)
		cd.SetAuthMethod(method)
	}
	next.ServeHTTP(w, r)
	return true
}

// wantsOAuthChallenge reports whether an unauthenticated request should get the MCP 401
// challenge rather than the browser login redirect: the domain supports MCP sign-in, and
// the client sent a bearer token that did not verify or is not a browser navigation.
func wantsOAuthChallenge(r *http.Request, config DomainConfig) bool {
	if config.MCPOAuthIssuer == "" {
		return false
	}
	if _, ok := bearerToken(r); ok {
		return true
	}
	return !strings.Contains(r.Header.Get("Accept"), "text/html")
}

// writeOAuthChallenge sends the RFC 9728 section 5.1 challenge that tells an MCP client
// where to find the authorization server.
func writeOAuthChallenge(w http.ResponseWriter, r *http.Request, host string) {
	if cd := proxy.CapturedDataFromContext(r.Context()); cd != nil {
		cd.SetOrigin(proxy.OriginAuth)
	}
	challenge := `Bearer resource_metadata="` + resourceURL(host) + protectedResourcePath + `"`
	if _, ok := bearerToken(r); ok {
		challenge += `, error="invalid_token"`
	}
	w.Header().Set("WWW-Authenticate", challenge)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = w.Write([]byte(`{"error":"unauthorized","error_description":"sign in with the authorization server named in WWW-Authenticate"}` + "\n"))
}
