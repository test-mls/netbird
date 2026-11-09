package proxy

import (
	"crypto/ed25519"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/netbirdio/netbird/proxy/appauthz"
	"github.com/netbirdio/netbird/shared/management/proto"
)

// jwksPath is where upstreams fetch the key that verifies the identity JWTs
// app_authz signs for a service. It is served on the service's own domain,
// ahead of authentication, because the upstream fetching it holds no session.
const jwksPath = "/.well-known/netbird/jwks.json"

// jwksStore holds the public JWKS document per service domain.
type jwksStore struct {
	mu     sync.RWMutex
	byHost map[string][]byte
}

// set stores doc for host; a nil doc removes it.
func (j *jwksStore) set(host string, doc []byte) {
	host = strings.ToLower(host)
	j.mu.Lock()
	defer j.mu.Unlock()
	if doc == nil {
		delete(j.byHost, host)
		return
	}
	if j.byHost == nil {
		j.byHost = make(map[string][]byte)
	}
	j.byHost[host] = doc
}

func (j *jwksStore) get(host string) ([]byte, bool) {
	j.mu.RLock()
	defer j.mu.RUnlock()
	doc, ok := j.byHost[strings.ToLower(host)]
	return doc, ok
}

// middleware answers jwksPath for domains that sign identity JWTs and passes
// every other request through, including jwksPath on domains that do not, so
// an upstream serving its own file at that path keeps working.
func (j *jwksStore) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != jwksPath || (r.Method != http.MethodGet && r.Method != http.MethodHead) {
			next.ServeHTTP(w, r)
			return
		}
		doc, ok := j.get(requestHost(r))
		if !ok {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=300")
		w.WriteHeader(http.StatusOK)
		if r.Method == http.MethodGet {
			_, _ = w.Write(doc)
		}
	})
}

func requestHost(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.Host); err == nil {
		return host
	}
	return r.Host
}

// jwksForMapping returns the JWKS document for a mapping whose app_authz
// middleware signs JWTs, or nil when it signs none.
func jwksForMapping(mapping *proto.ProxyMapping) []byte {
	var keys []appauthz.JWK
	seen := make(map[string]struct{})
	for _, pm := range mapping.GetPath() {
		for _, mw := range pm.GetOptions().GetMiddlewares() {
			if mw.GetId() != appauthz.MiddlewareID || !mw.GetEnabled() {
				continue
			}
			jwk, ok := signingJWK(mw.GetConfigJson())
			if !ok {
				continue
			}
			if _, dup := seen[jwk.Kid]; dup {
				continue
			}
			seen[jwk.Kid] = struct{}{}
			keys = append(keys, jwk)
		}
	}
	if len(keys) == 0 {
		return nil
	}
	doc, err := json.Marshal(struct {
		Keys []appauthz.JWK `json:"keys"`
	}{Keys: keys})
	if err != nil {
		return nil
	}
	return doc
}

// mcpOAuthIssuer returns the OAuth authorization server MCP clients sign in to the
// mapping's domain with, or "" when its app_authz middleware names none.
func mcpOAuthIssuer(mapping *proto.ProxyMapping) string {
	for _, pm := range mapping.GetPath() {
		for _, mw := range pm.GetOptions().GetMiddlewares() {
			if mw.GetId() != appauthz.MiddlewareID || !mw.GetEnabled() {
				continue
			}
			var cfg appauthz.Config
			if err := json.Unmarshal(mw.GetConfigJson(), &cfg); err == nil && cfg.OAuthIssuer != "" {
				return cfg.OAuthIssuer
			}
		}
	}
	return ""
}

func signingJWK(raw []byte) (appauthz.JWK, bool) {
	var cfg appauthz.Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return appauthz.JWK{}, false
	}
	if cfg.Forwarding.Mode != appauthz.ForwardJWT || cfg.Forwarding.SigningKey == "" {
		return appauthz.JWK{}, false
	}
	key, err := appauthz.DecodeSeed(cfg.Forwarding.SigningKey)
	if err != nil {
		return appauthz.JWK{}, false
	}
	jwk := appauthz.PublicJWK(key.Public().(ed25519.PublicKey))
	if cfg.Forwarding.KeyID != "" {
		jwk.Kid = cfg.Forwarding.KeyID
	}
	return jwk, true
}
