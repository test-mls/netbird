package proxy

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/proxy/appauthz"
	"github.com/netbirdio/netbird/shared/management/proto"
)

func appAuthzMapping(t *testing.T, cfg appauthz.Config) *proto.ProxyMapping {
	t.Helper()
	raw, err := json.Marshal(cfg)
	require.NoError(t, err)
	return &proto.ProxyMapping{
		Domain: "tickets.acme.io",
		Path: []*proto.PathMapping{{
			Path: "/",
			Options: &proto.PathTargetOptions{Middlewares: []*proto.MiddlewareConfig{{
				Id: appauthz.MiddlewareID, Enabled: true, ConfigJson: raw,
			}}},
		}},
	}
}

func TestJWKSServedForJWTServices(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	pub := priv.Public().(ed25519.PublicKey)
	mapping := appAuthzMapping(t, appauthz.Config{Forwarding: appauthz.Forwarding{
		Mode: appauthz.ForwardJWT, SigningKey: appauthz.EncodeSeed(priv), KeyID: appauthz.KeyID(pub),
	}})

	var store jwksStore
	store.set(mapping.GetDomain(), jwksForMapping(mapping))

	upstream := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) })
	h := store.middleware(upstream)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://TICKETS.acme.io:443"+jwksPath, nil))
	require.Equal(t, http.StatusOK, rec.Code, "JWKS is served without auth, host match ignores case and port")
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))

	var doc struct {
		Keys []appauthz.JWK `json:"keys"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &doc))
	require.Len(t, doc.Keys, 1)
	x, err := base64.RawURLEncoding.DecodeString(doc.Keys[0].X)
	require.NoError(t, err)
	assert.Equal(t, []byte(pub), x, "served key is the signing key's public half")
	assert.Equal(t, appauthz.KeyID(pub), doc.Keys[0].Kid)
	assert.NotContains(t, rec.Body.String(), appauthz.EncodeSeed(priv), "the private seed must never be served")

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://other.acme.io"+jwksPath, nil))
	assert.Equal(t, http.StatusTeapot, rec.Code, "other domains fall through to the upstream")

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "https://tickets.acme.io"+jwksPath, nil))
	assert.Equal(t, http.StatusTeapot, rec.Code, "only GET and HEAD are answered")

	store.set(mapping.GetDomain(), nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://tickets.acme.io"+jwksPath, nil))
	assert.Equal(t, http.StatusTeapot, rec.Code, "removed services stop serving a JWKS")
}

func TestJWKSNotPublishedForHeadersMode(t *testing.T) {
	mapping := appAuthzMapping(t, appauthz.Config{Forwarding: appauthz.Forwarding{Mode: appauthz.ForwardHeaders}})
	assert.Nil(t, jwksForMapping(mapping), "headers mode signs nothing, so there is no JWKS")
	assert.Nil(t, jwksForMapping(&proto.ProxyMapping{Domain: "plain.acme.io"}), "no app_authz, no JWKS")
}
