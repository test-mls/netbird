// Package appauthz holds the per-service application authorization model
// shared by management and the proxy: role mappings, MCP tool permissions and
// how the resolved identity is forwarded to the upstream.
//
// Management builds a Config from the service and ships it to the proxy as the
// config of the app_authz middleware. The proxy resolves roles from the
// caller's group IDs, enforces MCP tools/call permissions and stamps identity
// headers or a signed JWT on the upstream request.
package appauthz

import (
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/netbirdio/netbird/proxy/auth"
)

// MiddlewareID is the registry identifier of the proxy middleware that
// enforces this config.
const MiddlewareID = "app_authz"

// ForwardingMode selects how the resolved identity reaches the upstream.
type ForwardingMode string

const (
	// ForwardHeaders stamps X-NetBird-User-Id, X-NetBird-Roles and
	// X-NetBird-Auth-Method next to the existing X-NetBird-User and
	// X-NetBird-Groups headers.
	ForwardHeaders ForwardingMode = "headers"
	// ForwardJWT stamps a short-lived EdDSA JWT carrying user, groups,
	// roles and MCP tools.
	ForwardJWT ForwardingMode = "jwt"
)

// Upstream header names stamped by the proxy.
const (
	HeaderUserID     = "X-NetBird-User-Id"
	HeaderRoles      = "X-NetBird-Roles"
	HeaderAuthMethod = "X-NetBird-Auth-Method"
	HeaderIdentity   = "X-NetBird-Identity"
	HeaderMCPTools   = "X-NetBird-MCP-Tools"
	HeaderAuthorize  = "Authorization"
)

// MaxRoles bounds the number of roles per service.
const MaxRoles = 64

// MaxToolsPerRole bounds the tool patterns per role.
const MaxToolsPerRole = 256

// Role maps NetBird groups to a role name and the MCP tools the role may call.
type Role struct {
	Name     string   `json:"name"`
	Groups   []string `json:"groups,omitempty"`
	MCPTools []string `json:"mcp_tools,omitempty"`
}

// Forwarding describes how identity is forwarded upstream. SigningKey is the
// base64 Ed25519 seed used in JWT mode; it is set by management when building
// the proxy mapping and never stored or returned by the API.
type Forwarding struct {
	Mode       ForwardingMode `json:"mode"`
	Header     string         `json:"header,omitempty"`
	Issuer     string         `json:"issuer,omitempty"`
	Audience   string         `json:"audience,omitempty"`
	KeyID      string         `json:"kid,omitempty"`
	SigningKey string         `json:"signing_key,omitempty"`
}

// Config is the on-wire config of the app_authz middleware.
type Config struct {
	Roles       []Role     `json:"roles,omitempty"`
	APIKeyRoles []string   `json:"api_key_roles,omitempty"`
	EnforceMCP  bool       `json:"enforce_mcp,omitempty"`
	Forwarding  Forwarding `json:"forwarding"`
	// OAuthIssuer is the OAuth 2.1 authorization server MCP clients sign in
	// with, set when the service uses SSO and management runs its MCP broker.
	// The proxy then serves protected resource metadata, accepts the broker's
	// bearer tokens and answers non-browser clients with a 401 challenge.
	OAuthIssuer string `json:"oauth_issuer,omitempty"`
}

// ResolveRoles returns the role names granted to a caller, in config order.
// Header (API key) callers get APIKeyRoles; every other method is matched by
// group ID. A caller with no matching group gets no roles.
func (c *Config) ResolveRoles(method string, groupIDs []string) []string {
	if method == auth.MethodHeader.String() {
		return slices.Clone(c.APIKeyRoles)
	}
	if len(groupIDs) == 0 {
		return nil
	}
	var roles []string
	for _, r := range c.Roles {
		if slices.ContainsFunc(r.Groups, func(g string) bool { return slices.Contains(groupIDs, g) }) {
			roles = append(roles, r.Name)
		}
	}
	return roles
}

// ToolPatterns returns the union of MCP tool patterns granted by the roles.
func (c *Config) ToolPatterns(roles []string) []string {
	var patterns []string
	for _, r := range c.Roles {
		if !slices.Contains(roles, r.Name) {
			continue
		}
		for _, p := range r.MCPTools {
			if !slices.Contains(patterns, p) {
				patterns = append(patterns, p)
			}
		}
	}
	return patterns
}

// ToolAllowed reports whether tool matches any of the patterns. An empty tool
// name never matches.
func ToolAllowed(patterns []string, tool string) bool {
	if tool == "" {
		return false
	}
	for _, p := range patterns {
		if globMatch(p, tool) {
			return true
		}
	}
	return false
}

// globMatch matches name against pattern where '*' matches any run of
// characters, including none. Every other character matches itself.
func globMatch(pattern, name string) bool {
	star := strings.IndexByte(pattern, '*')
	if star < 0 {
		return pattern == name
	}
	if !strings.HasPrefix(name, pattern[:star]) {
		return false
	}
	rest := pattern[star+1:]
	name = name[star:]
	if rest == "" {
		return true
	}
	for i := 0; i <= len(name); i++ {
		if globMatch(rest, name[i:]) {
			return true
		}
	}
	return false
}

// upstreamKeyInfo binds the derived key to its purpose so it can never be
// confused with the session key it is derived from.
const upstreamKeyInfo = "netbird-upstream-identity-v1"

// DeriveSigningKey derives the upstream identity signing key from a service's
// base64 Ed25519 session private key. The derived key is distinct from the
// session key, so a leak of it cannot forge proxy sessions.
func DeriveSigningKey(sessionPrivateKeyB64 string) (ed25519.PrivateKey, error) {
	raw, err := base64.StdEncoding.DecodeString(sessionPrivateKeyB64)
	if err != nil {
		return nil, fmt.Errorf("decode session key: %w", err)
	}
	if len(raw) != ed25519.PrivateKeySize {
		return nil, errors.New("session key is not an Ed25519 private key")
	}
	seed, err := hkdf.Key(sha256.New, ed25519.PrivateKey(raw).Seed(), nil, upstreamKeyInfo, ed25519.SeedSize)
	if err != nil {
		return nil, fmt.Errorf("derive key: %w", err)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// EncodeSeed returns the base64 seed of key for Forwarding.SigningKey.
func EncodeSeed(key ed25519.PrivateKey) string {
	return base64.StdEncoding.EncodeToString(key.Seed())
}

// DecodeSeed parses Forwarding.SigningKey.
func DecodeSeed(seedB64 string) (ed25519.PrivateKey, error) {
	seed, err := base64.StdEncoding.DecodeString(seedB64)
	if err != nil {
		return nil, fmt.Errorf("decode signing key: %w", err)
	}
	if len(seed) != ed25519.SeedSize {
		return nil, errors.New("signing key has the wrong length")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// KeyID returns a stable key identifier for pub.
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}

// PublicKeyPEM encodes pub as a PKIX PEM block, the form most JWT libraries
// accept for EdDSA verification.
func PublicKeyPEM(pub ed25519.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("marshal public key: %w", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), nil
}

// JWK is a single OKP JSON Web Key (RFC 8037).
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
}

// PublicJWK returns pub as an OKP JWK.
func PublicJWK(pub ed25519.PublicKey) JWK {
	return JWK{
		Kty: "OKP",
		Crv: "Ed25519",
		X:   base64.RawURLEncoding.EncodeToString(pub),
		Kid: KeyID(pub),
		Alg: "EdDSA",
		Use: "sig",
	}
}
