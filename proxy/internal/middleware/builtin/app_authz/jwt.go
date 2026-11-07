package app_authz

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/netbirdio/netbird/proxy/appauthz"
)

// tokenLifetime keeps upstream tokens short-lived: they are minted per
// request, so there is no reason for them to outlive it by much.
const tokenLifetime = 60 * time.Second

// claims is the upstream identity token payload.
type claims struct {
	jwt.RegisteredClaims
	Email      string   `json:"email,omitempty"`
	Groups     []string `json:"groups,omitempty"`
	Roles      []string `json:"roles"`
	MCPTools   []string `json:"mcp_tools,omitempty"`
	AuthMethod string   `json:"auth_method,omitempty"`
}

type signer struct {
	key      ed25519.PrivateKey
	keyID    string
	issuer   string
	audience string
	now      func() time.Time
}

func newSigner(key ed25519.PrivateKey, f appauthz.Forwarding) *signer {
	kid := f.KeyID
	if kid == "" {
		kid = appauthz.KeyID(key.Public().(ed25519.PublicKey))
	}
	return &signer{key: key, keyID: kid, issuer: f.Issuer, audience: f.Audience, now: time.Now}
}

type identity struct {
	userID     string
	email      string
	groups     []string
	roles      []string
	tools      []string
	authMethod string
}

func (s *signer) sign(id identity) (string, error) {
	now := s.now()
	jti, err := newJTI()
	if err != nil {
		return "", err
	}
	c := claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.issuer,
			Subject:   id.userID,
			ExpiresAt: jwt.NewNumericDate(now.Add(tokenLifetime)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ID:        jti,
		},
		Email:      id.email,
		Groups:     id.groups,
		Roles:      id.roles,
		MCPTools:   id.tools,
		AuthMethod: id.authMethod,
	}
	if s.audience != "" {
		c.Audience = jwt.ClaimStrings{s.audience}
	}
	if c.Roles == nil {
		c.Roles = []string{}
	}
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, c)
	token.Header["kid"] = s.keyID
	signed, err := token.SignedString(s.key)
	if err != nil {
		return "", fmt.Errorf("sign upstream token: %w", err)
	}
	return signed, nil
}

func newJTI() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generate jti: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}
