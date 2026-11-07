package service

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/proxy/appauthz"
	"github.com/netbirdio/netbird/shared/management/http/api"
	"github.com/netbirdio/netbird/shared/management/proto"
)

// appAuthzCaptureBytes bounds the request body the proxy buffers to read MCP
// JSON-RPC calls. Tool calls are small; a larger body is denied, not passed.
const appAuthzCaptureBytes int64 = 256 << 10

// appAuthzTimeoutMs bounds one app_authz invocation.
const appAuthzTimeoutMs = 200

// AuthorizationConfig is the per-service application authorization model:
// role mappings, MCP tool permissions and how identity is forwarded upstream.
// It is stored inside the service's auth JSON column.
type AuthorizationConfig struct {
	Roles       []appauthz.Role         `json:"roles,omitempty"`
	APIKeyRoles []string                `json:"api_key_roles,omitempty"`
	EnforceMCP  bool                    `json:"enforce_mcp,omitempty"`
	Forwarding  appauthz.ForwardingMode `json:"forwarding"`
	JWTHeader   string                  `json:"jwt_header,omitempty"`
}

// baseConfig returns the admin-provided part of the proxy config.
func (a *AuthorizationConfig) baseConfig() appauthz.Config {
	return appauthz.Config{
		Roles:       a.Roles,
		APIKeyRoles: a.APIKeyRoles,
		EnforceMCP:  a.EnforceMCP,
		Forwarding:  appauthz.Forwarding{Mode: a.Forwarding, Header: a.JWTHeader},
	}
}

// Copy returns a deep copy.
func (a *AuthorizationConfig) Copy() *AuthorizationConfig {
	if a == nil {
		return nil
	}
	c := *a
	c.APIKeyRoles = slices.Clone(a.APIKeyRoles)
	c.Roles = make([]appauthz.Role, len(a.Roles))
	for i, r := range a.Roles {
		c.Roles[i] = appauthz.Role{Name: r.Name, Groups: slices.Clone(r.Groups), MCPTools: slices.Clone(r.MCPTools)}
	}
	return &c
}

// validateAuthorization checks the authorization block against the rest of
// the service.
func (s *Service) validateAuthorization() error {
	a := s.Auth.Authorization
	if a == nil {
		return nil
	}
	if s.Mode != "" && s.Mode != ModeHTTP {
		return errors.New("authorization is only supported for HTTP services")
	}
	cfg := a.baseConfig()
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("authorization: %w", err)
	}
	if a.Forwarding == appauthz.ForwardJWT && cfg.Forwarding.JWTHeader() == appauthz.HeaderAuthorize {
		for _, h := range s.Auth.HeaderAuths {
			if h != nil && h.Enabled && strings.EqualFold(h.Header, appauthz.HeaderAuthorize) {
				return errors.New("authorization: the JWT cannot use the Authorization header while header auth checks Authorization, because the proxy strips that header before forwarding")
			}
		}
	}
	return nil
}

// upstreamSigningKey derives the key that signs upstream identity JWTs.
func (s *Service) upstreamSigningKey() (ed25519.PrivateKey, error) {
	if s.SessionPrivateKey == "" {
		return nil, errors.New("service has no session key")
	}
	return appauthz.DeriveSigningKey(s.SessionPrivateKey)
}

// appAuthzMiddleware builds the app_authz middleware entry for the proxy, or
// nil when the service has no authorization block. In jwt mode a key that
// cannot be derived is left out on purpose: the proxy then refuses to build
// the middleware and serves the target as unavailable rather than unchecked.
func (s *Service) appAuthzMiddleware() *proto.MiddlewareConfig {
	a := s.Auth.Authorization
	if a == nil {
		return nil
	}
	cfg := a.baseConfig()
	if a.Forwarding == appauthz.ForwardJWT {
		cfg.Forwarding.Issuer = "https://" + s.Domain
		cfg.Forwarding.Audience = s.Domain
		key, err := s.upstreamSigningKey()
		if err != nil {
			log.Warnf("service %s: derive upstream identity key: %v", s.ID, err)
		} else {
			cfg.Forwarding.SigningKey = appauthz.EncodeSeed(key)
			cfg.Forwarding.KeyID = appauthz.KeyID(key.Public().(ed25519.PublicKey))
		}
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		log.Errorf("service %s: encode app_authz config: %v", s.ID, err)
		raw = []byte("{}")
	}
	mw := middlewaresToProto([]MiddlewareConfig{{
		ID:         appauthz.MiddlewareID,
		Enabled:    true,
		Slot:       MiddlewareSlotOnRequest,
		ConfigJSON: raw,
		FailMode:   MiddlewareFailClosed,
		TimeoutMs:  appAuthzTimeoutMs,
		CanMutate:  true,
	}})
	return mw[0]
}

// attachAppAuthz adds the app_authz middleware to an HTTP path mapping and,
// when MCP enforcement is on, makes the proxy capture JSON request bodies.
// The middleware runs first so later middlewares see the resolved identity.
func (s *Service) attachAppAuthz(pm *proto.PathMapping, mw *proto.MiddlewareConfig) {
	if mw == nil {
		return
	}
	if pm.Options == nil {
		pm.Options = &proto.PathTargetOptions{}
	}
	pm.Options.Middlewares = append([]*proto.MiddlewareConfig{mw}, pm.Options.Middlewares...)
	if !s.Auth.Authorization.EnforceMCP {
		return
	}
	pm.Options.CaptureMaxRequestBytes = max(pm.Options.CaptureMaxRequestBytes, appAuthzCaptureBytes)
	if !slices.Contains(pm.Options.CaptureContentTypes, "application/json") {
		pm.Options.CaptureContentTypes = append(pm.Options.CaptureContentTypes, "application/json")
	}
}

func authorizationFromAPI(in *api.ServiceAuthorizationConfig) *AuthorizationConfig {
	if in == nil {
		return nil
	}
	out := &AuthorizationConfig{Forwarding: appauthz.ForwardingMode(in.Forwarding)}
	if in.Roles != nil {
		for _, r := range *in.Roles {
			role := appauthz.Role{Name: r.Name}
			if r.Groups != nil {
				role.Groups = slices.Clone(*r.Groups)
			}
			if r.McpTools != nil {
				role.MCPTools = slices.Clone(*r.McpTools)
			}
			out.Roles = append(out.Roles, role)
		}
	}
	if in.ApiKeyRoles != nil {
		out.APIKeyRoles = slices.Clone(*in.ApiKeyRoles)
	}
	if in.EnforceMcp != nil {
		out.EnforceMCP = *in.EnforceMcp
	}
	if in.JwtHeader != nil {
		out.JWTHeader = string(*in.JwtHeader)
	}
	return out
}

func (s *Service) authorizationToAPI() *api.ServiceAuthorizationConfig {
	a := s.Auth.Authorization
	if a == nil {
		return nil
	}
	roles := make([]api.ServiceRoleMapping, 0, len(a.Roles))
	for _, r := range a.Roles {
		groups := slices.Clone(r.Groups)
		tools := slices.Clone(r.MCPTools)
		roles = append(roles, api.ServiceRoleMapping{Name: r.Name, Groups: &groups, McpTools: &tools})
	}
	apiKeyRoles := slices.Clone(a.APIKeyRoles)
	enforce := a.EnforceMCP
	out := &api.ServiceAuthorizationConfig{
		Roles:       &roles,
		ApiKeyRoles: &apiKeyRoles,
		EnforceMcp:  &enforce,
		Forwarding:  api.ServiceAuthorizationConfigForwarding(a.Forwarding),
	}
	if a.JWTHeader != "" {
		h := api.ServiceAuthorizationConfigJwtHeader(a.JWTHeader)
		out.JwtHeader = &h
	}
	if a.Forwarding == appauthz.ForwardJWT {
		s.addPublicKeyToAPI(out)
	}
	return out
}

func (s *Service) addPublicKeyToAPI(out *api.ServiceAuthorizationConfig) {
	key, err := s.upstreamSigningKey()
	if err != nil {
		log.Debugf("service %s: no upstream identity key for API response: %v", s.ID, err)
		return
	}
	pub := key.Public().(ed25519.PublicKey)
	pemStr, err := appauthz.PublicKeyPEM(pub)
	if err != nil {
		log.Debugf("service %s: encode upstream public key: %v", s.ID, err)
		return
	}
	kid := appauthz.KeyID(pub)
	out.PublicKeyPem = &pemStr
	out.KeyId = &kid
}
