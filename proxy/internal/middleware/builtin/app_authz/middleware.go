// Package app_authz implements the on-request middleware behind service roles.
// After the proxy has authenticated the caller it resolves the caller's roles
// from their group IDs (or from the service's API key roles) and forwards the
// identity upstream as headers or a signed JWT.
//
// Every identity header it writes is removed first, so a client cannot
// smuggle its own roles or token past the proxy.
package app_authz

import (
	"context"
	"strings"

	"github.com/netbirdio/netbird/proxy/appauthz"
	"github.com/netbirdio/netbird/proxy/internal/middleware"
)

// ID is the registry identifier for this middleware.
const ID = appauthz.MiddlewareID

// Version is reported via Middleware.Version().
const Version = "0.1.0"

// Metadata keys emitted for access logs.
const (
	keyRoles    = "app_authz.roles"
	keyDecision = "app_authz.decision"
)

// Middleware enforces one service's app authorization config.
type Middleware struct {
	cfg    appauthz.Config
	signer *signer
}

// ID returns the registry identifier.
func (m *Middleware) ID() string { return ID }

// Version returns the implementation version.
func (m *Middleware) Version() string { return Version }

// Slot reports that the middleware runs before the upstream call.
func (m *Middleware) Slot() middleware.Slot { return middleware.SlotOnRequest }

// AcceptedContentTypes is empty: the middleware reads no bodies.
func (m *Middleware) AcceptedContentTypes() []string { return nil }

// MetadataKeys lists the keys the middleware may emit.
func (m *Middleware) MetadataKeys() []string {
	return []string{keyRoles, keyDecision}
}

// MutationsSupported reports that the middleware stamps headers.
func (m *Middleware) MutationsSupported() bool { return true }

// Close is a no-op; the middleware holds no resources.
func (m *Middleware) Close() error { return nil }

// Invoke resolves roles and stamps identity.
func (m *Middleware) Invoke(_ context.Context, in *middleware.Input) (*middleware.Output, error) {
	roles := m.cfg.ResolveRoles(in.AuthMethod, in.UserGroups)
	tools := m.cfg.ToolPatterns(roles)
	meta := []middleware.KV{{Key: keyRoles, Value: strings.Join(roles, ",")}}

	mutations, err := m.identityMutations(in, roles, tools)
	if err != nil {
		return nil, err
	}
	return &middleware.Output{
		Decision:  middleware.DecisionAllow,
		Metadata:  append(meta, middleware.KV{Key: keyDecision, Value: "allow"}),
		Mutations: mutations,
	}, nil
}

// identityHeaders are removed from every request before the middleware stamps
// its own, so a client cannot forge them.
func identityHeaders() []string {
	return []string{appauthz.HeaderUserID, appauthz.HeaderRoles, appauthz.HeaderAuthMethod, appauthz.HeaderIdentity}
}

// identityMutations strips every identity header a client may have sent and
// stamps the resolved identity in the configured form. A request without an
// authenticated user gets the strip only.
func (m *Middleware) identityMutations(in *middleware.Input, roles, tools []string) (*middleware.Mutations, error) {
	mut := &middleware.Mutations{HeadersRemove: identityHeaders()}
	if in.UserID == "" {
		return mut, nil
	}

	switch m.cfg.Forwarding.Mode {
	case appauthz.ForwardJWT:
		token, err := m.signer.sign(identity{
			userID:     in.UserID,
			email:      in.UserEmail,
			groups:     groupLabels(in.UserGroups, in.UserGroupNames),
			roles:      roles,
			tools:      tools,
			authMethod: in.AuthMethod,
		})
		if err != nil {
			return nil, err
		}
		header := m.cfg.Forwarding.JWTHeader()
		value := token
		if header == appauthz.HeaderAuthorize {
			value = "Bearer " + token
			mut.HeadersRemove = append(mut.HeadersRemove, appauthz.HeaderAuthorize)
		}
		mut.HeadersAdd = append(mut.HeadersAdd, middleware.KV{Key: header, Value: value})
	default:
		mut.HeadersAdd = append(mut.HeadersAdd,
			middleware.KV{Key: appauthz.HeaderUserID, Value: in.UserID},
			middleware.KV{Key: appauthz.HeaderAuthMethod, Value: in.AuthMethod},
		)
		if len(roles) > 0 {
			mut.HeadersAdd = append(mut.HeadersAdd, middleware.KV{Key: appauthz.HeaderRoles, Value: strings.Join(roles, ",")})
		}
	}
	return mut, nil
}

// groupLabels pairs group IDs with their display names, falling back to the
// ID where no name is known.
func groupLabels(ids, names []string) []string {
	if len(ids) == 0 {
		return nil
	}
	labels := make([]string, len(ids))
	for i, id := range ids {
		labels[i] = id
		if i < len(names) && names[i] != "" {
			labels[i] = names[i]
		}
	}
	return labels
}
