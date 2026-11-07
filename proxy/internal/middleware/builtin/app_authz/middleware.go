// Package app_authz implements the on-request middleware behind service roles
// and MCP tool authorization. After the proxy has authenticated the caller it
// resolves the caller's roles from their group IDs (or from the service's API
// key roles), denies MCP tools/call requests for tools those roles do not
// grant, and forwards the identity upstream as headers or a signed JWT.
//
// Every identity header it writes is removed first, so a client cannot
// smuggle its own roles or token past the proxy.
package app_authz

import (
	"context"
	"net/http"
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
	keyTool     = "app_authz.mcp_tool"
	keyDecision = "app_authz.decision"
)

const (
	denyCodeToolForbidden = "mcp_tool_forbidden"
	denyCodeUninspectable = "mcp_request_uninspectable"
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

// AcceptedContentTypes lists the bodies the MCP check reads.
func (m *Middleware) AcceptedContentTypes() []string {
	if !m.cfg.EnforceMCP {
		return nil
	}
	return []string{"application/json"}
}

// MetadataKeys lists the keys the middleware may emit.
func (m *Middleware) MetadataKeys() []string {
	return []string{keyRoles, keyTool, keyDecision}
}

// MutationsSupported reports that the middleware stamps headers.
func (m *Middleware) MutationsSupported() bool { return true }

// Close is a no-op; the middleware holds no resources.
func (m *Middleware) Close() error { return nil }

// Invoke resolves roles, enforces MCP tool permissions and stamps identity.
func (m *Middleware) Invoke(_ context.Context, in *middleware.Input) (*middleware.Output, error) {
	roles := m.cfg.ResolveRoles(in.AuthMethod, in.UserGroups)
	tools := m.cfg.ToolPatterns(roles)
	meta := []middleware.KV{{Key: keyRoles, Value: strings.Join(roles, ",")}}

	if m.cfg.EnforceMCP {
		if out := m.checkTools(in, tools, meta); out != nil {
			return out, nil
		}
	}

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

// checkTools returns a deny output when the request carries a tools/call the
// caller's roles do not grant, or a body that cannot be inspected.
func (m *Middleware) checkTools(in *middleware.Input, patterns []string, meta []middleware.KV) *middleware.Output {
	body, err := parseBody(in.Method, kvToHeader(in.Headers), in.Body, in.BodyTruncated)
	if err != nil {
		return deny(denyCodeUninspectable, err.Error(), "", nil, meta)
	}
	var calls []string
	var denied bool
	var firstDenied string
	mcp := &middleware.MCPDeny{Batch: body.batch}
	for _, msg := range body.messages {
		req := middleware.MCPDeniedRequest{ID: msg.id, Tool: msg.tool}
		if msg.isCall {
			calls = append(calls, msg.tool)
			if !appauthz.ToolAllowed(patterns, msg.tool) {
				if !denied {
					firstDenied = msg.tool
				}
				req.Denied = true
				denied = true
			}
		}
		mcp.Requests = append(mcp.Requests, req)
	}
	if denied {
		return deny(denyCodeToolForbidden, "your roles do not allow this MCP tool", firstDenied, mcp, meta)
	}
	if len(calls) == 1 {
		meta = append(meta, middleware.KV{Key: keyTool, Value: calls[0]})
	}
	return nil
}

func deny(code, message, tool string, mcp *middleware.MCPDeny, meta []middleware.KV) *middleware.Output {
	details := map[string]string{}
	if tool != "" {
		details["tool"] = tool
		meta = append(meta, middleware.KV{Key: keyTool, Value: tool})
	}
	return &middleware.Output{
		Decision:   middleware.DecisionDeny,
		DenyStatus: http.StatusForbidden,
		DenyReason: &middleware.DenyReason{Code: code, Message: message, Details: details, MCP: mcp},
		Metadata:   append(meta, middleware.KV{Key: keyDecision, Value: "deny"}),
	}
}

// identityMutations strips every identity header a client may have sent and
// stamps the resolved identity in the configured form. A request without an
// authenticated user gets the strip only.
func (m *Middleware) identityMutations(in *middleware.Input, roles, tools []string) (*middleware.Mutations, error) {
	mut := &middleware.Mutations{
		HeadersRemove: []string{appauthz.HeaderUserID, appauthz.HeaderRoles, appauthz.HeaderAuthMethod, appauthz.HeaderIdentity, appauthz.HeaderMCPTools},
	}
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
		// Tool patterns let an MCP server in headers mode filter tools/list
		// without copying the role mapping into the app.
		if len(tools) > 0 {
			mut.HeadersAdd = append(mut.HeadersAdd, middleware.KV{Key: appauthz.HeaderMCPTools, Value: strings.Join(tools, ",")})
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

func kvToHeader(kvs []middleware.KV) http.Header {
	h := make(http.Header, len(kvs))
	for _, kv := range kvs {
		h.Add(kv.Key, kv.Value)
	}
	return h
}
