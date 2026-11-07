package middleware

import "strings"

const trustedIdentityMiddlewareID = "llm_identity_inject"

// appAuthzMiddlewareID may write the identity it resolved after
// authentication, including a signed token in Authorization. It must stay in
// step with appauthz.MiddlewareID.
const appAuthzMiddlewareID = "app_authz"

var appAuthzHeaders = []string{
	"X-NetBird-User-Id",
	"X-NetBird-Roles",
	"X-NetBird-Auth-Method",
	"X-NetBird-Identity",
	"X-NetBird-MCP-Tools",
	"Authorization",
}

var denyHeaders = []string{
	"Authorization",
	"Connection",
	"Cookie",
	"Set-Cookie",
	"Forwarded",
	"Keep-Alive",
	"Proxy-Authorization",
	"Proxy-Authenticate",
	"Proxy-Connection",
	"TE",
	"Upgrade",
	"Via",
	"X-Real-IP",
	"X-Request-ID",
	"Host",
	"Content-Length",
	"Transfer-Encoding",
	"Trailer",
}

var denyHeaderPrefixes = []string{
	"X-Authenticated-",
	"X-Forwarded-",
	"X-Remote-",
	"X-NetBird-",
}

// IsHeaderMutable reports whether a middleware is allowed to mutate
// the named header. The check is case-insensitive and honours both
// exact matches and the compiled-in prefix denylist.
func IsHeaderMutable(name string) bool {
	if name == "" {
		return false
	}
	if !isHeaderFieldName(name) {
		return false
	}
	for _, d := range denyHeaders {
		if strings.EqualFold(d, name) {
			return false
		}
	}
	for _, p := range denyHeaderPrefixes {
		if len(name) >= len(p) && strings.EqualFold(name[:len(p)], p) {
			return false
		}
	}
	return true
}

// isHeaderFieldName reports whether name is a valid RFC 7230 header
// field-name (a non-empty token of tchar octets). Rejects names with
// spaces, control characters, or separators that could enable header
// injection or smuggling when applied to the outbound request.
func isHeaderFieldName(name string) bool {
	for i := 0; i < len(name); i++ {
		c := name[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			continue
		}
		switch c {
		case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
			continue
		default:
			return false
		}
	}
	return true
}

// FilterHeaderMutations returns the subsets of HeadersAdd and
// HeadersRemove that are safe to apply, plus the list of blocked
// header names so the dispatcher can increment the blocked-header
// metric.
func FilterHeaderMutations(m *Mutations) (filteredAdd []KV, filteredRemove []string, blocked []string) {
	return filterHeaderMutations(m, "")
}

// FilterHeaderMutationsFor is FilterHeaderMutations with the per-middleware
// identity exemptions applied, as the chain does for middlewareID.
func FilterHeaderMutationsFor(m *Mutations, middlewareID string) (filteredAdd []KV, filteredRemove []string, blocked []string) {
	return filterHeaderMutations(m, middlewareID)
}

func filterHeaderMutations(m *Mutations, middlewareID string) (filteredAdd []KV, filteredRemove []string, blocked []string) {
	if m == nil {
		return nil, nil, nil
	}
	for _, kv := range m.HeadersAdd {
		if IsHeaderMutable(kv.Key) || isTrustedIdentityHeader(middlewareID, kv.Key) {
			filteredAdd = append(filteredAdd, kv)
			continue
		}
		blocked = append(blocked, kv.Key)
	}
	for _, name := range m.HeadersRemove {
		if IsHeaderMutable(name) || isTrustedIdentityHeader(middlewareID, name) {
			filteredRemove = append(filteredRemove, name)
			continue
		}
		blocked = append(blocked, name)
	}
	return filteredAdd, filteredRemove, blocked
}

func isTrustedIdentityHeader(middlewareID, name string) bool {
	switch middlewareID {
	case trustedIdentityMiddlewareID:
		return strings.EqualFold(name, "x-netbird-user-id") ||
			strings.EqualFold(name, "x-netbird-groups")
	case appAuthzMiddlewareID:
		for _, h := range appAuthzHeaders {
			if strings.EqualFold(name, h) {
				return true
			}
		}
	}
	return false
}
