package appauthz

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

var (
	roleNameRegexp    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$`)
	toolPatternRegexp = regexp.MustCompile(`^[A-Za-z0-9_.*/:-]{1,128}$`)
)

// maxStarsPerPattern keeps glob matching cheap on the request path.
const maxStarsPerPattern = 4

// Validate checks the admin-provided parts of the config: role names, tool
// patterns, API key roles and the forwarding mode. It does not check the
// fields management fills in when building the proxy mapping.
func (c *Config) Validate() error {
	if len(c.Roles) > MaxRoles {
		return fmt.Errorf("at most %d roles are allowed", MaxRoles)
	}
	seen := make(map[string]struct{}, len(c.Roles))
	for i, r := range c.Roles {
		if err := validateRole(r); err != nil {
			return fmt.Errorf("role %d: %w", i, err)
		}
		if _, dup := seen[r.Name]; dup {
			return fmt.Errorf("duplicate role %q", r.Name)
		}
		seen[r.Name] = struct{}{}
	}
	for _, name := range c.APIKeyRoles {
		if _, ok := seen[name]; !ok {
			return fmt.Errorf("api key role %q is not a defined role", name)
		}
	}
	return c.Forwarding.validate()
}

func validateRole(r Role) error {
	if !roleNameRegexp.MatchString(r.Name) {
		return fmt.Errorf("invalid role name %q: use letters, digits, '_', '.', ':' or '-', up to 64 characters", r.Name)
	}
	for _, g := range r.Groups {
		if strings.TrimSpace(g) == "" {
			return errors.New("group IDs must not be empty")
		}
	}
	if len(r.MCPTools) > MaxToolsPerRole {
		return fmt.Errorf("at most %d MCP tool patterns per role", MaxToolsPerRole)
	}
	for _, p := range r.MCPTools {
		if !toolPatternRegexp.MatchString(p) || strings.Count(p, "*") > maxStarsPerPattern {
			return fmt.Errorf("invalid MCP tool pattern %q", p)
		}
	}
	return nil
}

func (f Forwarding) validate() error {
	switch f.Mode {
	case ForwardHeaders:
		if f.Header != "" {
			return errors.New("header is only used in jwt mode")
		}
		return nil
	case ForwardJWT:
		switch f.Header {
		case "", HeaderIdentity, HeaderAuthorize:
			return nil
		default:
			return fmt.Errorf("jwt header must be %s or %s", HeaderIdentity, HeaderAuthorize)
		}
	default:
		return fmt.Errorf("unknown forwarding mode %q", f.Mode)
	}
}

// JWTHeader returns the header the JWT is written to, defaulting to
// X-NetBird-Identity.
func (f Forwarding) JWTHeader() string {
	if f.Header == "" {
		return HeaderIdentity
	}
	return f.Header
}
