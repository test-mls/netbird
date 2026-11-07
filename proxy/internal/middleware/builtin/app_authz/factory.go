package app_authz

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/netbirdio/netbird/proxy/appauthz"
	"github.com/netbirdio/netbird/proxy/internal/middleware"
	"github.com/netbirdio/netbird/proxy/internal/middleware/builtin"
)

// Factory builds app_authz instances from the config management ships.
type Factory struct{}

// ID returns the registry identifier.
func (Factory) ID() string { return ID }

// New parses and validates the config. Unlike observer middlewares, an empty
// or malformed config is an error: app_authz is a security control, and a
// failed build leaves the target without its chain, which the proxy serves as
// 503 instead of forwarding unchecked.
func (Factory) New(rawConfig []byte) (middleware.Middleware, error) {
	var cfg appauthz.Config
	if err := json.Unmarshal(rawConfig, &cfg); err != nil {
		return nil, fmt.Errorf("decode config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validate config: %w", err)
	}
	m := &Middleware{cfg: cfg}
	if cfg.Forwarding.Mode == appauthz.ForwardJWT {
		if cfg.Forwarding.SigningKey == "" {
			return nil, errors.New("jwt forwarding requires a signing key")
		}
		key, err := appauthz.DecodeSeed(cfg.Forwarding.SigningKey)
		if err != nil {
			return nil, err
		}
		m.signer = newSigner(key, cfg.Forwarding)
	}
	return m, nil
}

func init() {
	builtin.Register(Factory{})
}
