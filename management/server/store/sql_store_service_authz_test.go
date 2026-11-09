package store

import (
	"context"
	"os"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	rpservice "github.com/netbirdio/netbird/management/internals/modules/reverseproxy/service"
	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/sessionkey"
	"github.com/netbirdio/netbird/proxy/appauthz"
	"github.com/netbirdio/netbird/util/crypt"
)

// TestSqlStore_ServiceAuthorizationKeyRoundtrip guards the loaders that feed
// proxy mappings. JWT forwarding derives its signing key from the service's
// session key, so a loader that returns the key still encrypted turns the
// service into a 503 on the proxy. The roles must also survive every loader.
func TestSqlStore_ServiceAuthorizationKeyRoundtrip(t *testing.T) {
	if os.Getenv("CI") == "true" && (runtime.GOOS == "darwin" || runtime.GOOS == "windows") {
		t.Skip("skip CI tests on darwin and windows")
	}

	runTestForAllEngines(t, "", func(t *testing.T, store Store) {
		ctx := context.Background()
		key, err := crypt.GenerateKey()
		require.NoError(t, err)
		enc, err := crypt.NewFieldEncrypt(key)
		require.NoError(t, err)
		store.(*SqlStore).SetFieldEncrypt(enc)

		account := newAccountWithId(ctx, "account_authz_svc", "testuser", "")
		require.NoError(t, store.SaveAccount(ctx, account))

		keys, err := sessionkey.GenerateKeyPair()
		require.NoError(t, err)
		authz := &rpservice.AuthorizationConfig{
			Roles:      []appauthz.Role{{Name: "admin", Groups: []string{"grp-ops"}, MCPTools: []string{"*"}}},
			EnforceMCP: true,
			Forwarding: appauthz.ForwardJWT,
		}
		svc := &rpservice.Service{
			ID:                "svc-authz",
			AccountID:         account.Id,
			Name:              "tickets",
			Domain:            "tickets.example",
			ProxyCluster:      "cluster.example",
			Enabled:           true,
			Mode:              rpservice.ModeHTTP,
			SessionPrivateKey: keys.PrivateKey,
			SessionPublicKey:  keys.PublicKey,
			Auth: rpservice.AuthConfig{
				BearerAuth:    &rpservice.BearerAuthConfig{Enabled: true},
				Authorization: authz,
			},
		}
		require.NoError(t, store.CreateService(ctx, svc))

		check := func(name string, got *rpservice.Service) {
			t.Helper()
			require.NotNil(t, got, name)
			assert.Equal(t, keys.PrivateKey, got.SessionPrivateKey, "%s returns the session key decrypted", name)
			_, err := appauthz.DeriveSigningKey(got.SessionPrivateKey)
			assert.NoError(t, err, "%s: the JWT signing key can be derived", name)
			require.NotNil(t, got.Auth.Authorization, "%s keeps the authorization block", name)
			assert.Equal(t, authz.Roles, got.Auth.Authorization.Roles, name)
			assert.True(t, got.Auth.Authorization.EnforceMCP, name)
		}

		byID, err := store.GetServiceByID(ctx, LockingStrengthNone, account.Id, svc.ID)
		require.NoError(t, err)
		check("GetServiceByID", byID)

		byDomain, err := store.GetServiceByDomain(ctx, svc.Domain)
		require.NoError(t, err)
		check("GetServiceByDomain", byDomain)

		accountServices, err := store.GetAccountServices(ctx, LockingStrengthNone, account.Id)
		require.NoError(t, err)
		require.Len(t, accountServices, 1)
		check("GetAccountServices", accountServices[0])

		all, err := store.GetServices(ctx, LockingStrengthNone)
		require.NoError(t, err)
		for _, s := range all {
			if s.ID == svc.ID {
				check("GetServices", s)
			}
		}

		// The account loaders feed the network map, not mappings, but they must
		// not drop the block either: a later save would erase it.
		loaded, err := store.GetAccount(ctx, account.Id)
		require.NoError(t, err)
		require.Len(t, loaded.Services, 1)
		require.NotNil(t, loaded.Services[0].Auth.Authorization, "GetAccount keeps the authorization block")
		assert.Equal(t, authz.Roles, loaded.Services[0].Auth.Authorization.Roles)
	})
}
