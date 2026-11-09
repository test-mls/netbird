package manager

import (
	"context"
	"fmt"

	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/service"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/shared/management/status"
)

// validateAuthorizationGroups checks that every group a role maps from exists
// in the service's account. A group from another account, or one that no
// longer exists, would never match a caller, so the role would silently grant
// nothing.
func validateAuthorizationGroups(ctx context.Context, s store.Store, accountID string, svc *service.Service) error {
	ids := svc.Auth.Authorization.GroupIDs()
	if len(ids) == 0 {
		return nil
	}
	groups, err := s.GetGroupsByIDs(ctx, store.LockingStrengthNone, accountID, ids)
	if err != nil {
		return fmt.Errorf("load role groups: %w", err)
	}
	for _, id := range ids {
		if _, ok := groups[id]; !ok {
			return status.Errorf(status.InvalidArgument, "authorization: role group %s not found in the account", id)
		}
	}
	return nil
}
