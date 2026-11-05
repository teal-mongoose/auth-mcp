package connector

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

// Microsoft's shared tenants accept accounts from many organizations, or personal accounts. The GUID is
// the consumers tenant, which is what personal accounts' tid holds.
var sharedMicrosoftTenants = []string{"common", "organizations", "consumers", "9188040d-6c67-4c5b-b112-36a304b66dad"}

// microsoft accepts only the connection's tenant, and identifies people by tid and oid as Microsoft
// recommends. Tenant admins and sometimes users control email and preferred_username, so those are
// not checked, and are for display only.
//
// It doesn't match existing Firebase accounts. Firebase's microsoft.com record has no tenant in it, so
// a match on oid alone would ignore the tenant. Microsoft users need a link, until what Firebase stores
// has been confirmed against a real account.
var microsoft = adapter{
	validate: func(cfg Config) error {
		if cfg.TenantID == "" {
			return errors.New("TenantID is required")
		}
		if slices.Contains(sharedMicrosoftTenants, strings.ToLower(cfg.TenantID)) {
			return errors.New("TenantID must be a single organization's tenant, not a shared one")
		}
		want := fmt.Sprintf("https://login.microsoftonline.com/%s/v2.0", cfg.TenantID)
		if !cfg.localIssuer() && cfg.Issuer != want {
			return fmt.Errorf("issuer must be %s", want)
		}
		return nil
	},
	subject: func(cfg Config, c claims) (string, error) {
		if c.TenantID == "" {
			return "", refuse(ReasonMissingClaim, "tid")
		}
		if !strings.EqualFold(c.TenantID, cfg.TenantID) {
			return "", refuse(ReasonWrongTenant, "")
		}
		if c.ObjectID == "" {
			return "", refuse(ReasonMissingClaim, "oid")
		}
		return strings.ToLower(c.TenantID + "|" + c.ObjectID), nil
	},
}
