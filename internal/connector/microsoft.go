package connector

import (
	"errors"
	"net/url"
	"slices"
	"strings"
)

// Microsoft's shared endpoints issue tokens for many tenants. A connection must use its own tenant's
// issuer instead, so the issuer check stays on.
var sharedMicrosoftTenants = []string{"common", "organizations", "consumers"}

// microsoft accepts only the connection's tenant, and identifies people by tid and oid as Microsoft
// recommends. Tenant admins and sometimes users control email and preferred_username, so those are
// not checked, and are for display only.
var microsoft = adapter{
	validate: func(cfg Config) error {
		if cfg.TenantID == "" {
			return errors.New("TenantID is required")
		}
		if u, err := url.Parse(cfg.Issuer); err == nil {
			for _, segment := range strings.Split(u.Path, "/") {
				if slices.Contains(sharedMicrosoftTenants, strings.ToLower(segment)) {
					return errors.New("issuer must be the tenant's own, not a shared endpoint")
				}
			}
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
	// What Firebase stores as the microsoft.com uid needs confirming against a real account.
	existingProvider: func(c claims) (string, string) { return "microsoft.com", c.ObjectID },
}
