package connector

import (
	"slices"
	"strings"
)

// google accepts only Workspace accounts in the connection's domains. The hd claim is Google's
// statement of which Workspace the account belongs to, and personal accounts don't have one.
var google = adapter{
	validate: requireDomains,
	subject: func(cfg Config, c claims) (string, error) {
		if !c.EmailVerified {
			return "", refuse(ReasonEmailNotVerified, "")
		}
		if !slices.Contains(cfg.Domains, strings.ToLower(c.HostedDomain)) {
			return "", refuse(ReasonWrongDomain, "hd not allowed for this connection")
		}
		return cfg.Issuer + "|" + c.Subject, nil
	},
	existingProvider: func(c claims) (string, string) { return "google.com", c.Subject },
}
