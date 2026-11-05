package connector

import (
	"slices"
	"strings"
)

// okta limits each customer's connection to that customer's domains, so one customer's Okta can't
// claim another customer's people. The issuer check has already tied the token to this Okta.
var okta = adapter{
	validate: requireDomains,
	subject: func(cfg Config, c claims) (string, error) {
		if c.Email == "" {
			return "", refuse(ReasonMissingClaim, "email")
		}
		if !c.EmailVerified {
			return "", refuse(ReasonEmailNotVerified, "")
		}
		domain, ok := emailDomain(c.Email)
		if !ok || !slices.Contains(cfg.Domains, domain) {
			return "", refuse(ReasonWrongDomain, "email domain not allowed for this connection")
		}
		return cfg.ID + "|" + c.Subject, nil
	},
}

// emailDomain returns the lowercase part after the first @. With a second @, that part contains an
// @ and can't match an allowed domain.
func emailDomain(email string) (string, bool) {
	local, domain, found := strings.Cut(email, "@")
	if !found || local == "" {
		return "", false
	}
	return strings.ToLower(domain), true
}
