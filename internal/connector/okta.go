package connector

import (
	"fmt"
	"net/url"
	"slices"
	"strings"
)

// oktaHostSuffixes are where Okta hosts its customers' orgs. An issuer elsewhere, such as a customer's
// own domain, could be repointed at a server the customer runs. Allowing custom domains would need
// its own review.
var oktaHostSuffixes = []string{".okta.com", ".oktapreview.com", ".okta-emea.com"}

func isOktaHost(issuer string) bool {
	u, err := url.Parse(issuer)
	if err != nil {
		return false
	}
	return slices.ContainsFunc(oktaHostSuffixes, func(suffix string) bool {
		return strings.HasSuffix(strings.ToLower(u.Hostname()), suffix)
	})
}

// okta limits each customer's connection to that customer's domains. The domain check relies on what
// the customer's own Okta says, so it's a second line of defence. What really keeps customers apart
// is that identities are keyed by connection, and that a link is needed.
var okta = adapter{
	validate: func(cfg Config) error {
		if !cfg.localIssuer() && !isOktaHost(cfg.Issuer) {
			return fmt.Errorf("issuer %q isn't hosted by Okta", cfg.Issuer)
		}
		return requireDomains(cfg)
	},
	subject: func(cfg Config, c claims) (string, error) {
		if c.Email == "" {
			return "", refuse(ReasonMissingClaim, "email")
		}
		if !c.EmailVerified {
			return "", refuse(ReasonEmailNotVerified, "")
		}
		domain, ok := EmailDomain(c.Email)
		if !ok || !slices.Contains(cfg.Domains, domain) {
			return "", refuse(ReasonWrongDomain, "email domain not allowed for this connection")
		}
		return cfg.ID + "|" + c.Subject, nil
	},
}

// EmailDomain returns the lowercase part after the first @. With a second @, that part contains an
// @ and can't match an allowed domain.
func EmailDomain(email string) (string, bool) {
	local, domain, found := strings.Cut(email, "@")
	if !found || local == "" {
		return "", false
	}
	return strings.ToLower(domain), true
}
