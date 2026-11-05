// Package connector signs people in at an OIDC provider and returns who they verifiably are.
//
// Each connection is one provider setup, such as one customer's Okta. The shared code here runs the
// authorization code flow with PKCE and validates the ID token. A small adapter per provider then
// applies that provider's rules, and decides which claims identify the person. A new OIDC provider
// needs only a new adapter.
//
// Identity deliberately has no field for roles or permissions, so nothing a provider sends can grant
// any. Email is for display, and must never be used to decide who someone is.
package connector

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const httpTimeout = 10 * time.Second

// Kind says which provider's rules apply to a connection.
type Kind string

// Supported kinds.
const (
	KindGoogle    Kind = "google"
	KindMicrosoft Kind = "microsoft"
	KindOkta      Kind = "okta"
)

var adapters = map[Kind]adapter{
	KindGoogle:    google,
	KindMicrosoft: microsoft,
	KindOkta:      okta,
}

// adapter is what a provider adds to the shared flow.
type adapter struct {
	// validate checks the provider-specific parts of a connection's config.
	validate func(Config) error
	// subject applies the provider's rules, and returns the stable identifier for this person within
	// the connection, or a *Refused.
	subject func(Config, claims) (string, error)
	// existingProvider, if set, says how Firebase would have recorded someone who signed in with this
	// provider directly, before the broker existed.
	existingProvider func(claims) (providerID, providerUID string)
}

// claims are the ID token claims adapters may read. A provider's other claims are ignored.
type claims struct {
	Subject         string `json:"sub"`
	Email           string `json:"email"`
	EmailVerified   bool   `json:"email_verified"`
	Name            string `json:"name"`
	AuthorizedParty string `json:"azp"`
	HostedDomain    string `json:"hd"`
	TenantID        string `json:"tid"`
	ObjectID        string `json:"oid"`
}

// Secret is a value that must not reach logs, errors or tool output. Use string(s) to read it.
type Secret string

const redacted = "[redacted]"

// String implements fmt.Stringer.
func (Secret) String() string { return redacted }

// GoString implements fmt.GoStringer.
func (Secret) GoString() string { return redacted }

// LogValue implements slog.LogValuer.
func (Secret) LogValue() slog.Value { return slog.StringValue(redacted) }

// MarshalText implements encoding.TextMarshaler, which also covers JSON.
func (Secret) MarshalText() ([]byte, error) { return []byte(redacted), nil }

// Config describes one connection.
type Config struct {
	ID           string
	Kind         Kind
	Issuer       string
	ClientID     string
	ClientSecret Secret
	RedirectURL  string
	// Domains are the email or Workspace domains this connection may sign in. Required for Google
	// and Okta.
	Domains []string
	// TenantID is the only Microsoft tenant this connection accepts. Required for Microsoft.
	TenantID string
}

func (c Config) validated() (Config, error) {
	var errs []error
	if c.ID == "" {
		errs = append(errs, errors.New("ID is required"))
	}
	if c.ClientID == "" {
		errs = append(errs, errors.New("ClientID is required"))
	}
	if c.ClientSecret == "" {
		errs = append(errs, errors.New("ClientSecret is required"))
	}
	if err := checkURL("Issuer", c.Issuer); err != nil {
		errs = append(errs, err)
	}
	if err := checkURL("RedirectURL", c.RedirectURL); err != nil {
		errs = append(errs, err)
	}

	domains := make([]string, 0, len(c.Domains))
	for _, domain := range c.Domains {
		domains = append(domains, strings.ToLower(strings.TrimSpace(domain)))
	}
	c.Domains = domains

	if a, ok := adapters[c.Kind]; !ok {
		errs = append(errs, fmt.Errorf("unknown kind %q", c.Kind))
	} else if err := a.validate(c); err != nil {
		errs = append(errs, err)
	}

	if err := errors.Join(errs...); err != nil {
		return Config{}, fmt.Errorf("connection %q: %w", c.ID, err)
	}
	return c, nil
}

// checkURL requires https, allowing plain http only on this machine, for the mock providers.
func checkURL(name, value string) error {
	u, err := url.Parse(value)
	if err != nil || u.Host == "" {
		return fmt.Errorf("%s %q is not an absolute URL", name, value)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		host := u.Hostname()
		if ip := net.ParseIP(host); host == "localhost" || (ip != nil && ip.IsLoopback()) {
			return nil
		}
	}
	return fmt.Errorf("%s %q must use https", name, value)
}

func requireDomains(c Config) error {
	if len(c.Domains) == 0 || slices.Contains(c.Domains, "") {
		return errors.New("at least one domain is required, with none blank")
	}
	return nil
}

// Reason says why a sign-in was refused, in a form that's safe to log and show to admins.
type Reason string

// Refusal reasons.
const (
	ReasonStateMismatch    Reason = "state_mismatch"
	ReasonProviderError    Reason = "provider_error"
	ReasonMissingCode      Reason = "missing_code"
	ReasonExchangeFailed   Reason = "exchange_failed"
	ReasonMissingIDToken   Reason = "missing_id_token"
	ReasonInvalidIDToken   Reason = "invalid_id_token"
	ReasonNonceMismatch    Reason = "nonce_mismatch"
	ReasonWrongAudience    Reason = "wrong_audience"
	ReasonMissingClaim     Reason = "missing_claim"
	ReasonWrongTenant      Reason = "wrong_tenant"
	ReasonWrongDomain      Reason = "wrong_domain"
	ReasonEmailNotVerified Reason = "email_not_verified"
)

// Refused is returned when a sign-in fails. Error reveals only the reason and a short detail. Err
// may hold a provider's raw response, so don't log it.
type Refused struct {
	Reason Reason
	Detail string
	Err    error
}

func (r *Refused) Error() string {
	if r.Detail == "" {
		return "sign-in refused: " + string(r.Reason)
	}
	return "sign-in refused: " + string(r.Reason) + ": " + r.Detail
}

// Unwrap implements errors.Unwrap.
func (r *Refused) Unwrap() error { return r.Err }

func refuse(reason Reason, detail string) error {
	return &Refused{Reason: reason, Detail: detail}
}

// Identity is a person the provider has vouched for. ConnectionID and Subject together identify them.
type Identity struct {
	ConnectionID string
	Subject      string
	// Email and Name are for display only. Never use them to identify anyone or decide access.
	Email string
	Name  string
	// ExistingProviderID and ExistingProviderUID find someone who signed in with this provider through
	// Firebase directly, if the provider supports that. Otherwise they're empty.
	ExistingProviderID  string
	ExistingProviderUID string
}

// Pending is what must be kept server-side between Begin and Complete. The caller must store it
// privately, use it once and expire it, because that's what makes state single-use.
type Pending struct {
	State    string
	Nonce    string
	Verifier string
}

// Callback is what the provider sent back to the redirect URL.
type Callback struct {
	State string
	Code  string
	Error string
}

// Connector runs sign-ins for one connection.
type Connector struct {
	config   Config
	adapter  adapter
	oauth    oauth2.Config
	verifier *oidc.IDTokenVerifier
	http     *http.Client
}

// New checks the config, and fetches the provider's discovery document.
func New(ctx context.Context, cfg Config) (*Connector, error) {
	cfg, err := cfg.validated()
	if err != nil {
		return nil, err
	}

	httpClient := &http.Client{Timeout: httpTimeout}
	provider, err := oidc.NewProvider(oidc.ClientContext(ctx, httpClient), cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("connection %q: discovery: %w", cfg.ID, err)
	}

	return &Connector{
		config:  cfg,
		adapter: adapters[cfg.Kind],
		oauth: oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: string(cfg.ClientSecret),
			Endpoint:     provider.Endpoint(),
			RedirectURL:  cfg.RedirectURL,
			Scopes:       []string{oidc.ScopeOpenID, "email", "profile"},
		},
		// The default config checks signature, issuer, audience and expiry. Those checks stay on.
		verifier: provider.Verifier(&oidc.Config{ClientID: cfg.ClientID}),
		http:     httpClient,
	}, nil
}

// Begin returns the URL to send the person to, and what to keep until they come back.
func (c *Connector) Begin() (authURL string, pending Pending) {
	pending = Pending{
		State:    rand.Text(),
		Nonce:    rand.Text(),
		Verifier: oauth2.GenerateVerifier(),
	}
	authURL = c.oauth.AuthCodeURL(pending.State,
		oidc.Nonce(pending.Nonce),
		oauth2.S256ChallengeOption(pending.Verifier))
	return authURL, pending
}

// providerErrorCode keeps provider-supplied text out of logs unless it looks like an OAuth error code.
var providerErrorCode = regexp.MustCompile(`^[a-z0-9_]{1,64}$`)

// Complete finishes a sign-in. Any failure is a *Refused.
func (c *Connector) Complete(ctx context.Context, pending Pending, callback Callback) (Identity, error) {
	// State goes first: until it matches, nothing in this request can be trusted.
	if !secretsMatch(pending.State, callback.State) {
		return Identity{}, refuse(ReasonStateMismatch, "")
	}
	if callback.Error != "" {
		detail := "unrecognized error"
		if providerErrorCode.MatchString(callback.Error) {
			detail = callback.Error
		}
		return Identity{}, refuse(ReasonProviderError, detail)
	}
	if callback.Code == "" {
		return Identity{}, refuse(ReasonMissingCode, "")
	}

	token, err := c.oauth.Exchange(oidc.ClientContext(ctx, c.http), callback.Code,
		oauth2.VerifierOption(pending.Verifier))
	if err != nil {
		return Identity{}, &Refused{Reason: ReasonExchangeFailed, Err: err}
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return Identity{}, refuse(ReasonMissingIDToken, "")
	}

	idToken, err := c.verifier.Verify(oidc.ClientContext(ctx, c.http), rawIDToken)
	if err != nil {
		return Identity{}, &Refused{Reason: ReasonInvalidIDToken, Err: err}
	}

	// go-oidc leaves the nonce to the caller.
	if !secretsMatch(pending.Nonce, idToken.Nonce) {
		return Identity{}, refuse(ReasonNonceMismatch, "")
	}

	var cl claims
	if err := idToken.Claims(&cl); err != nil {
		return Identity{}, &Refused{Reason: ReasonInvalidIDToken, Detail: "malformed claims", Err: err}
	}

	// A token meant for several clients must name this one as the party it was issued to.
	if cl.AuthorizedParty != "" && cl.AuthorizedParty != c.config.ClientID {
		return Identity{}, refuse(ReasonWrongAudience, "azp names another client")
	}
	if len(idToken.Audience) > 1 && cl.AuthorizedParty == "" {
		return Identity{}, refuse(ReasonWrongAudience, "several audiences and no azp")
	}

	if cl.Subject == "" {
		return Identity{}, refuse(ReasonMissingClaim, "sub")
	}

	subject, err := c.adapter.subject(c.config, cl)
	if err != nil {
		return Identity{}, err
	}

	identity := Identity{
		ConnectionID: c.config.ID,
		Subject:      subject,
		Email:        strings.ToLower(cl.Email),
		Name:         cl.Name,
	}
	if c.adapter.existingProvider != nil {
		identity.ExistingProviderID, identity.ExistingProviderUID = c.adapter.existingProvider(cl)
	}
	return identity, nil
}

// secretsMatch compares in constant time, and never matches an empty value.
func secretsMatch(want, got string) bool {
	return want != "" && subtle.ConstantTimeCompare([]byte(want), []byte(got)) == 1
}
