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
	"io"
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

const (
	httpTimeout = 10 * time.Second
	// maxProviderResponse caps what a provider can make the broker read.
	maxProviderResponse = 1 << 20
)

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
	// AllowLocal accepts plain http on this machine, and lifts the issuer pin for issuers there. It's
	// only for mock providers.
	AllowLocal bool
	// AllowLocalRedirect accepts a plain http RedirectURL on this machine, while the provider stays real
	// and pinned. It's for testing a real provider before there's anywhere to deploy.
	AllowLocalRedirect bool
}

// localIssuer says whether this is a mock provider on this machine, where one is allowed.
func (c Config) localIssuer() bool {
	return c.AllowLocal && isLocalURL(c.Issuer)
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
	if err := checkURL("Issuer", c.Issuer, c.AllowLocal); err != nil {
		errs = append(errs, err)
	}
	if err := checkURL("RedirectURL", c.RedirectURL, c.AllowLocal || c.AllowLocalRedirect); err != nil {
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

// checkURL requires https. Plain http on this machine is allowed only for mock providers.
func checkURL(name, value string, allowLocal bool) error {
	u, err := url.Parse(value)
	if err != nil || u.Host == "" {
		return fmt.Errorf("%s %q is not an absolute URL", name, value)
	}
	if u.Scheme == "https" || (allowLocal && isLocalURL(value)) {
		return nil
	}
	return fmt.Errorf("%s %q must use https", name, value)
}

func isLocalURL(value string) bool {
	u, err := url.Parse(value)
	if err != nil {
		return false
	}
	host := u.Hostname()
	ip := net.ParseIP(host)
	return host == "localhost" || (ip != nil && ip.IsLoopback())
}

// checkEndpoints applies the same rule to what a provider's discovery document says. Without it, a
// provider could have the broker post its client secret and codes over plain http.
func checkEndpoints(cfg Config, endpoints ...string) error {
	for _, endpoint := range endpoints {
		if err := checkURL("discovered endpoint", endpoint, cfg.AllowLocal); err != nil {
			return err
		}
	}
	return nil
}

// limitedTransport stops a provider from exhausting the broker's memory with a huge response.
type limitedTransport struct{}

func (limitedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	res, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	res.Body = limitedBody{Reader: io.LimitReader(res.Body, maxProviderResponse), Closer: res.Body}
	return res, nil
}

type limitedBody struct {
	io.Reader
	io.Closer
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
	ReasonIssuerMismatch   Reason = "issuer_mismatch"
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
	// Issuer is the iss parameter (RFC 9207), which some providers send to prevent mix-ups.
	Issuer string
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

	httpClient := &http.Client{
		Timeout:   httpTimeout,
		Transport: limitedTransport{},
		// A provider's endpoints don't redirect, and following one could lead anywhere.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	provider, err := oidc.NewProvider(oidc.ClientContext(ctx, httpClient), cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("connection %q: discovery: %w", cfg.ID, err)
	}
	var discovered struct {
		JWKSURI string `json:"jwks_uri"`
	}
	if err := provider.Claims(&discovered); err != nil {
		return nil, fmt.Errorf("connection %q: discovery: %w", cfg.ID, err)
	}
	if err := checkEndpoints(cfg, provider.Endpoint().AuthURL, provider.Endpoint().TokenURL, discovered.JWKSURI); err != nil {
		return nil, fmt.Errorf("connection %q: %w", cfg.ID, err)
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
	if callback.Issuer != "" && callback.Issuer != c.config.Issuer {
		return Identity{}, refuse(ReasonIssuerMismatch, "")
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
