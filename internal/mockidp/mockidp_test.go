package mockidp

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const redirectURL = "http://127.0.0.1:1/callback"

func start(t *testing.T, identities ...Identity) *Provider {
	t.Helper()
	p, err := Start(Config{
		Name:         "test",
		Addr:         "127.0.0.1:0",
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		Identities:   identities,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := p.Shutdown(); err != nil {
			t.Error(err)
		}
	})
	return p
}

var microsoftUser = Identity{
	Subject:       "sub-1",
	Email:         "user@customer-c.test",
	Name:          "Customer C User",
	EmailVerified: true,
	Extra:         map[string]any{"tid": "tenant-c", "oid": "oid-1", "admin": true},
}

// client is the OIDC relying party a real broker would be, with its checks left on.
type client struct {
	oauth    oauth2.Config
	verifier *oidc.IDTokenVerifier
}

func newClient(t *testing.T, p *Provider) client {
	t.Helper()
	provider, err := oidc.NewProvider(context.Background(), p.Issuer())
	if err != nil {
		t.Fatal(err)
	}
	return client{
		oauth: oauth2.Config{
			ClientID:     "client-id",
			ClientSecret: "client-secret",
			Endpoint:     provider.Endpoint(),
			RedirectURL:  redirectURL,
			Scopes:       []string{oidc.ScopeOpenID, "email", "profile"},
		},
		verifier: provider.Verifier(&oidc.Config{ClientID: "client-id"}),
	}
}

// authorize follows the authorization request up to its redirect, and returns the code.
func (c client) authorize(t *testing.T, state, nonce, verifier string) string {
	t.Helper()
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	res, err := noRedirect.Get(c.oauth.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier)))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(res.Body)
		t.Fatalf("authorize = %d, want a redirect: %s", res.StatusCode, body)
	}
	location, err := url.Parse(res.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if got := location.Query().Get("state"); got != state {
		t.Fatalf("redirect state = %q, want %q", got, state)
	}
	return location.Query().Get("code")
}

func TestFullSignInWithProviderClaims(t *testing.T) {
	p := start(t, microsoftUser)
	c := newClient(t, p)
	if err := p.SignInNext("sub-1"); err != nil {
		t.Fatal(err)
	}

	verifier := oauth2.GenerateVerifier()
	code := c.authorize(t, "state-1", "nonce-1", verifier)

	token, err := c.oauth.Exchange(context.Background(), code, oauth2.VerifierOption(verifier))
	if err != nil {
		t.Fatal(err)
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		t.Fatal("no id_token in the token response")
	}
	idToken, err := c.verifier.Verify(context.Background(), rawIDToken)
	if err != nil {
		t.Fatal(err)
	}

	if idToken.Issuer != p.Issuer() {
		t.Errorf("iss = %q, want %q", idToken.Issuer, p.Issuer())
	}
	if idToken.Subject != "sub-1" {
		t.Errorf("sub = %q, want sub-1", idToken.Subject)
	}
	if idToken.Nonce != "nonce-1" {
		t.Errorf("nonce = %q, want nonce-1", idToken.Nonce)
	}

	var claims struct {
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		Name          string `json:"name"`
		TID           string `json:"tid"`
		OID           string `json:"oid"`
		Admin         bool   `json:"admin"`
	}
	if err := idToken.Claims(&claims); err != nil {
		t.Fatal(err)
	}
	if claims.Email != "user@customer-c.test" || !claims.EmailVerified || claims.Name != "Customer C User" {
		t.Errorf("standard claims = %+v", claims)
	}
	if claims.TID != "tenant-c" || claims.OID != "oid-1" {
		t.Errorf("Microsoft claims = %+v, want tenant-c and oid-1", claims)
	}
	if !claims.Admin {
		t.Error("admin claim missing: the provider needs to be able to send claims it shouldn't")
	}
}

func TestWrongPKCEVerifierIsRejected(t *testing.T) {
	p := start(t, microsoftUser)
	c := newClient(t, p)
	if err := p.SignInNext("sub-1"); err != nil {
		t.Fatal(err)
	}

	code := c.authorize(t, "state-1", "nonce-1", oauth2.GenerateVerifier())

	if _, err := c.oauth.Exchange(context.Background(), code, oauth2.VerifierOption(oauth2.GenerateVerifier())); err == nil {
		t.Fatal("Exchange() succeeded with the wrong verifier")
	}
}

func TestTokenFromAnotherProviderFailsVerification(t *testing.T) {
	providerA := start(t, microsoftUser)
	providerB := start(t, microsoftUser)
	if providerA.Issuer() == providerB.Issuer() {
		t.Fatalf("both providers have issuer %q", providerA.Issuer())
	}

	a := newClient(t, providerA)
	b := newClient(t, providerB)
	if err := providerA.SignInNext("sub-1"); err != nil {
		t.Fatal(err)
	}

	verifier := oauth2.GenerateVerifier()
	code := a.authorize(t, "state-1", "nonce-1", verifier)
	token, err := a.oauth.Exchange(context.Background(), code, oauth2.VerifierOption(verifier))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := b.verifier.Verify(context.Background(), token.Extra("id_token").(string)); err == nil {
		t.Fatal("provider B's verifier accepted provider A's token")
	}
}

func TestChooserListsIdentitiesAndPicksOne(t *testing.T) {
	second := Identity{Subject: "sub-2", Email: "second@customer-c.test", EmailVerified: true}
	p := start(t, microsoftUser, second)
	c := newClient(t, p)

	authURL := c.oauth.AuthCodeURL("state-1", oidc.Nonce("nonce-1"))
	res, err := http.Get(authURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusOK {
		t.Fatalf("authorize without a choice = %d, want the chooser page", res.StatusCode)
	}
	page := string(body)
	for _, want := range []string{"user@customer-c.test", "second@customer-c.test", "mock_user=sub-2"} {
		if !strings.Contains(page, want) {
			t.Errorf("chooser page is missing %q", want)
		}
	}

	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	chosen, err := noRedirect.Get(authURL + "&mock_user=sub-2")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = chosen.Body.Close() }()
	if chosen.StatusCode != http.StatusFound {
		t.Fatalf("authorize with a choice = %d, want a redirect", chosen.StatusCode)
	}
	location, err := url.Parse(chosen.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}

	token, err := c.oauth.Exchange(context.Background(), location.Query().Get("code"))
	if err != nil {
		t.Fatal(err)
	}
	idToken, err := c.verifier.Verify(context.Background(), token.Extra("id_token").(string))
	if err != nil {
		t.Fatal(err)
	}
	if idToken.Subject != "sub-2" {
		t.Fatalf("signed in as %q, want sub-2", idToken.Subject)
	}
}

func TestRejectedRequestDoesNotLeaveAUserQueued(t *testing.T) {
	second := Identity{Subject: "sub-2", Email: "second@customer-c.test", EmailVerified: true}
	p := start(t, microsoftUser, second)
	c := newClient(t, p)

	// A wrong client id is rejected after the middleware has queued sub-2.
	wrong := c.oauth
	wrong.ClientID = "wrong-client"
	res, err := http.Get(wrong.AuthCodeURL("state-1") + "&mock_user=sub-2")
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if res.StatusCode == http.StatusFound {
		t.Fatal("request with a wrong client id was accepted")
	}

	if err := p.SignInNext("sub-1"); err != nil {
		t.Fatal(err)
	}
	verifier := oauth2.GenerateVerifier()
	code := c.authorize(t, "state-2", "nonce-2", verifier)
	token, err := c.oauth.Exchange(context.Background(), code, oauth2.VerifierOption(verifier))
	if err != nil {
		t.Fatal(err)
	}
	idToken, err := c.verifier.Verify(context.Background(), token.Extra("id_token").(string))
	if err != nil {
		t.Fatal(err)
	}
	if idToken.Subject != "sub-1" {
		t.Fatalf("signed in as %q, want sub-1", idToken.Subject)
	}
}

func TestUnknownIdentityIsRefused(t *testing.T) {
	p := start(t, microsoftUser)
	c := newClient(t, p)

	if err := p.SignInNext("nobody"); err == nil {
		t.Fatal("SignInNext() accepted an unknown subject")
	}

	res, err := http.Get(c.oauth.AuthCodeURL("state-1") + "&mock_user=nobody")
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("authorize with an unknown user = %d, want %d", res.StatusCode, http.StatusBadRequest)
	}
}
