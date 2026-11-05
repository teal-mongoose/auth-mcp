package connector

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	testClientID     = "client-id"
	testClientSecret = "very-private-client-secret"
)

var (
	signingKey = sync.OnceValue(func() *rsa.PrivateKey { return newKey() })
	forgeryKey = sync.OnceValue(func() *rsa.PrivateKey { return newKey() })
)

func newKey() *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return key
}

// fakeProvider hands back whatever token a test gives it, including ones no real provider should
// send, which is what the mock providers can't do.
type fakeProvider struct {
	server *httptest.Server

	mu          sync.Mutex
	published   *rsa.PrivateKey
	kid         string
	idToken     string
	omitIDToken bool
	tokenStatus int
	tokenBody   string
	tokenHits   int
	lastForm    url.Values
}

func newFakeProvider(t *testing.T) *fakeProvider {
	t.Helper()
	f := &fakeProvider{published: signingKey(), kid: "key-1"}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{
			"issuer":                                f.server.URL,
			"authorization_endpoint":                f.server.URL + "/authorize",
			"token_endpoint":                        f.server.URL + "/token",
			"jwks_uri":                              f.server.URL + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("GET /jwks", func(w http.ResponseWriter, _ *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		public := f.published.PublicKey
		writeJSON(w, map[string]any{"keys": []map[string]string{{
			"kty": "RSA",
			"alg": "RS256",
			"use": "sig",
			"kid": f.kid,
			"n":   base64.RawURLEncoding.EncodeToString(public.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(public.E)).Bytes()),
		}}})
	})
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		f.tokenHits++
		f.lastForm = r.PostForm
		if f.tokenStatus != 0 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(f.tokenStatus)
			_, _ = w.Write([]byte(f.tokenBody))
			return
		}
		response := map[string]any{"access_token": "access", "token_type": "Bearer"}
		if !f.omitIDToken {
			response["id_token"] = f.idToken
		}
		writeJSON(w, response)
	})

	f.server = httptest.NewServer(mux)
	t.Cleanup(f.server.Close)
	return f
}

func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}

func (f *fakeProvider) setIDToken(token string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.idToken = token
}

// sign signs claims with key, using the published key id.
func (f *fakeProvider) sign(t *testing.T, key *rsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	f.mu.Lock()
	kid := f.kid
	f.mu.Unlock()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims(claims))
	token.Header["kid"] = kid
	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

// goodClaims are valid claims that every adapter's rules can accept. Each attack changes them.
func (f *fakeProvider) goodClaims(nonce string) map[string]any {
	now := time.Now()
	return map[string]any{
		"iss":            f.server.URL,
		"aud":            testClientID,
		"sub":            "subject-1",
		"iat":            now.Unix(),
		"exp":            now.Add(10 * time.Minute).Unix(),
		"nonce":          nonce,
		"email":          "user@customer-a.test",
		"email_verified": true,
		"name":           "A User",
		"hd":             "customer-a.test",
		"tid":            "tenant-a",
		"oid":            "object-1",
	}
}

func (f *fakeProvider) connector(t *testing.T, kind Kind) *Connector {
	t.Helper()
	c, err := New(context.Background(), Config{
		ID:           "conn",
		Kind:         kind,
		Issuer:       f.server.URL,
		ClientID:     testClientID,
		ClientSecret: testClientSecret,
		RedirectURL:  callbackURL,
		Domains:      []string{"customer-a.test"},
		TenantID:     "tenant-a",
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestBaselineIsAcceptedByEveryKind(t *testing.T) {
	// If these fail, the attack tests below would be passing for the wrong reason.
	want := map[Kind]string{
		KindGoogle:    "|subject-1",
		KindMicrosoft: "tenant-a|object-1",
		KindOkta:      "conn|subject-1",
	}
	for kind, wantSuffix := range want {
		t.Run(string(kind), func(t *testing.T) {
			f := newFakeProvider(t)
			c := f.connector(t, kind)
			_, pending := c.Begin()
			f.setIDToken(f.sign(t, signingKey(), f.goodClaims(pending.Nonce)))

			got, err := c.Complete(context.Background(), pending, Callback{State: pending.State, Code: "code"})
			if err != nil {
				t.Fatal(err)
			}
			if !strings.HasSuffix(got.Subject, wantSuffix) {
				t.Errorf("subject = %q, want it to end in %q", got.Subject, wantSuffix)
			}
		})
	}
}

func TestTokenAttacksAreRefused(t *testing.T) {
	tests := []struct {
		name string
		// claims changes good claims, signed with the real key.
		claims func(map[string]any)
		// token replaces the signing step entirely.
		token func(*testing.T, *fakeProvider, map[string]any) string
		want  Reason
	}{
		{
			name: "signed with an unpublished key",
			token: func(t *testing.T, f *fakeProvider, c map[string]any) string {
				return f.sign(t, forgeryKey(), c)
			},
			want: ReasonInvalidIDToken,
		},
		{
			name: "no signature, alg none",
			token: func(t *testing.T, _ *fakeProvider, c map[string]any) string {
				t.Helper()
				signed, err := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims(c)).SignedString(jwt.UnsafeAllowNoneSignatureType)
				if err != nil {
					t.Fatal(err)
				}
				return signed
			},
			want: ReasonInvalidIDToken,
		},
		{
			name: "HS256 signed with the public key as the secret",
			token: func(t *testing.T, _ *fakeProvider, c map[string]any) string {
				t.Helper()
				der, err := x509.MarshalPKIXPublicKey(&signingKey().PublicKey)
				if err != nil {
					t.Fatal(err)
				}
				signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims(c)).SignedString(der)
				if err != nil {
					t.Fatal(err)
				}
				return signed
			},
			want: ReasonInvalidIDToken,
		},
		{
			name: "payload changed after signing",
			token: func(t *testing.T, f *fakeProvider, c map[string]any) string {
				t.Helper()
				parts := strings.Split(f.sign(t, signingKey(), c), ".")
				c["sub"] = "someone-else"
				payload, err := json.Marshal(c)
				if err != nil {
					t.Fatal(err)
				}
				parts[1] = base64.RawURLEncoding.EncodeToString(payload)
				return strings.Join(parts, ".")
			},
			want: ReasonInvalidIDToken,
		},
		{
			name:  "not a JWT",
			token: func(*testing.T, *fakeProvider, map[string]any) string { return "not-a-jwt" },
			want:  ReasonInvalidIDToken,
		},
		{name: "wrong issuer", claims: func(c map[string]any) { c["iss"] = "https://evil.test" }, want: ReasonInvalidIDToken},
		{name: "no issuer", claims: func(c map[string]any) { delete(c, "iss") }, want: ReasonInvalidIDToken},
		{name: "wrong audience", claims: func(c map[string]any) { c["aud"] = "another-client" }, want: ReasonInvalidIDToken},
		{name: "no audience", claims: func(c map[string]any) { delete(c, "aud") }, want: ReasonInvalidIDToken},
		{name: "expired", claims: func(c map[string]any) { c["exp"] = time.Now().Add(-time.Hour).Unix() }, want: ReasonInvalidIDToken},
		{name: "no expiry", claims: func(c map[string]any) { delete(c, "exp") }, want: ReasonInvalidIDToken},
		{name: "not valid yet", claims: func(c map[string]any) { c["nbf"] = time.Now().Add(time.Hour).Unix() }, want: ReasonInvalidIDToken},
		{name: "claim of the wrong type", claims: func(c map[string]any) { c["email_verified"] = "true" }, want: ReasonInvalidIDToken},
		{name: "wrong nonce", claims: func(c map[string]any) { c["nonce"] = "replayed-nonce" }, want: ReasonNonceMismatch},
		{name: "no nonce", claims: func(c map[string]any) { delete(c, "nonce") }, want: ReasonNonceMismatch},
		{name: "several audiences and no azp", claims: func(c map[string]any) { c["aud"] = []string{testClientID, "another-client"} }, want: ReasonWrongAudience},
		{
			name: "several audiences issued to another client",
			claims: func(c map[string]any) {
				c["aud"] = []string{testClientID, "another-client"}
				c["azp"] = "another-client"
			},
			want: ReasonWrongAudience,
		},
		{name: "azp names another client", claims: func(c map[string]any) { c["azp"] = "another-client" }, want: ReasonWrongAudience},
		{name: "no subject", claims: func(c map[string]any) { delete(c, "sub") }, want: ReasonMissingClaim},
	}

	for _, kind := range []Kind{KindGoogle, KindMicrosoft, KindOkta} {
		for _, tt := range tests {
			t.Run(string(kind)+"/"+tt.name, func(t *testing.T) {
				f := newFakeProvider(t)
				c := f.connector(t, kind)
				_, pending := c.Begin()

				claims := f.goodClaims(pending.Nonce)
				if tt.claims != nil {
					tt.claims(claims)
				}
				token := ""
				if tt.token != nil {
					token = tt.token(t, f, claims)
				} else {
					token = f.sign(t, signingKey(), claims)
				}
				f.setIDToken(token)

				got, err := c.Complete(context.Background(), pending, Callback{State: pending.State, Code: "code"})
				assertRefused(t, err, tt.want)
				if got != (Identity{}) {
					t.Errorf("identity = %+v alongside a refusal", got)
				}
			})
		}
	}
}

func TestProviderRulesAreEnforced(t *testing.T) {
	tests := []struct {
		name   string
		kind   Kind
		claims func(map[string]any)
		want   Reason // Empty means accepted.
	}{
		{name: "personal account has no hd", kind: KindGoogle, claims: func(c map[string]any) { delete(c, "hd") }, want: ReasonWrongDomain},
		{name: "another workspace", kind: KindGoogle, claims: func(c map[string]any) { c["hd"] = "customer-b.test" }, want: ReasonWrongDomain},
		{name: "hd with the right ending", kind: KindGoogle, claims: func(c map[string]any) { c["hd"] = "evil-customer-a.test" }, want: ReasonWrongDomain},
		{name: "email not verified", kind: KindGoogle, claims: func(c map[string]any) { c["email_verified"] = false }, want: ReasonEmailNotVerified},
		{name: "verification missing", kind: KindGoogle, claims: func(c map[string]any) { delete(c, "email_verified") }, want: ReasonEmailNotVerified},
		{name: "hd in another case", kind: KindGoogle, claims: func(c map[string]any) { c["hd"] = "CUSTOMER-A.test" }},

		{name: "another tenant", kind: KindMicrosoft, claims: func(c map[string]any) { c["tid"] = "tenant-b" }, want: ReasonWrongTenant},
		{name: "no tenant", kind: KindMicrosoft, claims: func(c map[string]any) { delete(c, "tid") }, want: ReasonMissingClaim},
		{name: "no object id", kind: KindMicrosoft, claims: func(c map[string]any) { delete(c, "oid") }, want: ReasonMissingClaim},
		{name: "email is not what's checked", kind: KindMicrosoft, claims: func(c map[string]any) {
			delete(c, "email")
			delete(c, "email_verified")
		}},
		{name: "another domain's email doesn't change the key", kind: KindMicrosoft, claims: func(c map[string]any) { c["email"] = "ceo@customer-b.test" }},

		{name: "no email", kind: KindOkta, claims: func(c map[string]any) { delete(c, "email") }, want: ReasonMissingClaim},
		{name: "unverified email", kind: KindOkta, claims: func(c map[string]any) { c["email_verified"] = false }, want: ReasonEmailNotVerified},
		{name: "another domain", kind: KindOkta, claims: func(c map[string]any) { c["email"] = "user@customer-b.test" }, want: ReasonWrongDomain},
		{name: "subdomain of an allowed domain", kind: KindOkta, claims: func(c map[string]any) { c["email"] = "user@sub.customer-a.test" }, want: ReasonWrongDomain},
		{name: "allowed domain as a prefix", kind: KindOkta, claims: func(c map[string]any) { c["email"] = "user@customer-a.test.evil.test" }, want: ReasonWrongDomain},
		{name: "two at signs", kind: KindOkta, claims: func(c map[string]any) { c["email"] = "user@evil.test@customer-a.test" }, want: ReasonWrongDomain},
		{name: "no local part", kind: KindOkta, claims: func(c map[string]any) { c["email"] = "@customer-a.test" }, want: ReasonWrongDomain},
		{name: "no at sign", kind: KindOkta, claims: func(c map[string]any) { c["email"] = "customer-a.test" }, want: ReasonWrongDomain},
		{name: "domain in another case", kind: KindOkta, claims: func(c map[string]any) { c["email"] = "User@CUSTOMER-A.test" }},
	}

	for _, tt := range tests {
		t.Run(string(tt.kind)+"/"+tt.name, func(t *testing.T) {
			f := newFakeProvider(t)
			c := f.connector(t, tt.kind)
			_, pending := c.Begin()
			claims := f.goodClaims(pending.Nonce)
			tt.claims(claims)
			f.setIDToken(f.sign(t, signingKey(), claims))

			_, err := c.Complete(context.Background(), pending, Callback{State: pending.State, Code: "code"})
			if tt.want == "" {
				if err != nil {
					t.Fatalf("Complete() = %v, want success", err)
				}
				return
			}
			assertRefused(t, err, tt.want)
		})
	}
}

func TestMicrosoftKeyIgnoresEmail(t *testing.T) {
	f := newFakeProvider(t)
	c := f.connector(t, KindMicrosoft)

	subjects := map[string]bool{}
	for _, email := range []string{"first@customer-a.test", "renamed@elsewhere.test"} {
		_, pending := c.Begin()
		claims := f.goodClaims(pending.Nonce)
		claims["email"] = email
		f.setIDToken(f.sign(t, signingKey(), claims))

		got, err := c.Complete(context.Background(), pending, Callback{State: pending.State, Code: "code"})
		if err != nil {
			t.Fatal(err)
		}
		subjects[got.Subject] = true
	}
	if len(subjects) != 1 {
		t.Errorf("renaming an email changed the identity: %v", subjects)
	}
}

func TestCallbackProblemsNeverReachTheProvider(t *testing.T) {
	tests := []struct {
		name       string
		callback   func(Pending) Callback
		pending    func(Pending) Pending
		want       Reason
		wantDetail string
	}{
		{name: "wrong state", callback: func(Pending) Callback { return Callback{State: "guess", Code: "code"} }, want: ReasonStateMismatch},
		{name: "no state", callback: func(Pending) Callback { return Callback{Code: "code"} }, want: ReasonStateMismatch},
		{
			name:     "empty state on both sides",
			callback: func(Pending) Callback { return Callback{Code: "code"} },
			pending:  func(p Pending) Pending { p.State = ""; return p },
			want:     ReasonStateMismatch,
		},
		{name: "provider error with bad state", callback: func(Pending) Callback { return Callback{State: "guess", Error: "access_denied"} }, want: ReasonStateMismatch},
		{name: "provider error", callback: func(p Pending) Callback { return Callback{State: p.State, Error: "access_denied"} }, want: ReasonProviderError, wantDetail: "access_denied"},
		{name: "provider error with odd text", callback: func(p Pending) Callback { return Callback{State: p.State, Error: "<script>\nforged log line"} }, want: ReasonProviderError, wantDetail: "unrecognized error"},
		{name: "no code", callback: func(p Pending) Callback { return Callback{State: p.State} }, want: ReasonMissingCode},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFakeProvider(t)
			c := f.connector(t, KindOkta)
			_, pending := c.Begin()
			callback := tt.callback(pending)
			if tt.pending != nil {
				pending = tt.pending(pending)
			}

			_, err := c.Complete(context.Background(), pending, callback)
			assertRefused(t, err, tt.want)
			if tt.wantDetail != "" && !strings.Contains(err.Error(), tt.wantDetail) {
				t.Errorf("err = %q, want it to contain %q", err, tt.wantDetail)
			}

			f.mu.Lock()
			defer f.mu.Unlock()
			if f.tokenHits != 0 {
				t.Errorf("token endpoint was called %d times", f.tokenHits)
			}
		})
	}
}

func TestTokenResponseProblems(t *testing.T) {
	t.Run("provider rejects the code, and its response stays out of the error", func(t *testing.T) {
		f := newFakeProvider(t)
		c := f.connector(t, KindOkta)
		_, pending := c.Begin()
		f.tokenStatus = http.StatusBadRequest
		f.tokenBody = `{"error":"invalid_grant","error_description":"private provider detail"}`

		_, err := c.Complete(context.Background(), pending, Callback{State: pending.State, Code: "code"})
		assertRefused(t, err, ReasonExchangeFailed)
		if strings.Contains(err.Error(), "private provider detail") {
			t.Errorf("err = %q includes the provider's response", err)
		}
	})

	t.Run("no ID token", func(t *testing.T) {
		f := newFakeProvider(t)
		c := f.connector(t, KindOkta)
		_, pending := c.Begin()
		f.omitIDToken = true

		_, err := c.Complete(context.Background(), pending, Callback{State: pending.State, Code: "code"})
		assertRefused(t, err, ReasonMissingIDToken)
	})

	t.Run("cancelled request", func(t *testing.T) {
		f := newFakeProvider(t)
		c := f.connector(t, KindOkta)
		_, pending := c.Begin()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		_, err := c.Complete(ctx, pending, Callback{State: pending.State, Code: "code"})
		assertRefused(t, err, ReasonExchangeFailed)
	})
}

func TestBeginUsesPKCEAndFreshValues(t *testing.T) {
	f := newFakeProvider(t)
	c := f.connector(t, KindOkta)

	authURL, first := c.Begin()
	_, second := c.Begin()

	if first.State == second.State || first.Nonce == second.Nonce || first.Verifier == second.Verifier {
		t.Errorf("two sign-ins shared a value: %+v and %+v", first, second)
	}

	parsed, err := url.Parse(authURL)
	if err != nil {
		t.Fatal(err)
	}
	query := parsed.Query()
	sum := sha256.Sum256([]byte(first.Verifier))
	want := map[string]string{
		"state":                 first.State,
		"nonce":                 first.Nonce,
		"client_id":             testClientID,
		"redirect_uri":          callbackURL,
		"response_type":         "code",
		"scope":                 "openid email profile",
		"code_challenge_method": "S256",
		"code_challenge":        base64.RawURLEncoding.EncodeToString(sum[:]),
	}
	for name, value := range want {
		if got := query.Get(name); got != value {
			t.Errorf("%s = %q, want %q", name, got, value)
		}
	}
	if strings.Contains(authURL, first.Verifier) {
		t.Error("the PKCE verifier appears in the URL")
	}
	if strings.Contains(authURL, testClientSecret) {
		t.Error("the client secret appears in the URL")
	}
}

func TestExchangeSendsTheVerifier(t *testing.T) {
	f := newFakeProvider(t)
	c := f.connector(t, KindOkta)
	_, pending := c.Begin()
	f.setIDToken(f.sign(t, signingKey(), f.goodClaims(pending.Nonce)))

	if _, err := c.Complete(context.Background(), pending, Callback{State: pending.State, Code: "the-code"}); err != nil {
		t.Fatal(err)
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	if got := f.lastForm.Get("code_verifier"); got != pending.Verifier {
		t.Errorf("code_verifier = %q, want %q", got, pending.Verifier)
	}
	if got := f.lastForm.Get("code"); got != "the-code" {
		t.Errorf("code = %q", got)
	}
	if got := f.lastForm.Get("redirect_uri"); got != callbackURL {
		t.Errorf("redirect_uri = %q", got)
	}
}

func TestProviderKeyRotationStillWorks(t *testing.T) {
	f := newFakeProvider(t)
	c := f.connector(t, KindOkta)

	_, pending := c.Begin()
	f.setIDToken(f.sign(t, signingKey(), f.goodClaims(pending.Nonce)))
	if _, err := c.Complete(context.Background(), pending, Callback{State: pending.State, Code: "code"}); err != nil {
		t.Fatal(err)
	}

	f.mu.Lock()
	f.published = forgeryKey()
	f.kid = "key-2"
	f.mu.Unlock()

	_, pending = c.Begin()
	f.setIDToken(f.sign(t, forgeryKey(), f.goodClaims(pending.Nonce)))
	if _, err := c.Complete(context.Background(), pending, Callback{State: pending.State, Code: "code"}); err != nil {
		t.Fatalf("after rotation: %v", err)
	}
}

func TestStartupContextCanEndBeforeSignIns(t *testing.T) {
	f := newFakeProvider(t)
	ctx, cancel := context.WithCancel(context.Background())
	c, err := New(ctx, Config{
		ID: "conn", Kind: KindOkta, Issuer: f.server.URL, ClientID: testClientID, ClientSecret: testClientSecret,
		RedirectURL: callbackURL, Domains: []string{"customer-a.test"},
	})
	if err != nil {
		t.Fatal(err)
	}
	cancel()

	_, pending := c.Begin()
	f.setIDToken(f.sign(t, signingKey(), f.goodClaims(pending.Nonce)))
	if _, err := c.Complete(context.Background(), pending, Callback{State: pending.State, Code: "code"}); err != nil {
		t.Fatalf("Complete() after the startup context ended = %v", err)
	}
}

func TestDiscoveryForAnotherIssuerIsRefused(t *testing.T) {
	f := newFakeProvider(t)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{
			"issuer":                 f.server.URL,
			"authorization_endpoint": f.server.URL + "/authorize",
			"token_endpoint":         f.server.URL + "/token",
			"jwks_uri":               f.server.URL + "/jwks",
		})
	})
	impostor := httptest.NewServer(mux)
	defer impostor.Close()

	_, err := New(context.Background(), Config{
		ID: "conn", Kind: KindOkta, Issuer: impostor.URL, ClientID: testClientID, ClientSecret: testClientSecret,
		RedirectURL: callbackURL, Domains: []string{"customer-a.test"},
	})
	if err == nil {
		t.Fatal("New() accepted discovery naming another issuer")
	}
}

func TestConfigIsValidated(t *testing.T) {
	good := Config{
		ID: "conn", Kind: KindOkta, Issuer: "https://customer-a.okta.test", ClientID: "id", ClientSecret: "secret",
		RedirectURL: "https://auth.test/callback", Domains: []string{"customer-a.test"}, TenantID: "tenant-a",
	}

	tests := []struct {
		name   string
		change func(*Config)
		want   string
	}{
		{"no id", func(c *Config) { c.ID = "" }, "ID is required"},
		{"no client id", func(c *Config) { c.ClientID = "" }, "ClientID is required"},
		{"no client secret", func(c *Config) { c.ClientSecret = "" }, "ClientSecret is required"},
		{"unknown kind", func(c *Config) { c.Kind = "myspace" }, "unknown kind"},
		{"issuer over http", func(c *Config) { c.Issuer = "http://customer-a.okta.test" }, "must use https"},
		{"issuer lookalike of localhost", func(c *Config) { c.Issuer = "http://localhost.evil.test" }, "must use https"},
		{"issuer not a URL", func(c *Config) { c.Issuer = "customer-a.okta.test" }, "not an absolute URL"},
		{"redirect over http", func(c *Config) { c.RedirectURL = "http://auth.test/callback" }, "must use https"},
		{"okta without domains", func(c *Config) { c.Domains = nil }, "at least one domain"},
		{"okta with a blank domain", func(c *Config) { c.Domains = []string{" "} }, "at least one domain"},
		{"google without domains", func(c *Config) { c.Kind = KindGoogle; c.Domains = nil }, "at least one domain"},
		{"microsoft without a tenant", func(c *Config) { c.Kind = KindMicrosoft; c.TenantID = "" }, "TenantID is required"},
		{"microsoft common endpoint", func(c *Config) {
			c.Kind = KindMicrosoft
			c.Issuer = "https://login.microsoftonline.com/common/v2.0"
		}, "not a shared endpoint"},
		{"microsoft organizations endpoint", func(c *Config) {
			c.Kind = KindMicrosoft
			c.Issuer = "https://login.microsoftonline.com/Organizations/v2.0"
		}, "not a shared endpoint"},
		{"microsoft consumers endpoint", func(c *Config) {
			c.Kind = KindMicrosoft
			c.Issuer = "https://login.microsoftonline.com/consumers/v2.0"
		}, "not a shared endpoint"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := good
			tt.change(&cfg)
			_, err := cfg.validated()
			if err == nil {
				t.Fatal("validated() = nil, want an error")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("validated() = %q, want it to contain %q", err, tt.want)
			}
		})
	}

	if _, err := good.validated(); err != nil {
		t.Fatalf("good config: %v", err)
	}
	localMock := good
	localMock.Issuer = "http://127.0.0.1:9402/oidc"
	localMock.RedirectURL = "http://localhost:8701/callback"
	if _, err := localMock.validated(); err != nil {
		t.Fatalf("local mock config: %v", err)
	}
}

func TestClientSecretStaysOutOfOutput(t *testing.T) {
	cfg := Config{ID: "conn", ClientSecret: testClientSecret}

	var logged strings.Builder
	slog.New(slog.NewJSONHandler(&logged, nil)).Info("connection", "secret", cfg.ClientSecret)
	encoded, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}

	outputs := map[string]string{
		"%v":     fmt.Sprintf("%v", cfg),
		"%+v":    fmt.Sprintf("%+v", cfg),
		"%#v":    fmt.Sprintf("%#v", cfg),
		"String": cfg.ClientSecret.String(),
		"json":   string(encoded),
		"slog":   logged.String(),
	}
	for name, output := range outputs {
		if strings.Contains(output, testClientSecret) {
			t.Errorf("%s output contains the secret: %s", name, output)
		}
	}
	if string(cfg.ClientSecret) != testClientSecret {
		t.Error("the secret can't be read back")
	}
}
