package connector

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"testing"

	"github.com/teal-mongoose/auth-mcp/internal/fixtures"
	"github.com/teal-mongoose/auth-mcp/internal/mockidp"
)

const callbackURL = "http://127.0.0.1:1/callback"

// startMock runs one of the dev stack's mock providers on a free port.
func startMock(t *testing.T, name string) (*mockidp.Provider, mockidp.Config) {
	t.Helper()
	for _, cfg := range fixtures.MockProviders() {
		if cfg.Name != name {
			continue
		}
		cfg.Addr = "127.0.0.1:0"
		provider, err := mockidp.Start(cfg)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := provider.Shutdown(); err != nil {
				t.Error(err)
			}
		})
		return provider, cfg
	}
	t.Fatalf("no mock provider %q", name)
	return nil, mockidp.Config{}
}

// signIn runs a whole sign-in as subject, up to and including Complete.
func signIn(t *testing.T, c *Connector, provider *mockidp.Provider, subject string) (Identity, error) {
	t.Helper()
	authURL, pending := c.Begin()
	return c.Complete(context.Background(), pending, follow(t, provider, subject, authURL))
}

// follow signs in at the provider, and returns its redirect back as a Callback.
func follow(t *testing.T, provider *mockidp.Provider, subject, authURL string) Callback {
	t.Helper()
	if err := provider.SignInNext(subject); err != nil {
		t.Fatal(err)
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	res, err := client.Get(authURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusFound {
		t.Fatalf("authorize = %d, want a redirect", res.StatusCode)
	}
	location, err := url.Parse(res.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	return Callback{State: location.Query().Get("state"), Code: location.Query().Get("code")}
}

func TestProviderScenarios(t *testing.T) {
	googleConn := func(p *mockidp.Provider, m mockidp.Config) Config {
		return Config{
			ID: "staff-google", Kind: KindGoogle, Issuer: p.Issuer(), RedirectURL: callbackURL,
			ClientID: m.ClientID, ClientSecret: Secret(m.ClientSecret), Domains: []string{"healthspaces.test"},
		}
	}
	oktaConn := func(id, domain string) func(*mockidp.Provider, mockidp.Config) Config {
		return func(p *mockidp.Provider, m mockidp.Config) Config {
			return Config{
				ID: id, Kind: KindOkta, Issuer: p.Issuer(), RedirectURL: callbackURL,
				ClientID: m.ClientID, ClientSecret: Secret(m.ClientSecret), Domains: []string{domain},
			}
		}
	}
	// Both Microsoft mocks are read through customer C's connection, which accepts only its tenant.
	microsoftConn := func(p *mockidp.Provider, m mockidp.Config) Config {
		return Config{
			ID: "customer-c-microsoft", Kind: KindMicrosoft, Issuer: p.Issuer(), RedirectURL: callbackURL,
			ClientID: m.ClientID, ClientSecret: Secret(m.ClientSecret), TenantID: "tenant-customer-c",
		}
	}

	tests := []struct {
		name       string
		mock       string
		connection func(*mockidp.Provider, mockidp.Config) Config
		subject    string
		want       func(issuer string) Identity
		wantReason Reason
	}{
		{
			name: "google staff in the right domain", mock: fixtures.MockGoogle, connection: googleConn, subject: "google-staff",
			want: func(issuer string) Identity {
				return Identity{ConnectionID: "staff-google", Subject: issuer + "|google-staff", Email: "staff@healthspaces.test", Name: "Generic Staff"}
			},
		},
		{
			name: "google account in another domain", mock: fixtures.MockGoogle, connection: googleConn, subject: "google-other",
			wantReason: ReasonWrongDomain,
		},
		{
			name: "okta user at customer A", mock: fixtures.MockOktaA, connection: oktaConn("customer-a-okta", "customer-a.test"), subject: "okta-a-user",
			want: func(string) Identity {
				return Identity{ConnectionID: "customer-a-okta", Subject: "customer-a-okta|okta-a-user", Email: "user@customer-a.test", Name: "Customer A User"}
			},
		},
		{
			name: "okta user at customer B", mock: fixtures.MockOktaB, connection: oktaConn("customer-b-okta", "customer-b.test"), subject: "okta-b-user",
			want: func(string) Identity {
				return Identity{ConnectionID: "customer-b-okta", Subject: "customer-b-okta|okta-b-user", Email: "user@customer-b.test", Name: "Customer B User"}
			},
		},
		{
			name: "customer B's okta claiming a customer A address", mock: fixtures.MockOktaB, connection: oktaConn("customer-b-okta", "customer-b.test"), subject: "okta-b-spoof",
			wantReason: ReasonWrongDomain,
		},
		{
			// The provider also sends admin: true and roles. Identity has nowhere to put them.
			name: "okta sending admin claims gets a plain identity", mock: fixtures.MockOktaA, connection: oktaConn("customer-a-okta", "customer-a.test"), subject: "okta-a-admin-claim",
			want: func(string) Identity {
				return Identity{ConnectionID: "customer-a-okta", Subject: "customer-a-okta|okta-a-admin-claim", Email: "admin-claim@customer-a.test", Name: "Provider Sends Admin"}
			},
		},
		{
			name: "microsoft user in the right tenant", mock: fixtures.MockMicrosoftC, connection: microsoftConn, subject: "ms-c-user",
			want: func(string) Identity {
				return Identity{ConnectionID: "customer-c-microsoft", Subject: "tenant-customer-c|oid-customer-c", Email: "user@customer-c.test", Name: "Customer C User"}
			},
		},
		{
			name: "same email from another microsoft tenant", mock: fixtures.MockMicrosoftOther, connection: microsoftConn, subject: "ms-other-user",
			wantReason: ReasonWrongTenant,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider, mock := startMock(t, tt.mock)
			c, err := New(context.Background(), tt.connection(provider, mock))
			if err != nil {
				t.Fatal(err)
			}

			got, err := signIn(t, c, provider, tt.subject)

			if tt.wantReason != "" {
				assertRefused(t, err, tt.wantReason)
				if got != (Identity{}) {
					t.Errorf("identity = %+v alongside a refusal", got)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if want := tt.want(provider.Issuer()); got != want {
				t.Errorf("identity = %+v, want %+v", got, want)
			}
		})
	}
}

func TestSameEmailAtTwoConnectionsIsTwoIdentities(t *testing.T) {
	providerA, mockA := startMock(t, fixtures.MockOktaA)
	providerB, mockB := startMock(t, fixtures.MockOktaB)

	a, err := New(context.Background(), Config{
		ID: "customer-a-okta", Kind: KindOkta, Issuer: providerA.Issuer(), RedirectURL: callbackURL,
		ClientID: mockA.ClientID, ClientSecret: Secret(mockA.ClientSecret), Domains: []string{"customer-a.test"},
	})
	if err != nil {
		t.Fatal(err)
	}
	// A misconfigured connection that does allow customer A's domain.
	b, err := New(context.Background(), Config{
		ID: "customer-b-okta", Kind: KindOkta, Issuer: providerB.Issuer(), RedirectURL: callbackURL,
		ClientID: mockB.ClientID, ClientSecret: Secret(mockB.ClientSecret), Domains: []string{"customer-a.test"},
	})
	if err != nil {
		t.Fatal(err)
	}

	real, err := signIn(t, a, providerA, "okta-a-user")
	if err != nil {
		t.Fatal(err)
	}
	spoof, err := signIn(t, b, providerB, "okta-b-spoof")
	if err != nil {
		t.Fatal(err)
	}

	if real.Email != spoof.Email {
		t.Fatalf("emails differ: %q and %q", real.Email, spoof.Email)
	}
	if real.ConnectionID == spoof.ConnectionID || real.Subject == spoof.Subject {
		t.Errorf("same email resolved to the same identity: %+v and %+v", real, spoof)
	}
}

func TestStateFromAnotherSignInIsRefused(t *testing.T) {
	provider, mock := startMock(t, fixtures.MockOktaA)
	c, err := New(context.Background(), Config{
		ID: "customer-a-okta", Kind: KindOkta, Issuer: provider.Issuer(), RedirectURL: callbackURL,
		ClientID: mock.ClientID, ClientSecret: Secret(mock.ClientSecret), Domains: []string{"customer-a.test"},
	})
	if err != nil {
		t.Fatal(err)
	}

	authURL, _ := c.Begin()
	_, otherPending := c.Begin()
	callback := follow(t, provider, "okta-a-user", authURL)

	_, err = c.Complete(context.Background(), otherPending, callback)
	assertRefused(t, err, ReasonStateMismatch)
}

func TestCodeFromAnotherProviderIsRefused(t *testing.T) {
	providerA, mockA := startMock(t, fixtures.MockOktaA)
	providerB, mockB := startMock(t, fixtures.MockOktaB)

	a, err := New(context.Background(), Config{
		ID: "customer-a-okta", Kind: KindOkta, Issuer: providerA.Issuer(), RedirectURL: callbackURL,
		ClientID: mockA.ClientID, ClientSecret: Secret(mockA.ClientSecret), Domains: []string{"customer-a.test"},
	})
	if err != nil {
		t.Fatal(err)
	}
	b, err := New(context.Background(), Config{
		ID: "customer-b-okta", Kind: KindOkta, Issuer: providerB.Issuer(), RedirectURL: callbackURL,
		ClientID: mockB.ClientID, ClientSecret: Secret(mockB.ClientSecret), Domains: []string{"customer-b.test"},
	})
	if err != nil {
		t.Fatal(err)
	}

	authURL, pending := b.Begin()
	callback := follow(t, providerB, "okta-b-user", authURL)

	_, err = a.Complete(context.Background(), pending, callback)
	assertRefused(t, err, ReasonExchangeFailed)
}

func assertRefused(t *testing.T, err error, want Reason) {
	t.Helper()
	var refused *Refused
	if !errors.As(err, &refused) {
		t.Fatalf("err = %v, want a refusal for %s", err, want)
	}
	if refused.Reason != want {
		t.Fatalf("reason = %s (%s), want %s", refused.Reason, refused.Detail, want)
	}
}
