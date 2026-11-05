// Package fixtures holds the generic test accounts and mock providers. Every value is a test value.
// It's used only by the dev stack and tests, and must never be linked into the server: see
// TestServerDoesNotLinkTestCode.
package fixtures

import (
	"github.com/teal-mongoose/auth-mcp/internal/devenv"
	"github.com/teal-mongoose/auth-mcp/internal/mockidp"
)

// Account is a generic Firebase account in one project.
type Account struct {
	UID      string
	Email    string
	Name     string
	Disabled bool
	Claims   map[string]any
	// ProviderID and ProviderUID record an existing social sign-in, as a user who signed in before the
	// broker existed would have.
	ProviderID  string
	ProviderUID string
}

// Accounts lists the generic Firebase accounts for each project. user@customer-a.test is in both
// test apps under different uids, so a mix-up between projects shows up as the wrong uid.
func Accounts() map[string][]Account {
	return map[string][]Account{
		devenv.BrokerProject: {
			{
				UID: "seed-admin", Email: "admin@healthspaces.test", Name: "Generic Admin",
				Claims:     map[string]any{"admin": true},
				ProviderID: "google.com", ProviderUID: "google-admin",
			},
			{
				UID: "seed-staff", Email: "staff@healthspaces.test", Name: "Generic Staff",
				ProviderID: "google.com", ProviderUID: "google-staff",
			},
		},
		devenv.AppAProject: {
			{
				UID: "seed-staff", Email: "staff@healthspaces.test", Name: "Generic Staff",
				ProviderID: "google.com", ProviderUID: "google-staff",
			},
			{
				UID: "seed-customer-a", Email: "user@customer-a.test", Name: "Customer A User",
				Claims: map[string]any{"practice": "customer-a", "clinic": "main", "roles": []any{"provider"}, "admin": false},
			},
			{
				UID: "seed-customer-c", Email: "user@customer-c.test", Name: "Customer C User",
				ProviderID: "microsoft.com", ProviderUID: "oid-customer-c",
			},
			{UID: "seed-admin-claim", Email: "admin-claim@customer-a.test", Name: "Provider Sends Admin"},
			{UID: "seed-disabled", Email: "disabled@customer-a.test", Name: "Disabled User", Disabled: true},
			{
				// Tools must show this claim's name but not its value.
				UID: "seed-odd-claims", Email: "odd-claims@customer-a.test", Name: "Odd Claims User",
				Claims: map[string]any{"admin": false, "password": "generic-hidden-value"},
			},
		},
		devenv.AppBProject: {
			{UID: "seed-customer-b", Email: "user@customer-b.test", Name: "Customer B User"},
			{UID: "seed-customer-a-in-b", Email: "user@customer-a.test", Name: "Customer A User"},
		},
	}
}

// Mock provider names.
const (
	MockGoogle         = "google"
	MockOktaA          = "okta-customer-a"
	MockOktaB          = "okta-customer-b"
	MockMicrosoftC     = "microsoft-customer-c"
	MockMicrosoftOther = "microsoft-other-tenant"
)

// MockProviders lists the mock providers and who can sign in at each, including the people the
// broker must turn away.
func MockProviders() []mockidp.Config {
	return []mockidp.Config{
		{
			Name: MockGoogle, Addr: "127.0.0.1:9401", ClientID: "mock-google-client", ClientSecret: "mock-google-secret",
			Identities: []mockidp.Identity{
				{Subject: "google-admin", Email: "admin@healthspaces.test", Name: "Generic Admin", EmailVerified: true, Extra: map[string]any{"hd": "healthspaces.test"}},
				{Subject: "google-staff", Email: "staff@healthspaces.test", Name: "Generic Staff", EmailVerified: true, Extra: map[string]any{"hd": "healthspaces.test"}},
				{Subject: "google-other", Email: "staff@other.test", Name: "Wrong Domain", EmailVerified: true, Extra: map[string]any{"hd": "other.test"}},
			},
		},
		{
			Name: MockOktaA, Addr: "127.0.0.1:9402", ClientID: "mock-okta-a-client", ClientSecret: "mock-okta-a-secret",
			Identities: []mockidp.Identity{
				{Subject: "okta-a-user", Email: "user@customer-a.test", Name: "Customer A User", EmailVerified: true},
				{Subject: "okta-a-new", Email: "new@customer-a.test", Name: "Not Linked", EmailVerified: true},
				{Subject: "okta-a-admin-claim", Email: "admin-claim@customer-a.test", Name: "Provider Sends Admin", EmailVerified: true, Extra: map[string]any{"admin": true, "roles": []any{"admin"}}},
				{Subject: "okta-a-disabled", Email: "disabled@customer-a.test", Name: "Disabled User", EmailVerified: true},
			},
		},
		{
			Name: MockOktaB, Addr: "127.0.0.1:9403", ClientID: "mock-okta-b-client", ClientSecret: "mock-okta-b-secret",
			Identities: []mockidp.Identity{
				{Subject: "okta-b-user", Email: "user@customer-b.test", Name: "Customer B User", EmailVerified: true},
				{Subject: "okta-b-spoof", Email: "user@customer-a.test", Name: "Claims To Be Customer A", EmailVerified: true},
			},
		},
		{
			Name: MockMicrosoftC, Addr: "127.0.0.1:9404", ClientID: "mock-microsoft-client", ClientSecret: "mock-microsoft-secret",
			Identities: []mockidp.Identity{
				{Subject: "ms-c-user", Email: "user@customer-c.test", Name: "Customer C User", EmailVerified: true, Extra: map[string]any{"tid": "tenant-customer-c", "oid": "oid-customer-c"}},
			},
		},
		{
			Name: MockMicrosoftOther, Addr: "127.0.0.1:9405", ClientID: "mock-microsoft-client", ClientSecret: "mock-microsoft-secret",
			Identities: []mockidp.Identity{
				{Subject: "ms-other-user", Email: "user@customer-c.test", Name: "Same Email, Other Tenant", EmailVerified: true, Extra: map[string]any{"tid": "tenant-other", "oid": "oid-other"}},
			},
		},
	}
}
