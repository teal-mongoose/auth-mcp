// Package fixtures holds the generic test accounts and broker data. Every value is a test value.
// It's used only by the dev stack and tests, and must never be linked into the server: see
// TestServerDoesNotLinkTestCode.
package fixtures

import (
	"os"

	"github.com/teal-mongoose/auth-mcp/internal/broker"
	"github.com/teal-mongoose/auth-mcp/internal/connector"
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
			{
				// The stale org must be replaced by the connection's when they sign in.
				UID: "seed-admin-claim", Email: "admin-claim@customer-a.test", Name: "Provider Sends Admin",
				Claims: map[string]any{"org": "stale-org"},
			},
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

// Org ids.
const (
	OrgHealthspaces = "healthspaces"
	OrgCustomerA    = "customer-a"
	OrgCustomerB    = "customer-b"
	OrgCustomerC    = "customer-c"
)

// Orgs lists the customers, and Healthspaces itself.
func Orgs() []broker.Org {
	return []broker.Org{
		{ID: OrgHealthspaces, Name: "Healthspaces", Domains: []string{"healthspaces.test"}},
		{ID: OrgCustomerA, Name: "Customer A", Domains: []string{"customer-a.test"}},
		{ID: OrgCustomerB, Name: "Customer B", Domains: []string{"customer-b.test"}},
		{ID: OrgCustomerC, Name: "Customer C", Domains: []string{"customer-c.test"}},
	}
}

// Test app ids.
const (
	AppA     = "test-app-a"
	AppB     = "test-app-b"
	AppAdmin = "test-admin"
)

// Apps lists the registered test apps. Test Admin signs in to the broker's own project, as the admin
// screen will.
func Apps() []broker.App {
	return []broker.App{
		{ID: AppA, Name: "Test App A", ProjectID: devenv.AppAProject, RedirectURIs: []string{"http://" + devenv.TestAppAAddr + "/"}},
		{ID: AppB, Name: "Test App B", ProjectID: devenv.AppBProject, RedirectURIs: []string{"http://" + devenv.TestAppBAddr + "/"}},
		{ID: AppAdmin, Name: "Test Admin", ProjectID: devenv.BrokerProject, RedirectURIs: []string{"http://" + devenv.TestAdminAddr + "/"}},
	}
}

// Connection ids.
const (
	ConnectionGoogle     = "staff-google"
	ConnectionOktaA      = "customer-a-okta"
	ConnectionOktaB      = "customer-b-okta"
	ConnectionMicrosoftC = "customer-c-microsoft"
)

// connectionMocks says which mock provider each connection uses.
var connectionMocks = map[string]string{
	ConnectionGoogle:     mockidp.Google,
	ConnectionOktaA:      mockidp.OktaA,
	ConnectionOktaB:      mockidp.OktaB,
	ConnectionMicrosoftC: mockidp.MicrosoftC,
}

// MockProvider returns the config of a mock provider.
func MockProvider(name string) mockidp.Config {
	for _, config := range mockidp.Providers() {
		if config.Name == name {
			return config
		}
	}
	panic("no mock provider " + name)
}

// MockIssuer returns the issuer of a mock provider at its usual address.
func MockIssuer(name string) string {
	return "http://" + MockProvider(name).Addr + "/oidc"
}

// Connections lists the connections to the mock providers. Only staff's is listed on the sign-in page.
func Connections() []broker.Connection {
	connection := func(id, orgID, name string, kind connector.Kind, tenantID string) broker.Connection {
		mock := MockProvider(connectionMocks[id])
		return broker.Connection{
			ID: id, OrgID: orgID, Name: name, Kind: kind, Issuer: MockIssuer(mock.Name), ClientID: mock.ClientID,
			TenantID: tenantID, Enabled: true,
		}
	}
	staff := connection(ConnectionGoogle, OrgHealthspaces, "Healthspaces staff (mock Google)", connector.KindGoogle, "")
	staff.ShowOnSignInPage = true
	return []broker.Connection{
		staff,
		connection(ConnectionOktaA, OrgCustomerA, "Customer A (mock Okta)", connector.KindOkta, ""),
		connection(ConnectionOktaB, OrgCustomerB, "Customer B (mock Okta)", connector.KindOkta, ""),
		connection(ConnectionMicrosoftC, OrgCustomerC, "Customer C (mock Microsoft)", connector.KindMicrosoft, "tenant-customer-c"),
	}
}

// SetConnectionSecrets puts the mock client secrets where the broker reads them.
func SetConnectionSecrets() error {
	for id, mock := range connectionMocks {
		if err := os.Setenv(broker.SecretEnvName(id), MockProvider(mock).ClientSecret); err != nil {
			return err
		}
	}
	return nil
}

// Links lists who the broker already knows. Google and Microsoft users aren't here, because they're
// found through their existing Firebase accounts. new@customer-a.test isn't here, so is refused.
func Links() []broker.Link {
	link := func(connectionID, subject, projectID, uid string) broker.Link {
		return broker.Link{ConnectionID: connectionID, Subject: connectionID + "|" + subject, ProjectID: projectID, UID: uid}
	}
	return []broker.Link{
		link(ConnectionOktaA, "okta-a-user", devenv.AppAProject, "seed-customer-a"),
		link(ConnectionOktaA, "okta-a-user", devenv.AppBProject, "seed-customer-a-in-b"),
		link(ConnectionOktaA, "okta-a-admin-claim", devenv.AppAProject, "seed-admin-claim"),
		link(ConnectionOktaA, "okta-a-disabled", devenv.AppAProject, "seed-disabled"),
		link(ConnectionOktaB, "okta-b-user", devenv.AppBProject, "seed-customer-b"),
	}
}
