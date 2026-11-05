package mockidp

// Names of the dev stack's mock providers.
const (
	Google         = "google"
	OktaA          = "okta-customer-a"
	OktaB          = "okta-customer-b"
	MicrosoftC     = "microsoft-customer-c"
	MicrosoftOther = "microsoft-other-tenant"
)

// Providers lists the mock providers and who can sign in at each, including the people the
// broker must turn away.
func Providers() []Config {
	return []Config{
		{
			Name: Google, Addr: "127.0.0.1:9401", ClientID: "mock-google-client", ClientSecret: "mock-google-secret",
			Identities: []Identity{
				{Subject: "google-admin", Email: "admin@healthspaces.test", Name: "Generic Admin", EmailVerified: true, Extra: map[string]any{"hd": "healthspaces.test"}},
				{Subject: "google-staff", Email: "staff@healthspaces.test", Name: "Generic Staff", EmailVerified: true, Extra: map[string]any{"hd": "healthspaces.test"}},
				{Subject: "google-other", Email: "staff@other.test", Name: "Wrong Domain", EmailVerified: true, Extra: map[string]any{"hd": "other.test"}},
			},
		},
		{
			Name: OktaA, Addr: "127.0.0.1:9402", ClientID: "mock-okta-a-client", ClientSecret: "mock-okta-a-secret",
			Identities: []Identity{
				{Subject: "okta-a-user", Email: "user@customer-a.test", Name: "Customer A User", EmailVerified: true},
				{Subject: "okta-a-new", Email: "new@customer-a.test", Name: "Not Linked", EmailVerified: true},
				{Subject: "okta-a-admin-claim", Email: "admin-claim@customer-a.test", Name: "Provider Sends Admin", EmailVerified: true, Extra: map[string]any{"admin": true, "roles": []any{"admin"}, "org": "customer-b"}},
				{Subject: "okta-a-disabled", Email: "disabled@customer-a.test", Name: "Disabled User", EmailVerified: true},
			},
		},
		{
			Name: OktaB, Addr: "127.0.0.1:9403", ClientID: "mock-okta-b-client", ClientSecret: "mock-okta-b-secret",
			Identities: []Identity{
				{Subject: "okta-b-user", Email: "user@customer-b.test", Name: "Customer B User", EmailVerified: true},
				{Subject: "okta-b-spoof", Email: "user@customer-a.test", Name: "Claims To Be Customer A", EmailVerified: true},
			},
		},
		{
			Name: MicrosoftC, Addr: "127.0.0.1:9404", ClientID: "mock-microsoft-client", ClientSecret: "mock-microsoft-secret",
			Identities: []Identity{
				{Subject: "ms-c-user", Email: "user@customer-c.test", Name: "Customer C User", EmailVerified: true, Extra: map[string]any{"tid": "tenant-customer-c", "oid": "oid-customer-c"}},
			},
		},
		{
			Name: MicrosoftOther, Addr: "127.0.0.1:9405", ClientID: "mock-microsoft-client", ClientSecret: "mock-microsoft-secret",
			Identities: []Identity{
				{Subject: "ms-other-user", Email: "user@customer-c.test", Name: "Same Email, Other Tenant", EmailVerified: true, Extra: map[string]any{"tid": "tenant-other", "oid": "oid-other"}},
			},
		},
	}
}
