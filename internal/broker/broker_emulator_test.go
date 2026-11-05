//go:build emulator

// These tests run a broker in-process against the dev stack's emulators and mock providers, so they
// need `go run ./cmd/dev` running.
package broker_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	gcpfirestore "cloud.google.com/go/firestore"
	"firebase.google.com/go/v4/auth"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"

	"github.com/teal-mongoose/auth-mcp/internal/broker"
	"github.com/teal-mongoose/auth-mcp/internal/connector"
	"github.com/teal-mongoose/auth-mcp/internal/devenv"
	"github.com/teal-mongoose/auth-mcp/internal/fixtures"
	"github.com/teal-mongoose/auth-mcp/internal/mockidp"
	"github.com/teal-mongoose/auth-mcp/internal/seed"
)

var (
	store     *broker.Store
	clients   map[string]*auth.Client
	firestore *gcpfirestore.Client
)

func TestMain(m *testing.M) {
	ctx := context.Background()
	if err := devenv.SetEmulatorEnv(); err != nil {
		fatal(err)
	}
	if err := fixtures.SetConnectionSecrets(); err != nil {
		fatal(err)
	}
	var err error
	clients, err = devenv.AuthClients(ctx)
	if err != nil {
		fatal(err)
	}
	firestore, err = devenv.FirestoreClient(ctx)
	if err != nil {
		fatal(err)
	}
	store = broker.NewStore(firestore)
	if err := seed.Run(ctx, devenv.SafetyConfig(), clients, store); err != nil {
		fatal(fmt.Errorf("seeding: %w; is `go run ./cmd/dev` running?", err))
	}
	if err := clearEvents(ctx); err != nil {
		fatal(err)
	}
	code := m.Run()
	_ = firestore.Close()
	os.Exit(code)
}

// clearEvents deletes every sign-in event. Tests that move the clock forward leave events dated in the
// future, which would otherwise stay the newest for later tests.
func clearEvents(ctx context.Context) error {
	docs, err := firestore.Collection("sign_in_events").Documents(ctx).GetAll()
	if err != nil {
		return err
	}
	for _, doc := range docs {
		if _, err := doc.Ref.Delete(ctx); err != nil {
			return err
		}
	}
	return nil
}

func clearEventsAfter(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		if err := clearEvents(context.Background()); err != nil {
			t.Error(err)
		}
	})
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

// testBroker is a broker with a clock tests can move forward.
type testBroker struct {
	url    string
	offset atomic.Int64
}

func newBroker(t *testing.T) *testBroker {
	t.Helper()
	tb := &testBroker{}
	var handler http.Handler
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler.ServeHTTP(w, r)
	}))
	t.Cleanup(server.Close)
	tb.url = server.URL
	handler = broker.New(broker.Config{
		BaseURL: server.URL,
		Store:   store,
		Auth:    clients,
		Now:     func() time.Time { return time.Now().Add(time.Duration(tb.offset.Load())) },

		AllowLocalProviders: true,
	}).Handler()
	return tb
}

func (tb *testBroker) advance(d time.Duration) { tb.offset.Add(int64(d)) }

// browser keeps cookies and stops at every redirect, so tests can look at each step.
type browser struct {
	client *http.Client
}

func newBrowser(t *testing.T) *browser {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &browser{client: &http.Client{
		Jar:           jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

func (b *browser) get(t *testing.T, target string) (*http.Response, string) {
	t.Helper()
	res, err := b.client.Get(target)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	return res, string(body)
}

// request is what an app sends to /authorize. An email goes through the sign-in page's form.
type request struct {
	appID       string
	redirectURI string
	state       string
	verifier    string
	connection  string
	email       string
}

func newRequest(appID, connection string) request {
	return request{
		appID:       appID,
		redirectURI: redirectFor(appID),
		state:       "app-state-" + oauth2.GenerateVerifier(),
		verifier:    oauth2.GenerateVerifier(),
		connection:  connection,
	}
}

func newRoutedRequest(appID, email string) request {
	r := newRequest(appID, "")
	r.email = email
	return r
}

func redirectFor(appID string) string {
	for _, app := range fixtures.Apps() {
		if app.ID == appID {
			return app.RedirectURIs[0]
		}
	}
	panic("no app " + appID)
}

func challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func (tb *testBroker) authorizeURL(r request) string {
	query := url.Values{
		"app_id":                {r.appID},
		"redirect_uri":          {r.redirectURI},
		"state":                 {r.state},
		"code_challenge":        {challenge(r.verifier)},
		"code_challenge_method": {"S256"},
	}
	if r.connection != "" {
		query.Set("connection", r.connection)
	}
	return tb.url + "/authorize?" + query.Encode()
}

// postEmail submits the sign-in page's form.
func (tb *testBroker) postEmail(t *testing.T, b *browser, r request) (*http.Response, string) {
	t.Helper()
	res, err := b.client.PostForm(tb.url+"/authorize", url.Values{
		"app_id":                {r.appID},
		"redirect_uri":          {r.redirectURI},
		"state":                 {r.state},
		"code_challenge":        {challenge(r.verifier)},
		"code_challenge_method": {"S256"},
		"email":                 {r.email},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	return res, string(body)
}

// toProvider starts a sign-in, and returns the provider URL the browser is sent to.
func (tb *testBroker) toProvider(t *testing.T, b *browser, r request) string {
	t.Helper()
	var (
		res  *http.Response
		body string
	)
	if r.email != "" {
		res, body = tb.postEmail(t, b, r)
	} else {
		res, body = b.get(t, tb.authorizeURL(r))
	}
	if res.StatusCode != http.StatusFound {
		t.Fatalf("authorize = %d: %s", res.StatusCode, body)
	}
	return res.Header.Get("Location")
}

// atProvider signs in at the provider as subject, and returns the broker callback URL.
func atProvider(t *testing.T, b *browser, providerURL, subject string) string {
	t.Helper()
	res, body := b.get(t, providerURL+"&mock_user="+url.QueryEscape(subject))
	if res.StatusCode != http.StatusFound {
		t.Fatalf("provider = %d: %s", res.StatusCode, body)
	}
	return res.Header.Get("Location")
}

// signIn runs a sign-in as far as the broker sending the browser back to the app.
func (tb *testBroker) signIn(t *testing.T, b *browser, r request, subject string) url.Values {
	t.Helper()
	callback := atProvider(t, b, tb.toProvider(t, b, r), subject)
	res, body := b.get(t, callback)
	if res.StatusCode != http.StatusFound {
		t.Fatalf("callback = %d: %s", res.StatusCode, body)
	}
	return backAtApp(t, res.Header.Get("Location"), r)
}

func backAtApp(t *testing.T, location string, r request) url.Values {
	t.Helper()
	if !strings.HasPrefix(location, r.redirectURI) {
		t.Fatalf("redirected to %q, want the app's %q", location, r.redirectURI)
	}
	u, err := url.Parse(location)
	if err != nil {
		t.Fatal(err)
	}
	if got := u.Query().Get("state"); got != r.state {
		t.Fatalf("state = %q, want %q", got, r.state)
	}
	return u.Query()
}

// exchange is what an app sends to /token.
type exchange struct {
	appID       string
	code        string
	verifier    string
	redirectURI string
	origin      string
}

func (tb *testBroker) exchange(t *testing.T, e exchange) (int, string, http.Header) {
	t.Helper()
	form := url.Values{"app_id": {e.appID}, "code": {e.code}, "code_verifier": {e.verifier}, "redirect_uri": {e.redirectURI}}
	req, err := http.NewRequest(http.MethodPost, tb.url+"/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if e.origin != "" {
		req.Header.Set("Origin", e.origin)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	return res.StatusCode, string(body), res.Header
}

func exchangeFor(r request, code string) exchange {
	return exchange{appID: r.appID, code: code, verifier: r.verifier, redirectURI: r.redirectURI}
}

func customTokenFrom(t *testing.T, status int, body string) string {
	t.Helper()
	if status != http.StatusOK {
		t.Fatalf("exchange = %d: %s", status, body)
	}
	var parsed struct {
		CustomToken string `json:"custom_token"`
	}
	if err := json.Unmarshal([]byte(body), &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.CustomToken == "" {
		t.Fatalf("no custom token in %s", body)
	}
	return parsed.CustomToken
}

func wantInvalidGrant(t *testing.T, status int, body string) {
	t.Helper()
	if status != http.StatusBadRequest || !strings.Contains(body, "invalid_grant") {
		t.Fatalf("exchange = %d %s, want invalid_grant", status, body)
	}
	if strings.Contains(body, "custom_token") {
		t.Fatalf("a refusal included a token: %s", body)
	}
}

func hostFor(projectID string) string {
	for _, project := range devenv.Projects() {
		if project.ID == projectID {
			return project.AuthEmulatorHost
		}
	}
	panic("no project " + projectID)
}

func postJSON(t *testing.T, target string, payload any, out any) {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	res, err := http.Post(target, "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusOK {
		t.Fatalf("POST %s = %d: %s", target, res.StatusCode, body)
	}
	if err := json.Unmarshal(body, out); err != nil {
		t.Fatal(err)
	}
}

// firebaseSession signs in with a custom token, as the web SDK does, and returns the session's tokens.
func firebaseSession(t *testing.T, projectID, customToken string) (idToken, refreshToken string) {
	t.Helper()
	var result struct {
		IDToken      string `json:"idToken"`
		RefreshToken string `json:"refreshToken"`
	}
	postJSON(t, "http://"+hostFor(projectID)+"/identitytoolkit.googleapis.com/v1/accounts:signInWithCustomToken?key=fake",
		map[string]any{"token": customToken, "returnSecureToken": true}, &result)
	return result.IDToken, result.RefreshToken
}

func refreshSession(t *testing.T, projectID, refreshToken string) string {
	t.Helper()
	var result struct {
		IDToken string `json:"id_token"`
	}
	postJSON(t, "http://"+hostFor(projectID)+"/securetoken.googleapis.com/v1/token?key=fake",
		map[string]any{"grant_type": "refresh_token", "refresh_token": refreshToken}, &result)
	return result.IDToken
}

func projectFor(appID string) string {
	for _, app := range fixtures.Apps() {
		if app.ID == appID {
			return app.ProjectID
		}
	}
	panic("no app " + appID)
}

func TestAccountTable(t *testing.T) {
	tb := newBroker(t)
	tests := []struct {
		name       string
		appID      string
		email      string // Routes by email if set.
		connection string // Otherwise, goes straight to this connection.
		subject    string
		wantUID    string
		wantOrg    string
		wantAdmin  bool
		wantReason string
		// reasonConnection is the connection the refusal should be recorded against.
		reasonConnection string
	}{
		{name: "admin, found by existing account", appID: fixtures.AppAdmin, email: "admin@healthspaces.test", subject: "google-admin", wantUID: "seed-admin", wantOrg: fixtures.OrgHealthspaces, wantAdmin: true},
		{name: "staff, found by existing account", appID: fixtures.AppA, email: "staff@healthspaces.test", subject: "google-staff", wantUID: "seed-staff", wantOrg: fixtures.OrgHealthspaces},
		{name: "staff in the broker project isn't an admin", appID: fixtures.AppAdmin, email: "staff@healthspaces.test", subject: "google-staff", wantUID: "seed-staff", wantOrg: fixtures.OrgHealthspaces},
		{name: "google account in another domain", appID: fixtures.AppA, connection: fixtures.ConnectionGoogle, subject: "google-other", wantReason: "wrong_domain", reasonConnection: fixtures.ConnectionGoogle},
		{name: "customer A", appID: fixtures.AppA, email: "user@customer-a.test", subject: "okta-a-user", wantUID: "seed-customer-a", wantOrg: fixtures.OrgCustomerA},
		{name: "customer A in another app has that project's uid", appID: fixtures.AppB, email: "user@customer-a.test", subject: "okta-a-user", wantUID: "seed-customer-a-in-b", wantOrg: fixtures.OrgCustomerA},
		{name: "customer B", appID: fixtures.AppB, email: "user@customer-b.test", subject: "okta-b-user", wantUID: "seed-customer-b", wantOrg: fixtures.OrgCustomerB},
		{name: "customer B's okta sending a customer A address", appID: fixtures.AppA, email: "user@customer-b.test", subject: "okta-b-spoof", wantReason: "wrong_domain", reasonConnection: fixtures.ConnectionOktaB},
		{name: "customer C, linked", appID: fixtures.AppA, email: "user@customer-c.test", subject: "ms-c-user", wantUID: "seed-customer-c", wantOrg: fixtures.OrgCustomerC},
		{name: "valid login, not linked", appID: fixtures.AppA, email: "new@customer-a.test", subject: "okta-a-new", wantReason: "not_linked", reasonConnection: fixtures.ConnectionOktaA},
		{name: "linked in one app, signing in to another", appID: fixtures.AppB, email: "admin-claim@customer-a.test", subject: "okta-a-admin-claim", wantReason: "not_linked", reasonConnection: fixtures.ConnectionOktaA},
		{name: "google staff with no account in this project", appID: fixtures.AppB, email: "staff@healthspaces.test", subject: "google-staff", wantReason: "not_linked", reasonConnection: fixtures.ConnectionGoogle},
		{name: "microsoft user with no account in this project", appID: fixtures.AppB, email: "user@customer-c.test", subject: "ms-c-user", wantReason: "not_linked", reasonConnection: fixtures.ConnectionMicrosoftC},
		{name: "microsoft user with an existing account but no link", appID: fixtures.AppA, email: "existing@customer-c.test", subject: "ms-c-existing", wantReason: "not_linked", reasonConnection: fixtures.ConnectionMicrosoftC},
		{name: "provider sends admin, roles and org", appID: fixtures.AppA, email: "admin-claim@customer-a.test", subject: "okta-a-admin-claim", wantUID: "seed-admin-claim", wantOrg: fixtures.OrgCustomerA},
		{name: "firebase account disabled", appID: fixtures.AppA, email: "disabled@customer-a.test", subject: "okta-a-disabled", wantReason: "account_disabled", reasonConnection: fixtures.ConnectionOktaA},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newRequest(tt.appID, tt.connection)
			r.email = tt.email
			result := tb.signIn(t, newBrowser(t), r, tt.subject)

			if tt.wantReason != "" {
				if result.Get("code") != "" {
					t.Fatalf("got a code: %v", result)
				}
				// Apps get a generic answer. The reason is only for admins.
				if result.Get("error") != "access_denied" {
					t.Errorf("error = %q, want access_denied", result.Get("error"))
				}
				lastEventIs(t, tt.reasonConnection, broker.OutcomeRefused, tt.wantReason)
				return
			}

			if result.Get("error") != "" {
				t.Fatalf("refused: %s", result.Get("error"))
			}
			status, body, headers := tb.exchange(t, exchangeFor(r, result.Get("code")))
			customToken := customTokenFrom(t, status, body)
			if got := headers.Get("Cache-Control"); got != "no-store" {
				t.Errorf("Cache-Control = %q on a token response", got)
			}

			project := projectFor(tt.appID)
			client := clients[project]
			idToken, refreshToken := firebaseSession(t, project, customToken)
			refreshed := refreshSession(t, project, refreshToken)
			for step, token := range map[string]string{"sign-in": idToken, "refresh": refreshed} {
				verified, err := client.VerifyIDTokenAndCheckRevoked(context.Background(), token)
				if err != nil {
					t.Fatalf("%s: %v", step, err)
				}
				if verified.UID != tt.wantUID {
					t.Errorf("%s: uid = %q, want %q", step, verified.UID, tt.wantUID)
				}
				if verified.Audience != project {
					t.Errorf("%s: audience = %q, want %q", step, verified.Audience, project)
				}
				if verified.Claims["org"] != tt.wantOrg {
					t.Errorf("%s: org = %v, want %q", step, verified.Claims["org"], tt.wantOrg)
				}
				if got := verified.Claims["admin"] == true; got != tt.wantAdmin {
					t.Errorf("%s: admin = %v, want %v", step, verified.Claims["admin"], tt.wantAdmin)
				}
			}
		})
	}
}

// TestEmailFromAnotherTenantIsRefused sends customer C's connection a token from another tenant, as
// someone with the same email address in another Microsoft tenant would produce. It uses its own
// connection, because a second one on customer C would change how customer C's email routes.
func TestEmailFromAnotherTenantIsRefused(t *testing.T) {
	tb := newBroker(t)
	ctx := context.Background()
	const id = "customer-c-other-tenant-token"
	mock := fixtures.MockProvider(mockidp.MicrosoftOther)
	t.Setenv(broker.SecretEnvName(id), mock.ClientSecret)

	err := store.PutConnection(ctx, broker.Connection{
		ID: id, OrgID: fixtures.OrgCustomerC, Name: "Other tenant", Kind: connector.KindMicrosoft,
		Issuer: fixtures.MockIssuer(mock.Name), ClientID: mock.ClientID, TenantID: "tenant-customer-c", Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := firestore.Collection("connections").Doc(id).Delete(ctx); err != nil {
			t.Error(err)
		}
	})

	r := newRequest(fixtures.AppA, id)
	result := tb.signIn(t, newBrowser(t), r, "ms-other-user")
	if result.Get("code") != "" || result.Get("error") != "access_denied" {
		t.Errorf("result = %v", result)
	}
	lastEventIs(t, id, broker.OutcomeRefused, "wrong_tenant")
}

func TestStoredClaimsSurviveSignInAndRefresh(t *testing.T) {
	tb := newBroker(t)
	r := newRequest(fixtures.AppA, fixtures.ConnectionOktaA)
	result := tb.signIn(t, newBrowser(t), r, "okta-a-user")
	status, body, _ := tb.exchange(t, exchangeFor(r, result.Get("code")))

	project := projectFor(fixtures.AppA)
	idToken, refreshToken := firebaseSession(t, project, customTokenFrom(t, status, body))
	for name, token := range map[string]string{"sign-in": idToken, "refresh": refreshSession(t, project, refreshToken)} {
		verified, err := clients[project].VerifyIDTokenAndCheckRevoked(context.Background(), token)
		if err != nil {
			t.Fatal(err)
		}
		if verified.Claims["practice"] != "customer-a" {
			t.Errorf("%s: practice claim = %v", name, verified.Claims["practice"])
		}
	}
}

func TestProviderClaimsDoNotReachTheSession(t *testing.T) {
	tb := newBroker(t)
	r := newRequest(fixtures.AppA, fixtures.ConnectionOktaA)
	// This provider sends admin: true, roles and org: customer-b.
	result := tb.signIn(t, newBrowser(t), r, "okta-a-admin-claim")
	status, body, _ := tb.exchange(t, exchangeFor(r, result.Get("code")))

	project := projectFor(fixtures.AppA)
	idToken, _ := firebaseSession(t, project, customTokenFrom(t, status, body))
	verified, err := clients[project].VerifyIDTokenAndCheckRevoked(context.Background(), idToken)
	if err != nil {
		t.Fatal(err)
	}
	if verified.UID != "seed-admin-claim" {
		t.Fatalf("uid = %q", verified.UID)
	}
	for _, claim := range []string{"admin", "roles"} {
		if value, present := verified.Claims[claim]; present {
			t.Errorf("provider's %s claim reached the session: %v", claim, value)
		}
	}
	// The connection's org beats both the provider's and the stale one stored on the account.
	if verified.Claims["org"] != fixtures.OrgCustomerA {
		t.Errorf("org = %v, want %q", verified.Claims["org"], fixtures.OrgCustomerA)
	}
}

func TestExistingUserIsLinkedOnce(t *testing.T) {
	tb := newBroker(t)
	ctx := context.Background()
	project := projectFor(fixtures.AppA)
	subject := fixtures.MockIssuer(mockidp.Google) + "|google-staff"

	if err := store.ClearLinks(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := seed.Run(ctx, devenv.SafetyConfig(), clients, store); err != nil {
			t.Error(err)
		}
	})

	if _, err := store.LinkedUID(ctx, fixtures.ConnectionGoogle, subject, project); err != broker.ErrNotFound {
		t.Fatalf("before sign-in: LinkedUID err = %v", err)
	}

	r := newRequest(fixtures.AppA, fixtures.ConnectionGoogle)
	result := tb.signIn(t, newBrowser(t), r, "google-staff")
	if result.Get("code") == "" {
		t.Fatalf("refused: %v", result)
	}

	uid, err := store.LinkedUID(ctx, fixtures.ConnectionGoogle, subject, project)
	if err != nil {
		t.Fatal(err)
	}
	if uid != "seed-staff" {
		t.Errorf("linked uid = %q, want seed-staff", uid)
	}
}

func TestRoutingByEmail(t *testing.T) {
	tb := newBroker(t)
	tests := []struct {
		name  string
		email string
		mock  string
	}{
		{"staff go to Google", "staff@healthspaces.test", mockidp.Google},
		{"customer A goes to its Okta", "anyone@customer-a.test", mockidp.OktaA},
		{"customer B goes to its Okta", "anyone@customer-b.test", mockidp.OktaB},
		{"customer C goes to its Microsoft", "anyone@customer-c.test", mockidp.MicrosoftC},
		{"case doesn't matter", "Anyone@CUSTOMER-A.test", mockidp.OktaA},
		{"spaces around it don't matter", "  anyone@customer-a.test ", mockidp.OktaA},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			providerURL := tb.toProvider(t, newBrowser(t), newRoutedRequest(fixtures.AppA, tt.email))
			if want := fixtures.MockIssuer(tt.mock) + "/"; !strings.HasPrefix(providerURL, want) {
				t.Errorf("sent to %q, want %q", providerURL, want)
			}
			if strings.Contains(strings.ToLower(providerURL), "anyone") {
				t.Errorf("the address is in the URL: %q", providerURL)
			}
		})
	}
}

func TestEmailsThatDoNotRoute(t *testing.T) {
	tb := newBroker(t)
	tests := []struct {
		name  string
		email string
		want  string
	}{
		{"unknown domain", "someone@unknown.test", "find a sign-in for that address"},
		{"subdomain of a customer", "someone@sub.customer-a.test", "find a sign-in for that address"},
		{"customer's domain as a prefix", "someone@customer-a.test.evil.test", "find a sign-in for that address"},
		{"two at signs", "someone@evil.test@customer-a.test", "find a sign-in for that address"},
		{"no domain", "someone", "Enter your full work email"},
		{"no local part", "@customer-a.test", "Enter your full work email"},
		{"empty", " ", "Enter your full work email"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newRoutedRequest(fixtures.AppA, tt.email)
			res, body := tb.postEmail(t, newBrowser(t), r)
			if res.StatusCode != http.StatusOK {
				t.Errorf("status = %d", res.StatusCode)
			}
			if location := res.Header.Get("Location"); location != "" {
				t.Errorf("redirected to %q", location)
			}
			if !strings.Contains(body, tt.want) {
				t.Errorf("page is missing %q: %s", tt.want, body)
			}
		})
	}
}

func TestTypedEmailIsNotRecorded(t *testing.T) {
	tb := newBroker(t)
	const email = "private-person@unknown.test"
	tb.postEmail(t, newBrowser(t), newRoutedRequest(fixtures.AppA, email))

	lastEventIs(t, "", broker.OutcomeRefused, "unknown_domain")
	events, err := store.RecentEvents(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if text := fmt.Sprintf("%+v", events[0]); strings.Contains(text, "private-person") || strings.Contains(text, "unknown.test") {
		t.Errorf("the event records what was typed: %s", text)
	}
}

func TestPostedRequestsAreCheckedLikeOthers(t *testing.T) {
	tb := newBroker(t)

	t.Run("unregistered return address never redirects", func(t *testing.T) {
		r := newRoutedRequest(fixtures.AppA, "user@customer-a.test")
		r.redirectURI = "https://evil.test/"
		res, _ := tb.postEmail(t, newBrowser(t), r)
		if res.StatusCode != http.StatusBadRequest || res.Header.Get("Location") != "" {
			t.Errorf("status = %d, Location = %q", res.StatusCode, res.Header.Get("Location"))
		}
	})

	t.Run("no state goes back to the app", func(t *testing.T) {
		r := newRoutedRequest(fixtures.AppA, "user@customer-a.test")
		r.state = ""
		res, _ := tb.postEmail(t, newBrowser(t), r)
		if !strings.Contains(res.Header.Get("Location"), "error=invalid_request") {
			t.Errorf("Location = %q", res.Header.Get("Location"))
		}
	})

	t.Run("huge form", func(t *testing.T) {
		r := newRoutedRequest(fixtures.AppA, strings.Repeat("a", 32<<10)+"@customer-a.test")
		res, _ := tb.postEmail(t, newBrowser(t), r)
		if res.StatusCode != http.StatusBadRequest {
			t.Errorf("status = %d", res.StatusCode)
		}
	})
}

func TestSignInPageHidesCustomers(t *testing.T) {
	tb := newBroker(t)
	res, body := newBrowser(t).get(t, tb.authorizeURL(newRequest(fixtures.AppA, "")))

	if !strings.Contains(body, "Healthspaces staff") {
		t.Errorf("staff's connection is missing: %s", body)
	}
	if !strings.Contains(body, `name="email"`) {
		t.Errorf("the email form is missing: %s", body)
	}
	for _, customer := range []string{"Customer A", "Customer B", "Customer C", "customer-a", "customer-b", "customer-c", "Okta", "Microsoft"} {
		if strings.Contains(body, customer) {
			t.Errorf("the page reveals %q", customer)
		}
	}
	// Browsers apply form-action to redirects, so it would stop the form reaching a provider.
	if strings.Contains(res.Header.Get("Content-Security-Policy"), "form-action") {
		t.Errorf("CSP = %q", res.Header.Get("Content-Security-Policy"))
	}
}

func TestDomainConfigurationProblems(t *testing.T) {
	tb := newBroker(t)
	ctx := context.Background()

	addOrg := func(t *testing.T, org broker.Org) {
		t.Helper()
		if err := store.PutOrg(ctx, org); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if _, err := firestore.Collection("orgs").Doc(org.ID).Delete(ctx); err != nil {
				t.Error(err)
			}
		})
	}
	addConnection := func(t *testing.T, connection broker.Connection) {
		t.Helper()
		if err := store.PutConnection(ctx, connection); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if _, err := firestore.Collection("connections").Doc(connection.ID).Delete(ctx); err != nil {
				t.Error(err)
			}
		})
	}

	t.Run("two orgs claiming a domain sends nobody anywhere", func(t *testing.T) {
		addOrg(t, broker.Org{ID: "impostor", Name: "Impostor", Domains: []string{"customer-a.test"}})
		res, body := tb.postEmail(t, newBrowser(t), newRoutedRequest(fixtures.AppA, "user@customer-a.test"))
		if location := res.Header.Get("Location"); location != "" {
			t.Errorf("redirected to %q", location)
		}
		if !strings.Contains(body, "find a sign-in for that address") {
			t.Errorf("page = %s", body)
		}
		lastEventIs(t, "", broker.OutcomeRefused, "ambiguous_domain")
	})

	t.Run("org with no enabled connection", func(t *testing.T) {
		addOrg(t, broker.Org{ID: "no-connections", Name: "No Connections", Domains: []string{"no-connections.test"}})
		addConnection(t, broker.Connection{ID: "off", OrgID: "no-connections", Name: "Off", Kind: connector.KindOkta, Issuer: fixtures.MockIssuer(mockidp.OktaA), ClientID: "x"})
		res, body := tb.postEmail(t, newBrowser(t), newRoutedRequest(fixtures.AppA, "user@no-connections.test"))
		if res.Header.Get("Location") != "" || !strings.Contains(body, "find a sign-in for that address") {
			t.Errorf("Location = %q, page = %s", res.Header.Get("Location"), body)
		}
		lastEventIs(t, "", broker.OutcomeRefused, "connection_unavailable")
	})

	t.Run("org with two connections offers only those", func(t *testing.T) {
		addOrg(t, broker.Org{ID: "two-connections", Name: "Two", Domains: []string{"two-connections.test"}})
		addConnection(t, broker.Connection{ID: "first", OrgID: "two-connections", Name: "First Way In", Kind: connector.KindOkta, Issuer: fixtures.MockIssuer(mockidp.OktaA), ClientID: "x", Enabled: true})
		addConnection(t, broker.Connection{ID: "second", OrgID: "two-connections", Name: "Second Way In", Kind: connector.KindOkta, Issuer: fixtures.MockIssuer(mockidp.OktaA), ClientID: "x", Enabled: true})
		addConnection(t, broker.Connection{ID: "third", OrgID: "two-connections", Name: "Disabled Way In", Kind: connector.KindOkta, Issuer: fixtures.MockIssuer(mockidp.OktaA), ClientID: "x"})

		res, body := tb.postEmail(t, newBrowser(t), newRoutedRequest(fixtures.AppA, "user@two-connections.test"))
		if res.StatusCode != http.StatusOK {
			t.Fatalf("status = %d", res.StatusCode)
		}
		for _, want := range []string{"First Way In", "Second Way In"} {
			if !strings.Contains(body, want) {
				t.Errorf("page is missing %q", want)
			}
		}
		for _, unwanted := range []string{"Disabled Way In", "Healthspaces staff", `name="email"`} {
			if strings.Contains(body, unwanted) {
				t.Errorf("page contains %q", unwanted)
			}
		}
	})

	t.Run("removing a domain takes effect at once", func(t *testing.T) {
		const id = "shrinking"
		mock := fixtures.MockProvider(mockidp.OktaA)
		t.Setenv(broker.SecretEnvName(id), mock.ClientSecret)
		addOrg(t, broker.Org{ID: id, Name: "Shrinking", Domains: []string{"customer-a.test", "shrinking.test"}})
		addConnection(t, broker.Connection{ID: id, OrgID: id, Name: "Shrinking", Kind: connector.KindOkta, Issuer: fixtures.MockIssuer(mock.Name), ClientID: mock.ClientID, Enabled: true})

		// Sign in once, so that a connector with the old domains is cached.
		first := tb.signIn(t, newBrowser(t), newRequest(fixtures.AppA, id), "okta-a-user")
		lastEventIs(t, id, broker.OutcomeRefused, "not_linked")
		if first.Get("error") != "access_denied" {
			t.Fatalf("result = %v", first)
		}

		if err := store.PutOrg(ctx, broker.Org{ID: id, Name: "Shrinking", Domains: []string{"shrinking.test"}}); err != nil {
			t.Fatal(err)
		}
		tb.signIn(t, newBrowser(t), newRequest(fixtures.AppA, id), "okta-a-user")
		lastEventIs(t, id, broker.OutcomeRefused, "wrong_domain")
	})

	t.Run("connection whose org is gone", func(t *testing.T) {
		addConnection(t, broker.Connection{ID: "orphan", OrgID: "no-such-org", Name: "Orphan", Kind: connector.KindOkta, Issuer: fixtures.MockIssuer(mockidp.OktaA), ClientID: "x", Enabled: true})
		r := newRequest(fixtures.AppA, "orphan")
		res, _ := newBrowser(t).get(t, tb.authorizeURL(r))
		if result := backAtApp(t, res.Header.Get("Location"), r); result.Get("error") != "access_denied" {
			t.Errorf("result = %v", result)
		}
	})
}

func lastEventIs(t *testing.T, connectionID, outcome, reason string) {
	t.Helper()
	events, err := store.RecentEvents(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatal("no events recorded")
	}
	event := events[0]
	if event.ConnectionID != connectionID || event.Outcome != outcome || event.Reason != reason {
		t.Errorf("last event = %+v, want %s %s %s", event, connectionID, outcome, reason)
	}
}

func TestUnregisteredReturnAddressesNeverRedirect(t *testing.T) {
	tb := newBroker(t)
	good := newRequest(fixtures.AppA, fixtures.ConnectionOktaA)
	tests := []struct {
		name   string
		change func(*request)
	}{
		{"another site", func(r *request) { r.redirectURI = "https://evil.test/" }},
		{"registered address as a prefix", func(r *request) { r.redirectURI = good.redirectURI + "evil" }},
		{"registered address as a subdomain trick", func(r *request) { r.redirectURI = "http://127.0.0.1:8711.evil.test/" }},
		{"another port", func(r *request) { r.redirectURI = "http://127.0.0.1:9999/" }},
		{"added query", func(r *request) { r.redirectURI = good.redirectURI + "?next=https://evil.test" }},
		{"no trailing slash", func(r *request) { r.redirectURI = strings.TrimSuffix(good.redirectURI, "/") }},
		{"another app's address", func(r *request) { r.redirectURI = redirectFor(fixtures.AppB) }},
		{"empty", func(r *request) { r.redirectURI = "" }},
		{"unknown app", func(r *request) { r.appID = "no-such-app" }},
		{"no app", func(r *request) { r.appID = "" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := good
			tt.change(&r)
			res, _ := newBrowser(t).get(t, tb.authorizeURL(r))
			if res.StatusCode != http.StatusBadRequest {
				t.Errorf("status = %d, want %d", res.StatusCode, http.StatusBadRequest)
			}
			if location := res.Header.Get("Location"); location != "" {
				t.Errorf("redirected to %q", location)
			}
		})
	}
}

func TestBadAuthorizeRequestsGoBackToTheApp(t *testing.T) {
	tb := newBroker(t)
	tests := []struct {
		name   string
		change func(url.Values)
	}{
		{"no state", func(q url.Values) { q.Del("state") }},
		{"huge state", func(q url.Values) { q.Set("state", strings.Repeat("a", 5000)) }},
		{"no challenge", func(q url.Values) { q.Del("code_challenge") }},
		{"short challenge", func(q url.Values) { q.Set("code_challenge", "short") }},
		{"plain PKCE", func(q url.Values) { q.Set("code_challenge_method", "plain") }},
		{"no PKCE method", func(q url.Values) { q.Del("code_challenge_method") }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newRequest(fixtures.AppA, fixtures.ConnectionOktaA)
			u, err := url.Parse(tb.authorizeURL(r))
			if err != nil {
				t.Fatal(err)
			}
			query := u.Query()
			tt.change(query)
			u.RawQuery = query.Encode()

			res, _ := newBrowser(t).get(t, u.String())
			if res.StatusCode != http.StatusFound {
				t.Fatalf("status = %d, want a redirect", res.StatusCode)
			}
			location := res.Header.Get("Location")
			if !strings.HasPrefix(location, r.redirectURI) || !strings.Contains(location, "error=invalid_request") {
				t.Errorf("redirected to %q, want the app with invalid_request", location)
			}
		})
	}
}

func TestCodeProblems(t *testing.T) {
	tb := newBroker(t)

	getCode := func(t *testing.T) (request, string) {
		t.Helper()
		r := newRequest(fixtures.AppA, fixtures.ConnectionOktaA)
		code := tb.signIn(t, newBrowser(t), r, "okta-a-user").Get("code")
		if code == "" {
			t.Fatal("no code")
		}
		return r, code
	}

	t.Run("reused", func(t *testing.T) {
		r, code := getCode(t)
		status, body, _ := tb.exchange(t, exchangeFor(r, code))
		customTokenFrom(t, status, body)
		status, body, _ = tb.exchange(t, exchangeFor(r, code))
		wantInvalidGrant(t, status, body)
	})

	t.Run("wrong verifier, which also uses it up", func(t *testing.T) {
		r, code := getCode(t)
		bad := exchangeFor(r, code)
		bad.verifier = oauth2.GenerateVerifier()
		status, body, _ := tb.exchange(t, bad)
		wantInvalidGrant(t, status, body)
		lastEventIs(t, "", broker.OutcomeRefused, "wrong_pkce_verifier")

		status, body, _ = tb.exchange(t, exchangeFor(r, code))
		wantInvalidGrant(t, status, body)
	})

	t.Run("another app's code", func(t *testing.T) {
		r, code := getCode(t)
		bad := exchangeFor(r, code)
		bad.appID = fixtures.AppB
		bad.redirectURI = redirectFor(fixtures.AppB)
		status, body, _ := tb.exchange(t, bad)
		wantInvalidGrant(t, status, body)
		lastEventIs(t, "", broker.OutcomeRefused, "code_for_another_app")
	})

	t.Run("wrong return address", func(t *testing.T) {
		r, code := getCode(t)
		bad := exchangeFor(r, code)
		bad.redirectURI = "http://127.0.0.1:8711/other"
		status, body, _ := tb.exchange(t, bad)
		wantInvalidGrant(t, status, body)
		lastEventIs(t, "", broker.OutcomeRefused, "code_for_another_redirect")
	})

	t.Run("made up", func(t *testing.T) {
		r, _ := getCode(t)
		status, body, _ := tb.exchange(t, exchangeFor(r, "MADEUPCODE"))
		wantInvalidGrant(t, status, body)
	})

	t.Run("expired", func(t *testing.T) {
		r, code := getCode(t)
		local := newBroker(t)
		local.advance(2 * time.Minute)
		clearEventsAfter(t)
		status, body, _ := local.exchange(t, exchangeFor(r, code))
		wantInvalidGrant(t, status, body)
		lastEventIs(t, "", broker.OutcomeRefused, "code_expired")
	})

	t.Run("not yet expired", func(t *testing.T) {
		r, code := getCode(t)
		local := newBroker(t)
		local.advance(30 * time.Second)
		clearEventsAfter(t)
		status, body, _ := local.exchange(t, exchangeFor(r, code))
		customTokenFrom(t, status, body)
	})

	t.Run("malformed verifier doesn't use it up", func(t *testing.T) {
		r, code := getCode(t)
		bad := exchangeFor(r, code)
		bad.verifier = "short"
		status, _, _ := tb.exchange(t, bad)
		if status != http.StatusBadRequest {
			t.Fatalf("status = %d", status)
		}
		status, body, _ := tb.exchange(t, exchangeFor(r, code))
		customTokenFrom(t, status, body)
	})

	t.Run("account disabled after signing in", func(t *testing.T) {
		r, code := getCode(t)
		ctx := context.Background()
		client := clients[projectFor(fixtures.AppA)]
		if _, err := client.UpdateUser(ctx, "seed-customer-a", (&auth.UserToUpdate{}).Disabled(true)); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if _, err := client.UpdateUser(ctx, "seed-customer-a", (&auth.UserToUpdate{}).Disabled(false)); err != nil {
				t.Error(err)
			}
		})
		status, body, _ := tb.exchange(t, exchangeFor(r, code))
		wantInvalidGrant(t, status, body)
		lastEventIs(t, "", broker.OutcomeRefused, "account_disabled")
	})
}

func TestConcurrentExchangesGetOneToken(t *testing.T) {
	tb := newBroker(t)
	r := newRequest(fixtures.AppA, fixtures.ConnectionOktaA)
	code := tb.signIn(t, newBrowser(t), r, "okta-a-user").Get("code")

	var wins atomic.Int32
	var wg sync.WaitGroup
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			status, _, _ := tb.exchange(t, exchangeFor(r, code))
			if status == http.StatusOK {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()

	if got := wins.Load(); got != 1 {
		t.Errorf("%d exchanges succeeded, want exactly 1", got)
	}
}

func TestCallbackProblems(t *testing.T) {
	tb := newBroker(t)
	r := newRequest(fixtures.AppA, fixtures.ConnectionOktaA)

	t.Run("works once", func(t *testing.T) {
		b := newBrowser(t)
		callback := atProvider(t, b, tb.toProvider(t, b, newRequestLike(r)), "okta-a-user")
		first, _ := b.get(t, callback)
		if first.StatusCode != http.StatusFound {
			t.Fatalf("first = %d", first.StatusCode)
		}
		second, _ := b.get(t, callback)
		if second.StatusCode != http.StatusBadRequest {
			t.Errorf("second = %d, want %d", second.StatusCode, http.StatusBadRequest)
		}
		lastEventIs(t, "", broker.OutcomeRefused, "unknown_or_used_state")
	})

	t.Run("in a different browser", func(t *testing.T) {
		attacker := newBrowser(t)
		callback := atProvider(t, attacker, tb.toProvider(t, attacker, newRequestLike(r)), "okta-a-user")

		res, _ := newBrowser(t).get(t, callback) // The victim opens the attacker's link.
		if res.StatusCode != http.StatusBadRequest {
			t.Errorf("status = %d, want %d", res.StatusCode, http.StatusBadRequest)
		}
		if location := res.Header.Get("Location"); strings.Contains(location, "code=") {
			t.Errorf("got a code: %q", location)
		}
		lastEventIs(t, fixtures.ConnectionOktaA, broker.OutcomeRefused, "different_browser")
	})

	t.Run("made-up state", func(t *testing.T) {
		res, _ := newBrowser(t).get(t, tb.url+"/callback/"+fixtures.ConnectionOktaA+"?state=made-up&code=whatever")
		if res.StatusCode != http.StatusBadRequest {
			t.Errorf("status = %d", res.StatusCode)
		}
	})

	t.Run("no state", func(t *testing.T) {
		res, _ := newBrowser(t).get(t, tb.url+"/callback/"+fixtures.ConnectionOktaA+"?code=whatever")
		if res.StatusCode != http.StatusBadRequest {
			t.Errorf("status = %d", res.StatusCode)
		}
	})

	t.Run("expired", func(t *testing.T) {
		b := newBrowser(t)
		request := newRequestLike(r)
		callback := atProvider(t, b, tb.toProvider(t, b, request), "okta-a-user")
		tb.advance(11 * time.Minute)
		t.Cleanup(func() { tb.advance(-11 * time.Minute) })
		clearEventsAfter(t)

		res, _ := b.get(t, callback)
		result := backAtApp(t, res.Header.Get("Location"), request)
		if result.Get("error") != "access_denied" || result.Get("code") != "" {
			t.Errorf("result = %v", result)
		}
		lastEventIs(t, fixtures.ConnectionOktaA, broker.OutcomeRefused, "signin_expired")
	})

	t.Run("provider reports an error", func(t *testing.T) {
		b := newBrowser(t)
		request := newRequestLike(r)
		providerURL := tb.toProvider(t, b, request)
		parsed, err := url.Parse(providerURL)
		if err != nil {
			t.Fatal(err)
		}
		res, _ := b.get(t, tb.url+"/callback/"+fixtures.ConnectionOktaA+"?error=access_denied&state="+url.QueryEscape(parsed.Query().Get("state")))
		result := backAtApp(t, res.Header.Get("Location"), request)
		if result.Get("error") != "access_denied" {
			t.Errorf("result = %v", result)
		}
		lastEventIs(t, fixtures.ConnectionOktaA, broker.OutcomeRefused, "provider_error")
	})
}

func newRequestLike(r request) request { return newRequest(r.appID, r.connection) }

func TestTwoTabsCanSignInAtOnce(t *testing.T) {
	tb := newBroker(t)
	b := newBrowser(t)

	first := newRequest(fixtures.AppA, fixtures.ConnectionOktaA)
	second := newRequest(fixtures.AppA, fixtures.ConnectionOktaA)
	firstCallback := atProvider(t, b, tb.toProvider(t, b, first), "okta-a-user")
	secondCallback := atProvider(t, b, tb.toProvider(t, b, second), "okta-a-user")

	for _, step := range []struct {
		callback string
		r        request
	}{{firstCallback, first}, {secondCallback, second}} {
		res, _ := b.get(t, step.callback)
		if code := backAtApp(t, res.Header.Get("Location"), step.r).Get("code"); code == "" {
			t.Error("a tab was refused")
		}
	}
}

func TestDisabledConnections(t *testing.T) {
	tb := newBroker(t)
	ctx := context.Background()
	const id = "temporary-okta"

	var okta broker.Connection
	for _, connection := range fixtures.Connections() {
		if connection.ID == fixtures.ConnectionOktaA {
			okta = connection
		}
	}
	okta.ID = id
	okta.Name = "Temporary Okta"
	okta.ShowOnSignInPage = true
	t.Setenv(broker.SecretEnvName(id), "mock-okta-a-secret")
	if err := store.PutConnection(ctx, okta); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := firestore.Collection("connections").Doc(id).Delete(ctx); err != nil {
			t.Error(err)
		}
	})

	setEnabled := func(t *testing.T, enabled bool) {
		t.Helper()
		okta.Enabled = enabled
		if err := store.PutConnection(ctx, okta); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("refused before leaving for the provider", func(t *testing.T) {
		setEnabled(t, false)
		r := newRequest(fixtures.AppA, id)
		res, _ := newBrowser(t).get(t, tb.authorizeURL(r))
		result := backAtApp(t, res.Header.Get("Location"), r)
		if result.Get("error") != "access_denied" {
			t.Errorf("result = %v", result)
		}
		lastEventIs(t, id, broker.OutcomeRefused, "connection_unavailable")
	})

	t.Run("hidden from the chooser", func(t *testing.T) {
		setEnabled(t, false)
		r := newRequest(fixtures.AppA, "")
		_, body := newBrowser(t).get(t, tb.authorizeURL(r))
		if strings.Contains(body, "Temporary Okta") {
			t.Error("a disabled connection is listed")
		}
		if !strings.Contains(body, "Healthspaces staff") {
			t.Errorf("an enabled connection is missing: %s", body)
		}
	})

	t.Run("refused if disabled during sign-in", func(t *testing.T) {
		setEnabled(t, true)
		b := newBrowser(t)
		r := newRequest(fixtures.AppA, id)
		callback := atProvider(t, b, tb.toProvider(t, b, r), "okta-a-user")
		setEnabled(t, false)

		res, _ := b.get(t, callback)
		result := backAtApp(t, res.Header.Get("Location"), r)
		if result.Get("code") != "" || result.Get("error") != "access_denied" {
			t.Errorf("result = %v", result)
		}
	})

	t.Run("unknown connection", func(t *testing.T) {
		r := newRequest(fixtures.AppA, "no-such-connection")
		res, _ := newBrowser(t).get(t, tb.authorizeURL(r))
		result := backAtApp(t, res.Header.Get("Location"), r)
		if result.Get("error") != "access_denied" {
			t.Errorf("result = %v", result)
		}
	})
}

func TestBrowsersOnlyGetTokensOnRegisteredOrigins(t *testing.T) {
	tb := newBroker(t)
	r := newRequest(fixtures.AppA, fixtures.ConnectionOktaA)
	code := tb.signIn(t, newBrowser(t), r, "okta-a-user").Get("code")

	bad := exchangeFor(r, code)
	bad.origin = "https://evil.test"
	status, body, headers := tb.exchange(t, bad)
	if status != http.StatusForbidden || strings.Contains(body, "custom_token") {
		t.Fatalf("from another origin = %d %s", status, body)
	}
	if got := headers.Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("allowed origin %q", got)
	}

	good := exchangeFor(r, code)
	good.origin = "http://" + devenv.TestAppAAddr
	status, body, headers = tb.exchange(t, good)
	customTokenFrom(t, status, body)
	if got := headers.Get("Access-Control-Allow-Origin"); got != good.origin {
		t.Errorf("Access-Control-Allow-Origin = %q, want %q", got, good.origin)
	}
}

func TestLinksAreSeparatePerConnectionAndProject(t *testing.T) {
	ctx := context.Background()
	t.Cleanup(func() {
		if err := seed.Run(ctx, devenv.SafetyConfig(), clients, store); err != nil {
			t.Error(err)
		}
	})

	const subject = "the-same-subject"
	links := []broker.Link{
		{ConnectionID: "connection-1", Subject: subject, ProjectID: devenv.AppAProject, UID: "uid-1"},
		{ConnectionID: "connection-2", Subject: subject, ProjectID: devenv.AppAProject, UID: "uid-2"},
		{ConnectionID: "connection-1", Subject: subject, ProjectID: devenv.AppBProject, UID: "uid-3"},
	}
	for _, link := range links {
		if err := store.PutLink(ctx, link); err != nil {
			t.Fatal(err)
		}
	}
	for _, link := range links {
		got, err := store.LinkedUID(ctx, link.ConnectionID, link.Subject, link.ProjectID)
		if err != nil {
			t.Fatal(err)
		}
		if got != link.UID {
			t.Errorf("%s in %s = %q, want %q", link.ConnectionID, link.ProjectID, got, link.UID)
		}
	}
}

func TestHugeTokenRequestIsRejected(t *testing.T) {
	tb := newBroker(t)
	// Valid but for its size: without the limit, this would be an unknown code, so invalid_grant.
	form := url.Values{
		"app_id":        {fixtures.AppA},
		"code":          {strings.Repeat("a", 32<<10)},
		"code_verifier": {oauth2.GenerateVerifier()},
		"redirect_uri":  {redirectFor(fixtures.AppA)},
	}
	res, err := http.Post(tb.url+"/token", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusBadRequest || !strings.Contains(string(body), "invalid_request") {
		t.Errorf("status = %d, body = %s", res.StatusCode, body)
	}
}

func TestSecretsStayOutOfPagesAndData(t *testing.T) {
	tb := newBroker(t)
	secrets := []string{}
	for _, mock := range mockidp.Providers() {
		secrets = append(secrets, mock.ClientSecret)
	}

	_, chooser := newBrowser(t).get(t, tb.authorizeURL(newRequest(fixtures.AppA, "")))
	b := newBrowser(t)
	providerURL := tb.toProvider(t, b, newRequest(fixtures.AppA, fixtures.ConnectionOktaA))

	connections, err := store.Connections(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	stored, err := json.Marshal(connections)
	if err != nil {
		t.Fatal(err)
	}

	for _, secret := range secrets {
		for name, text := range map[string]string{"chooser": chooser, "provider URL": providerURL, "stored connections": string(stored)} {
			if strings.Contains(text, secret) {
				t.Errorf("%s contains a client secret", name)
			}
		}
	}
}

func TestPagesSetSecurityHeaders(t *testing.T) {
	tb := newBroker(t)
	res, _ := newBrowser(t).get(t, tb.authorizeURL(newRequest(fixtures.AppA, "")))
	for name, want := range map[string]string{
		"Referrer-Policy": "no-referrer",
		"Cache-Control":   "no-store",
		"X-Frame-Options": "DENY",
	} {
		if got := res.Header.Get(name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
}

func TestBindingCookieIsLockedDown(t *testing.T) {
	tb := newBroker(t)
	b := newBrowser(t)
	res, _ := b.get(t, tb.authorizeURL(newRequest(fixtures.AppA, fixtures.ConnectionOktaA)))

	cookies := res.Cookies()
	if len(cookies) != 1 {
		t.Fatalf("%d cookies, want 1", len(cookies))
	}
	cookie := cookies[0]
	if !cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode || cookie.Path != "/callback" {
		t.Errorf("cookie = %+v", cookie)
	}
}

func TestSignedInEventRecordsWhoButNoSecrets(t *testing.T) {
	tb := newBroker(t)
	r := newRequest(fixtures.AppA, fixtures.ConnectionOktaA)
	code := tb.signIn(t, newBrowser(t), r, "okta-a-user").Get("code")

	events, err := store.RecentEvents(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}
	event := events[0]
	if event.Outcome != broker.OutcomeSignedIn || event.UID != "seed-customer-a" || event.AppID != fixtures.AppA {
		t.Errorf("event = %+v", event)
	}
	if strings.Contains(fmt.Sprintf("%+v", event), code) {
		t.Error("the event contains the code")
	}
}

// attackProvider is a provider that signs in whoever asks, and hands back whatever token a test builds,
// so that bad tokens can be tried against the whole broker. The connector package tests these in more
// depth. This checks that they stop the sign-in.
type attackProvider struct {
	server *httptest.Server
	key    *rsa.PrivateKey
	// token builds the token for the sign-in with this nonce.
	token atomic.Value
}

func newAttackProvider(t *testing.T) *attackProvider {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := &attackProvider{key: key}
	var nonce atomic.Value

	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                p.server.URL,
			"authorization_endpoint":                p.server.URL + "/authorize",
			"token_endpoint":                        p.server.URL + "/token",
			"jwks_uri":                              p.server.URL + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("GET /jwks", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "alg": "RS256", "use": "sig", "kid": "attack-key",
			"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		}}})
	})
	mux.HandleFunc("GET /authorize", func(w http.ResponseWriter, r *http.Request) {
		nonce.Store(r.URL.Query().Get("nonce"))
		target, err := url.Parse(r.URL.Query().Get("redirect_uri"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		target.RawQuery = url.Values{"code": {"provider-code"}, "state": {r.URL.Query().Get("state")}}.Encode()
		http.Redirect(w, r, target.String(), http.StatusFound)
	})
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, _ *http.Request) {
		build := p.token.Load().(func(nonce string) string)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "access", "token_type": "Bearer", "id_token": build(nonce.Load().(string)),
		})
	})
	p.server = httptest.NewServer(mux)
	t.Cleanup(p.server.Close)
	return p
}

func (p *attackProvider) sign(t *testing.T, key *rsa.PrivateKey, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "attack-key"
	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func TestBadTokensStopTheSignIn(t *testing.T) {
	tb := newBroker(t)
	ctx := context.Background()
	provider := newAttackProvider(t)
	forgeryKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	const id = "attack-okta"
	t.Setenv(broker.SecretEnvName(id), "attack-secret")
	err = store.PutConnection(ctx, broker.Connection{
		ID: id, OrgID: fixtures.OrgCustomerA, Name: "Attack", Kind: connector.KindOkta,
		Issuer: provider.server.URL, ClientID: "attack-client", Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	subject := id + "|attacker"
	err = store.PutLink(ctx, broker.Link{ConnectionID: id, Subject: subject, ProjectID: devenv.AppAProject, UID: "seed-customer-a"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := firestore.Collection("connections").Doc(id).Delete(ctx); err != nil {
			t.Error(err)
		}
		if err := seed.Run(ctx, devenv.SafetyConfig(), clients, store); err != nil {
			t.Error(err)
		}
	})

	good := func(nonce string) jwt.MapClaims {
		now := time.Now()
		return jwt.MapClaims{
			"iss": provider.server.URL, "aud": "attack-client", "sub": "attacker",
			"iat": now.Unix(), "exp": now.Add(10 * time.Minute).Unix(), "nonce": nonce,
			"email": "user@customer-a.test", "email_verified": true,
		}
	}

	tests := []struct {
		name   string
		change func(jwt.MapClaims)
		key    *rsa.PrivateKey
		want   string
	}{
		{name: "forged signature", key: forgeryKey, want: "invalid_id_token"},
		{name: "wrong issuer", change: func(c jwt.MapClaims) { c["iss"] = "https://evil.test" }, want: "invalid_id_token"},
		{name: "wrong audience", change: func(c jwt.MapClaims) { c["aud"] = "another-client" }, want: "invalid_id_token"},
		{name: "expired", change: func(c jwt.MapClaims) { c["exp"] = time.Now().Add(-time.Hour).Unix() }, want: "invalid_id_token"},
		{name: "wrong nonce", change: func(c jwt.MapClaims) { c["nonce"] = "replayed" }, want: "nonce_mismatch"},
		{name: "another customer's domain", change: func(c jwt.MapClaims) { c["email"] = "user@customer-b.test" }, want: "wrong_domain"},
	}

	signInWith := func(t *testing.T, build func(nonce string) string) (request, url.Values) {
		t.Helper()
		provider.token.Store(build)
		b := newBrowser(t)
		r := newRequest(fixtures.AppA, id)
		providerRes, _ := b.get(t, tb.toProvider(t, b, r))
		res, body := b.get(t, providerRes.Header.Get("Location"))
		if res.StatusCode != http.StatusFound {
			t.Fatalf("callback = %d: %s", res.StatusCode, body)
		}
		return r, backAtApp(t, res.Header.Get("Location"), r)
	}

	// If this fails, the attacks below would be passing for the wrong reason.
	t.Run("the same token, unchanged, is accepted", func(t *testing.T) {
		_, result := signInWith(t, func(nonce string) string { return provider.sign(t, provider.key, good(nonce)) })
		if result.Get("code") == "" {
			t.Fatalf("refused: %v", result)
		}
		lastEventIs(t, id, broker.OutcomeSignedIn, "")
	})

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, result := signInWith(t, func(nonce string) string {
				claims := good(nonce)
				if tt.change != nil {
					tt.change(claims)
				}
				key := provider.key
				if tt.key != nil {
					key = tt.key
				}
				return provider.sign(t, key, claims)
			})
			if result.Get("code") != "" || result.Get("error") != "access_denied" {
				t.Errorf("result = %v", result)
			}
			lastEventIs(t, id, broker.OutcomeRefused, tt.want)
		})
	}
}

// TestIdentityProviderMixUp plays out the classic attack on a broker with several providers. A
// malicious connection sends its victim on to an honest provider, hoping that the code comes back and
// gets posted to the malicious connection's token endpoint. The attacker could then redeem it in their
// own sign-in, and become the victim.
func TestIdentityProviderMixUp(t *testing.T) {
	tb := newBroker(t)
	ctx := context.Background()

	var stolen atomic.Value
	stolen.Store("")
	var mallory *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 mallory.URL,
			"authorization_endpoint": mallory.URL + "/authorize",
			"token_endpoint":         mallory.URL + "/token",
			"jwks_uri":               mallory.URL + "/jwks",
		})
	})
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err == nil {
			stolen.Store(r.PostForm.Get("code"))
		}
		http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
	})
	mallory = httptest.NewServer(mux)
	defer mallory.Close()

	const id = "mallory-okta"
	t.Setenv(broker.SecretEnvName(id), "mallory-secret")
	err := store.PutConnection(ctx, broker.Connection{
		ID: id, OrgID: fixtures.OrgCustomerB, Name: "Mallory", Kind: connector.KindOkta,
		Issuer: mallory.URL, ClientID: "mallory-client", Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := firestore.Collection("connections").Doc(id).Delete(ctx); err != nil {
			t.Error(err)
		}
	})

	// The attacker starts a sign-in at the honest provider, and stops before going there.
	attacker := newBrowser(t)
	attackerRequest := newRequest(fixtures.AppA, fixtures.ConnectionOktaA)
	attackerProviderURL, err := url.Parse(tb.toProvider(t, attacker, attackerRequest))
	if err != nil {
		t.Fatal(err)
	}
	attackerState := attackerProviderURL.Query().Get("state")

	// The victim clicks a link to the malicious connection.
	victim := newBrowser(t)
	victimProviderURL, err := url.Parse(tb.toProvider(t, victim, newRequest(fixtures.AppA, id)))
	if err != nil {
		t.Fatal(err)
	}

	// Mallory sends the victim to the honest provider, using the attacker's parameters and the
	// victim's state. The victim signs in there, as themselves.
	forged := *attackerProviderURL
	query := forged.Query()
	query.Set("state", victimProviderURL.Query().Get("state"))
	forged.RawQuery = query.Encode()
	callback := atProvider(t, victim, forged.String(), "okta-a-user")

	res, _ := victim.get(t, callback)
	if strings.Contains(res.Header.Get("Location"), "code=") {
		t.Errorf("the victim got a code from the mixed-up flow: %q", res.Header.Get("Location"))
	}

	code, _ := stolen.Load().(string)
	if code == "" {
		if res.StatusCode != http.StatusBadRequest {
			t.Errorf("mixed-up callback = %d, want %d", res.StatusCode, http.StatusBadRequest)
		}
		lastEventIs(t, id, broker.OutcomeRefused, "callback_for_another_connection")
		return
	}
	t.Errorf("the honest provider's code reached the malicious connection's token endpoint")

	// Mallory hands the code to the attacker, who redeems it in their own sign-in.
	attackerCallback, err := url.Parse(callback)
	if err != nil {
		t.Fatal(err)
	}
	attackerCallback.RawQuery = url.Values{"state": {attackerState}, "code": {code}}.Encode()
	res, body := attacker.get(t, attackerCallback.String())
	if res.StatusCode != http.StatusFound {
		t.Fatalf("attacker's callback = %d: %s", res.StatusCode, body)
	}
	result := backAtApp(t, res.Header.Get("Location"), attackerRequest)
	if result.Get("code") == "" {
		t.Fatalf("attacker was refused: %v", result)
	}
	status, tokenBody, _ := tb.exchange(t, exchangeFor(attackerRequest, result.Get("code")))
	idToken, _ := firebaseSession(t, projectFor(fixtures.AppA), customTokenFrom(t, status, tokenBody))
	verified, err := clients[projectFor(fixtures.AppA)].VerifyIDTokenAndCheckRevoked(ctx, idToken)
	if err != nil {
		t.Fatal(err)
	}
	t.Errorf("ACCOUNT TAKEOVER: the attacker now has a session as %q", verified.UID)
}

func TestBadIDsGoNoFurther(t *testing.T) {
	tb := newBroker(t)
	for _, id := range []string{"a/b", "a/b/c", "..", "CAPITALS", "under_score", strings.Repeat("a", 65), "a b"} {
		t.Run(id[:min(len(id), 10)], func(t *testing.T) {
			r := newRequest(fixtures.AppA, id)
			res, _ := newBrowser(t).get(t, tb.authorizeURL(r))
			result := backAtApp(t, res.Header.Get("Location"), r)
			if result.Get("error") != "access_denied" {
				t.Errorf("result = %v", result)
			}
			// Not recorded as it was sent.
			lastEventIs(t, "", broker.OutcomeRefused, "connection_unavailable")
		})
	}

	// An even number of parts would be a collection's path, which Firestore can't read as a document.
	for _, id := range []string{"a/b", "a/b/c"} {
		t.Run("as an app id: "+id, func(t *testing.T) {
			r := newRequest(fixtures.AppA, fixtures.ConnectionOktaA)
			r.appID = id
			res, _ := newBrowser(t).get(t, tb.authorizeURL(r))
			if res.StatusCode != http.StatusBadRequest || res.Header.Get("Location") != "" {
				t.Errorf("status = %d, Location = %q", res.StatusCode, res.Header.Get("Location"))
			}
		})
	}

	t.Run("old shared callback is gone", func(t *testing.T) {
		res, _ := newBrowser(t).get(t, tb.url+"/callback?state=x&code=y")
		if res.StatusCode != http.StatusNotFound {
			t.Errorf("status = %d", res.StatusCode)
		}
	})
}

func TestProviderIsToldTheConnectionsOwnCallback(t *testing.T) {
	tb := newBroker(t)
	providerURL, err := url.Parse(tb.toProvider(t, newBrowser(t), newRequest(fixtures.AppA, fixtures.ConnectionOktaA)))
	if err != nil {
		t.Fatal(err)
	}
	want := tb.url + "/callback/" + fixtures.ConnectionOktaA
	if got := providerURL.Query().Get("redirect_uri"); got != want {
		t.Errorf("redirect_uri = %q, want %q", got, want)
	}
}

func TestIssuerParameterFromAnotherProviderIsRefused(t *testing.T) {
	tb := newBroker(t)
	b := newBrowser(t)
	r := newRequest(fixtures.AppA, fixtures.ConnectionOktaA)
	callback := atProvider(t, b, tb.toProvider(t, b, r), "okta-a-user")

	res, _ := b.get(t, callback+"&iss="+url.QueryEscape("https://evil.test"))
	result := backAtApp(t, res.Header.Get("Location"), r)
	if result.Get("code") != "" {
		t.Errorf("got a code: %v", result)
	}
	lastEventIs(t, fixtures.ConnectionOktaA, broker.OutcomeRefused, "issuer_mismatch")
}

func TestRemovingAReturnAddressStopsSignInsInProgress(t *testing.T) {
	tb := newBroker(t)
	ctx := context.Background()
	const id = "shrinking-app"
	original := broker.App{ID: id, Name: "Shrinking", ProjectID: devenv.AppAProject, RedirectURIs: []string{"http://127.0.0.1:1/"}}
	if err := store.PutApp(ctx, original); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := firestore.Collection("apps").Doc(id).Delete(ctx); err != nil {
			t.Error(err)
		}
	})
	removed := original
	removed.RedirectURIs = []string{"http://127.0.0.1:2/"}

	start := func() request {
		return request{appID: id, redirectURI: "http://127.0.0.1:1/", state: "state", verifier: oauth2.GenerateVerifier(), connection: fixtures.ConnectionOktaA}
	}

	t.Run("at the callback", func(t *testing.T) {
		if err := store.PutApp(ctx, original); err != nil {
			t.Fatal(err)
		}
		b := newBrowser(t)
		callback := atProvider(t, b, tb.toProvider(t, b, start()), "okta-a-user")
		if err := store.PutApp(ctx, removed); err != nil {
			t.Fatal(err)
		}
		res, _ := b.get(t, callback)
		if res.StatusCode != http.StatusBadRequest || res.Header.Get("Location") != "" {
			t.Errorf("status = %d, Location = %q", res.StatusCode, res.Header.Get("Location"))
		}
		lastEventIs(t, fixtures.ConnectionOktaA, broker.OutcomeRefused, "redirect_no_longer_registered")
	})

	t.Run("at the exchange", func(t *testing.T) {
		if err := store.PutApp(ctx, original); err != nil {
			t.Fatal(err)
		}
		r := start()
		b := newBrowser(t)
		callback := atProvider(t, b, tb.toProvider(t, b, r), "okta-a-user")
		res, _ := b.get(t, callback)
		code := backAtApp(t, res.Header.Get("Location"), r).Get("code")
		if code == "" {
			t.Fatalf("no code: %q", res.Header.Get("Location"))
		}
		if err := store.PutApp(ctx, removed); err != nil {
			t.Fatal(err)
		}
		status, body, _ := tb.exchange(t, exchangeFor(r, code))
		wantInvalidGrant(t, status, body)
		lastEventIs(t, "", broker.OutcomeRefused, "redirect_no_longer_registered")
	})
}

func TestExchangeIsRecorded(t *testing.T) {
	tb := newBroker(t)
	r := newRequest(fixtures.AppA, fixtures.ConnectionOktaA)
	code := tb.signIn(t, newBrowser(t), r, "okta-a-user").Get("code")
	lastEventIs(t, fixtures.ConnectionOktaA, broker.OutcomeSignedIn, "")

	status, body, _ := tb.exchange(t, exchangeFor(r, code))
	customTokenFrom(t, status, body)
	events, err := store.RecentEvents(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}
	event := events[0]
	if event.Outcome != broker.OutcomeTokenIssued || event.UID != "seed-customer-a" || event.OrgID != fixtures.OrgCustomerA {
		t.Errorf("event = %+v", event)
	}
}

func TestDomainsAreStoredInLowercase(t *testing.T) {
	tb := newBroker(t)
	ctx := context.Background()
	if err := store.PutOrg(ctx, broker.Org{ID: "impostor", Name: "Impostor", Domains: []string{" CUSTOMER-A.test "}}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := firestore.Collection("orgs").Doc("impostor").Delete(ctx); err != nil {
			t.Error(err)
		}
	})
	res, _ := tb.postEmail(t, newBrowser(t), newRoutedRequest(fixtures.AppA, "user@customer-a.test"))
	if location := res.Header.Get("Location"); location != "" {
		t.Errorf("routed despite another org claiming the domain in capitals: %q", location)
	}
	lastEventIs(t, "", broker.OutcomeRefused, "ambiguous_domain")
}
