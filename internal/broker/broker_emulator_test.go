//go:build emulator

// These tests run a broker in-process against the dev stack's emulators and mock providers, so they
// need `go run ./cmd/dev` running.
package broker_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
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
	"golang.org/x/oauth2"

	"github.com/teal-mongoose/auth-mcp/internal/broker"
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

// request is what an app sends to /authorize.
type request struct {
	appID       string
	redirectURI string
	state       string
	verifier    string
	connection  string
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

// toProvider starts a sign-in, and returns the provider URL the browser is sent to.
func (tb *testBroker) toProvider(t *testing.T, b *browser, r request) string {
	t.Helper()
	res, body := b.get(t, tb.authorizeURL(r))
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

func TestSignInThroughEveryProvider(t *testing.T) {
	tb := newBroker(t)
	tests := []struct {
		name       string
		appID      string
		connection string
		subject    string
		wantUID    string
	}{
		{"google staff, found by existing account", fixtures.AppA, fixtures.ConnectionGoogle, "google-staff", "seed-staff"},
		{"okta customer A, linked", fixtures.AppA, fixtures.ConnectionOktaA, "okta-a-user", "seed-customer-a"},
		{"okta customer B, linked", fixtures.AppB, fixtures.ConnectionOktaB, "okta-b-user", "seed-customer-b"},
		{"microsoft customer C, found by existing account", fixtures.AppA, fixtures.ConnectionMicrosoftC, "ms-c-user", "seed-customer-c"},
		{"same person in another app has that project's uid", fixtures.AppB, fixtures.ConnectionOktaA, "okta-a-user", "seed-customer-a-in-b"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newRequest(tt.appID, tt.connection)
			result := tb.signIn(t, newBrowser(t), r, tt.subject)
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
			verified, err := client.VerifyIDTokenAndCheckRevoked(context.Background(), idToken)
			if err != nil {
				t.Fatal(err)
			}
			if verified.UID != tt.wantUID {
				t.Errorf("uid = %q, want %q", verified.UID, tt.wantUID)
			}
			if verified.Audience != project {
				t.Errorf("audience = %q, want %q", verified.Audience, project)
			}

			refreshed, err := client.VerifyIDTokenAndCheckRevoked(context.Background(), refreshSession(t, project, refreshToken))
			if err != nil {
				t.Fatalf("after refresh: %v", err)
			}
			if refreshed.UID != tt.wantUID {
				t.Errorf("uid after refresh = %q, want %q", refreshed.UID, tt.wantUID)
			}
		})
	}
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
	result := tb.signIn(t, newBrowser(t), r, "okta-a-admin-claim") // This provider sends admin: true.
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

func TestPeopleTheBrokerMustRefuse(t *testing.T) {
	tb := newBroker(t)
	tests := []struct {
		name       string
		appID      string
		connection string
		subject    string
		wantReason string
	}{
		{"valid login, not linked", fixtures.AppA, fixtures.ConnectionOktaA, "okta-a-new", "not_linked"},
		{"linked in one app, signing in to another", fixtures.AppB, fixtures.ConnectionOktaA, "okta-a-admin-claim", "not_linked"},
		{"firebase account disabled", fixtures.AppA, fixtures.ConnectionOktaA, "okta-a-disabled", "account_disabled"},
		{"google account in another domain", fixtures.AppA, fixtures.ConnectionGoogle, "google-other", "wrong_domain"},
		{"customer B's okta claiming a customer A address", fixtures.AppA, fixtures.ConnectionOktaB, "okta-b-spoof", "wrong_domain"},
		{"same email from another microsoft tenant", fixtures.AppA, fixtures.ConnectionMicrosoftOther, "ms-other-user", "not_linked"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newRequest(tt.appID, tt.connection)
			result := tb.signIn(t, newBrowser(t), r, tt.subject)

			if result.Get("code") != "" {
				t.Fatalf("got a code: %v", result)
			}
			// Apps get a generic answer. The reason is only for admins.
			if result.Get("error") != "access_denied" {
				t.Errorf("error = %q, want access_denied", result.Get("error"))
			}
			lastEventIs(t, tt.connection, broker.OutcomeRefused, tt.wantReason)
		})
	}
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
		res, _ := newBrowser(t).get(t, tb.url+"/callback?state=made-up&code=whatever")
		if res.StatusCode != http.StatusBadRequest {
			t.Errorf("status = %d", res.StatusCode)
		}
	})

	t.Run("no state", func(t *testing.T) {
		res, _ := newBrowser(t).get(t, tb.url+"/callback?code=whatever")
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
		res, _ := b.get(t, tb.url+"/callback?error=access_denied&state="+url.QueryEscape(parsed.Query().Get("state")))
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
		if !strings.Contains(body, "Customer A") {
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
