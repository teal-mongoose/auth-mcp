//go:build live

// These tests check what the emulators can't prove, against a real throwaway Firebase project: real token
// signing and verification, how real sessions treat claims, revocation, and real Firestore. Google isn't
// involved. They use temporary accounts, which they delete, and a mock provider. They run only with:
//
//	go test -tags=live -count=1 ./internal/live/
package live_test

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
	"log/slog"
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

	"cloud.google.com/go/firestore"
	"firebase.google.com/go/v4/auth"
	"github.com/golang-jwt/jwt/v5"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"golang.org/x/oauth2"

	"github.com/teal-mongoose/auth-mcp/internal/admin"
	"github.com/teal-mongoose/auth-mcp/internal/broker"
	"github.com/teal-mongoose/auth-mcp/internal/connector"
	"github.com/teal-mongoose/auth-mcp/internal/live"
	"github.com/teal-mongoose/auth-mcp/internal/mockidp"
)

var (
	cfg        live.Config
	authClient *auth.Client
	fs         *firestore.Client
	store      *broker.Store
	apiKey     string
)

func TestMain(m *testing.M) {
	envFile := os.Getenv("AUTH_MCP_ENV_FILE")
	if envFile == "" {
		envFile = "../../.env.live"
	}
	if err := live.LoadEnvFile(envFile); err != nil {
		fatal(err)
	}
	cfg = live.FromEnv()
	apiKey = os.Getenv("AUTH_MCP_FIREBASE_API_KEY")
	if apiKey == "" {
		fatal(fmt.Errorf("AUTH_MCP_FIREBASE_API_KEY must be set"))
	}
	var closeClients func()
	var err error
	authClient, fs, closeClients, err = live.Clients(context.Background(), cfg)
	if err != nil {
		fatal(err)
	}
	store = broker.NewStore(fs)
	code := m.Run()
	closeClients()
	os.Exit(code)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

func randomID(prefix string) string {
	return prefix + "-" + strings.ToLower(strings.ReplaceAll(rand.Text()[:12], "_", ""))
}

// tempUser creates an account that's deleted when the test ends.
func tempUser(t *testing.T, claims map[string]any) string {
	t.Helper()
	ctx := context.Background()
	uid := randomID("realcheck")
	if _, err := authClient.CreateUser(ctx, (&auth.UserToCreate{}).UID(uid).Email(uid+"@realcheck.example").DisplayName("Real Check")); err != nil {
		t.Fatalf("creating a temporary account: %v", err)
	}
	t.Cleanup(func() {
		if err := authClient.DeleteUser(context.Background(), uid); err != nil {
			t.Errorf("deleting %s: %v", uid, err)
		}
	})
	if claims != nil {
		if err := authClient.SetCustomUserClaims(ctx, uid, claims); err != nil {
			t.Fatal(err)
		}
	}
	return uid
}

func postJSON(t *testing.T, target string, payload map[string]any) (int, map[string]any) {
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
	out := map[string]any{}
	_ = json.Unmarshal(body, &out)
	return res.StatusCode, out
}

// exchangeCustomToken signs in the way a browser does, against the real service.
func exchangeCustomToken(t *testing.T, customToken string) (status int, idToken, refreshToken string) {
	t.Helper()
	status, out := postJSON(t, "https://identitytoolkit.googleapis.com/v1/accounts:signInWithCustomToken?key="+apiKey,
		map[string]any{"token": customToken, "returnSecureToken": true})
	idToken, _ = out["idToken"].(string)
	refreshToken, _ = out["refreshToken"].(string)
	return status, idToken, refreshToken
}

func signIn(t *testing.T, uid string, claims map[string]any) (idToken, refreshToken string) {
	t.Helper()
	customToken, err := authClient.CustomTokenWithClaims(context.Background(), uid, claims)
	if err != nil {
		t.Fatalf("signing a custom token: %v", err)
	}
	status, idToken, refreshToken := exchangeCustomToken(t, customToken)
	if idToken == "" {
		t.Fatalf("real sign-in with a custom token = %d", status)
	}
	return idToken, refreshToken
}

func refresh(t *testing.T, refreshToken string) string {
	t.Helper()
	status, out := postJSON(t, "https://securetoken.googleapis.com/v1/token?key="+apiKey,
		map[string]any{"grant_type": "refresh_token", "refresh_token": refreshToken})
	idToken, _ := out["id_token"].(string)
	if idToken == "" {
		t.Fatalf("real token refresh = %d", status)
	}
	return idToken
}

func TestRealTokensAreSignedAndVerified(t *testing.T) {
	ctx := context.Background()
	uid := tempUser(t, nil)

	customToken, err := authClient.CustomToken(ctx, uid)
	if err != nil {
		t.Fatalf("signing without a key file: %v", err)
	}
	header, err := base64.RawURLEncoding.DecodeString(strings.Split(customToken, ".")[0])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(header), "RS256") {
		t.Errorf("custom token header = %s, want a real signature", header)
	}

	status, idToken, _ := exchangeCustomToken(t, customToken)
	if idToken == "" {
		t.Fatalf("sign-in = %d", status)
	}
	verified, err := authClient.VerifyIDTokenAndCheckRevoked(ctx, idToken)
	if err != nil {
		t.Fatal(err)
	}
	if verified.UID != uid || verified.Audience != cfg.ProjectID || verified.Firebase.SignInProvider != "custom" {
		t.Errorf("verified = %+v", verified)
	}
}

func TestRealFirebaseRefusesATamperedCustomToken(t *testing.T) {
	uid := tempUser(t, nil)
	customToken, err := authClient.CustomToken(context.Background(), uid)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(customToken, ".")
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	claims["claims"] = map[string]any{"admin": true}
	changed, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	parts[1] = base64.RawURLEncoding.EncodeToString(changed)

	if status, idToken, _ := exchangeCustomToken(t, strings.Join(parts, ".")); idToken != "" {
		t.Errorf("real Firebase accepted a tampered custom token, status %d", status)
	}
}

func TestForgedIDTokensAreRefused(t *testing.T) {
	ctx := context.Background()
	uid := tempUser(t, map[string]any{"admin": true})
	now := time.Now()
	claims := jwt.MapClaims{
		"iss": "https://securetoken.google.com/" + cfg.ProjectID, "aud": cfg.ProjectID, "sub": uid, "user_id": uid,
		"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(), "auth_time": now.Unix(),
		"admin": true, "org": live.OrgStaff,
		"firebase": map[string]any{"sign_in_provider": "custom", "identities": map[string]any{}},
	}

	unsigned, err := jwt.NewWithClaims(jwt.SigningMethodNone, claims).SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatal(err)
	}
	// This is what the emulator accepts. Real verification must not.
	if _, err := authClient.VerifyIDToken(ctx, unsigned); err == nil {
		t.Error("accepted an unsigned token: the client is in emulator mode")
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	selfSigned := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	selfSigned.Header["kid"] = "forged"
	signed, err := selfSigned.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authClient.VerifyIDToken(ctx, signed); err == nil {
		t.Error("accepted a token signed with another key")
	}
}

func TestClaimsOnRealSessions(t *testing.T) {
	ctx := context.Background()
	uid := tempUser(t, map[string]any{"org": "stale-org", "practice": "stored-practice"})
	idToken, refreshToken := signIn(t, uid, map[string]any{"org": "connection-org"})

	for step, token := range map[string]string{"sign-in": idToken, "refresh": refresh(t, refreshToken)} {
		verified, err := authClient.VerifyIDTokenAndCheckRevoked(ctx, token)
		if err != nil {
			t.Fatalf("%s: %v", step, err)
		}
		if verified.Claims["org"] != "connection-org" {
			t.Errorf("%s: org = %v: the connection's must replace a stored one, and last through a refresh", step, verified.Claims["org"])
		}
		if verified.Claims["practice"] != "stored-practice" {
			t.Errorf("%s: practice = %v: stored claims must carry over", step, verified.Claims["practice"])
		}
	}
}

func TestExistingGoogleAccountIsFoundByItsIdentity(t *testing.T) {
	ctx := context.Background()
	uid := randomID("realcheck")
	sub := randomID("google-sub")
	result, err := authClient.ImportUsers(ctx, []*auth.UserToImport{(&auth.UserToImport{}).UID(uid).Email(uid + "@realcheck.example").
		ProviderData([]*auth.UserProvider{{ProviderID: "google.com", UID: sub, Email: uid + "@realcheck.example"}})})
	if err != nil {
		t.Fatal(err)
	}
	if result.FailureCount != 0 {
		t.Fatalf("import: %+v", result.Errors)
	}
	t.Cleanup(func() {
		if err := authClient.DeleteUser(context.Background(), uid); err != nil {
			t.Error(err)
		}
	})

	found, err := authClient.GetUsers(ctx, []auth.UserIdentifier{auth.ProviderIdentifier{ProviderID: "google.com", ProviderUID: sub}})
	if err != nil {
		t.Fatal(err)
	}
	if len(found.Users) != 1 || found.Users[0].UID != uid {
		t.Errorf("found %d users", len(found.Users))
	}
}

func adminServer(t *testing.T) string {
	t.Helper()
	handler := admin.New(admin.Config{
		Store:        store,
		Auth:         map[string]*auth.Client{cfg.ProjectID: authClient},
		AdminProject: cfg.ProjectID,
		AdminOrg:     live.OrgStaff,
		Logger:       slog.New(slog.DiscardHandler),
	}).Handler()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return server.URL
}

func adminStatus(t *testing.T, target, token string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, target, strings.NewReader(
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"realcheck","version":"1"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Authorization", "Bearer "+token)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	return res.StatusCode
}

func TestAdminAccessOnRealFirebase(t *testing.T) {
	ctx := context.Background()
	target := adminServer(t)
	org := map[string]any{"org": live.OrgStaff}

	t.Run("admin allowed, staff refused", func(t *testing.T) {
		adminToken, _ := signIn(t, tempUser(t, map[string]any{"admin": true}), org)
		if got := adminStatus(t, target, adminToken); got != http.StatusOK {
			t.Errorf("admin = %d", got)
		}
		staffToken, _ := signIn(t, tempUser(t, nil), org)
		if got := adminStatus(t, target, staffToken); got != http.StatusForbidden {
			t.Errorf("staff = %d", got)
		}
	})

	t.Run("revoking locks an admin out, because the server checks", func(t *testing.T) {
		uid := tempUser(t, map[string]any{"admin": true})
		token, _ := signIn(t, uid, org)
		if got := adminStatus(t, target, token); got != http.StatusOK {
			t.Fatalf("before revoking = %d", got)
		}
		time.Sleep(1100 * time.Millisecond) // Revocation works to the second.
		if err := authClient.RevokeRefreshTokens(ctx, uid); err != nil {
			t.Fatal(err)
		}
		// Without asking, the token still verifies. The emulator couldn't show this difference.
		if _, err := authClient.VerifyIDToken(ctx, token); err != nil {
			t.Errorf("VerifyIDToken should still accept a revoked token: %v", err)
		}
		if _, err := authClient.VerifyIDTokenAndCheckRevoked(ctx, token); !auth.IsIDTokenRevoked(err) {
			t.Errorf("VerifyIDTokenAndCheckRevoked = %v, want revoked", err)
		}
		if got := adminStatus(t, target, token); got != http.StatusUnauthorized {
			t.Errorf("after revoking = %d", got)
		}
	})

	t.Run("disabling locks an admin out", func(t *testing.T) {
		uid := tempUser(t, map[string]any{"admin": true})
		token, _ := signIn(t, uid, org)
		if _, err := authClient.UpdateUser(ctx, uid, (&auth.UserToUpdate{}).Disabled(true)); err != nil {
			t.Fatal(err)
		}
		if got := adminStatus(t, target, token); got != http.StatusUnauthorized {
			t.Errorf("after disabling = %d", got)
		}
	})

	t.Run("removing the claim applies at once", func(t *testing.T) {
		uid := tempUser(t, map[string]any{"admin": true})
		token, _ := signIn(t, uid, org)
		if err := authClient.SetCustomUserClaims(ctx, uid, nil); err != nil {
			t.Fatal(err)
		}
		if got := adminStatus(t, target, token); got != http.StatusForbidden {
			t.Errorf("after removing = %d", got)
		}
	})
}

type bearer struct{ token string }

func (b bearer) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.Header.Set("Authorization", "Bearer "+b.token)
	return http.DefaultTransport.RoundTrip(req)
}

func TestToolsOnRealFirebaseAndFirestore(t *testing.T) {
	ctx := context.Background()
	if err := store.PutApp(ctx, broker.App{ID: "realcheck-app", Name: "Real Check", ProjectID: cfg.ProjectID, RedirectURIs: []string{"http://127.0.0.1:1/"}}); err != nil {
		t.Fatalf("writing to real Firestore: %v", err)
	}
	t.Cleanup(func() {
		if _, err := fs.Collection("apps").Doc("realcheck-app").Delete(context.Background()); err != nil {
			t.Error(err)
		}
	})

	token, _ := signIn(t, tempUser(t, map[string]any{"admin": true}), map[string]any{"org": live.OrgStaff})
	transport := &mcp.StreamableClientTransport{
		Endpoint:   adminServer(t),
		HTTPClient: &http.Client{Transport: bearer{token: token}},
	}
	session, err := mcp.NewClient(&mcp.Implementation{Name: "realcheck", Version: "1"}, nil).Connect(ctx, transport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = session.Close() }()

	call := func(t *testing.T, tool string, args map[string]any) (bool, string) {
		t.Helper()
		result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: tool, Arguments: args})
		if err != nil {
			t.Fatalf("%s: %v", tool, err)
		}
		raw, err := json.Marshal(result)
		if err != nil {
			t.Fatal(err)
		}
		return result.IsError, string(raw)
	}

	// Each of these runs its query on real Firestore, which can demand indexes that the emulator doesn't.
	for tool, args := range map[string]map[string]any{
		"list_apps":           nil,
		"list_orgs":           nil,
		"list_connections":    nil,
		"list_sign_in_events": {"limit": 5},
		"list_users":          {"app_id": "realcheck-app", "limit": 2},
		"get_user_links":      {"app_id": "realcheck-app", "uid": "nobody"},
	} {
		t.Run(tool, func(t *testing.T) {
			if isError, raw := call(t, tool, args); isError {
				t.Errorf("failed: %s", raw)
			}
		})
	}

	t.Run("a bad page token gets a clear refusal", func(t *testing.T) {
		isError, raw := call(t, "list_users", map[string]any{"app_id": "realcheck-app", "page_token": "not-a-real-token"})
		if !isError || !strings.Contains(raw, "page_token") {
			t.Errorf("isError = %v: %s", isError, raw)
		}
	})
}

func challengeFor(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// TestSignInFlowOnRealFirebaseAndFirestore runs the whole broker on real services. Only the provider is a
// mock, because a real one needs a person.
func TestSignInFlowOnRealFirebaseAndFirestore(t *testing.T) {
	ctx := context.Background()
	domain := randomID("realcheck") + ".example"
	orgID, connectionID, appID := randomID("realcheck-org"), randomID("realcheck-conn"), randomID("realcheck-app")
	const redirectURI = "http://127.0.0.1:1/"
	mock, err := mockidp.Start(mockidp.Config{
		Name: "realcheck", Addr: "127.0.0.1:0", ClientID: "realcheck-client", ClientSecret: "realcheck-secret",
		Identities: []mockidp.Identity{
			{Subject: "person", Email: "person@" + domain, Name: "Person", EmailVerified: true},
			{Subject: "unlinked", Email: "unlinked@" + domain, Name: "Unlinked", EmailVerified: true},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = mock.Shutdown() })
	t.Setenv(broker.SecretEnvName(connectionID), "realcheck-secret")

	uid := tempUser(t, map[string]any{"practice": "stored-practice"})
	link := broker.Link{ConnectionID: connectionID, Subject: connectionID + "|person", ProjectID: cfg.ProjectID, UID: uid}
	for _, err := range []error{
		store.PutOrg(ctx, broker.Org{ID: orgID, Name: "Real Check", Domains: []string{domain}}),
		store.PutConnection(ctx, broker.Connection{ID: connectionID, OrgID: orgID, Name: "Real Check", Kind: connector.KindOkta, Issuer: mock.Issuer(), ClientID: "realcheck-client", Enabled: true}),
		store.PutApp(ctx, broker.App{ID: appID, Name: "Real Check", ProjectID: cfg.ProjectID, RedirectURIs: []string{redirectURI}}),
		store.PutLink(ctx, link),
	} {
		if err != nil {
			t.Fatalf("writing to real Firestore: %v", err)
		}
	}
	t.Cleanup(func() {
		ctx := context.Background()
		docs, err := fs.Collection("links").Where("uid", "==", uid).Documents(ctx).GetAll()
		if err != nil {
			t.Error(err)
		}
		for _, doc := range docs {
			if _, err := doc.Ref.Delete(ctx); err != nil {
				t.Error(err)
			}
		}
		for collection, id := range map[string]string{"orgs": orgID, "connections": connectionID, "apps": appID} {
			if _, err := fs.Collection(collection).Doc(id).Delete(ctx); err != nil {
				t.Error(err)
			}
		}
	})

	var handler http.Handler
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.ServeHTTP(w, r) }))
	t.Cleanup(server.Close)
	handler = broker.New(broker.Config{
		BaseURL: server.URL, Store: store, Auth: map[string]*auth.Client{cfg.ProjectID: authClient}, AllowLocalProviders: true,
	}).Handler()

	// signInAs routes by email, signs in at the mock, and returns where the browser ends up.
	signInAs := func(t *testing.T, subject, state, verifier string) url.Values {
		t.Helper()
		jar, err := cookiejar.New(nil)
		if err != nil {
			t.Fatal(err)
		}
		browser := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		res, err := browser.PostForm(server.URL+"/authorize", url.Values{
			"app_id": {appID}, "redirect_uri": {redirectURI}, "state": {state}, "email": {subject + "@" + domain},
			"code_challenge": {challengeFor(verifier)}, "code_challenge_method": {"S256"},
		})
		if err != nil {
			t.Fatal(err)
		}
		_ = res.Body.Close()
		location := res.Header.Get("Location")
		if !strings.HasPrefix(location, mock.Issuer()) {
			t.Fatalf("routed to %q", location)
		}
		res, err = browser.Get(location + "&mock_user=" + subject)
		if err != nil {
			t.Fatal(err)
		}
		_ = res.Body.Close()
		res, err = browser.Get(res.Header.Get("Location"))
		if err != nil {
			t.Fatal(err)
		}
		_ = res.Body.Close()
		back, err := url.Parse(res.Header.Get("Location"))
		if err != nil {
			t.Fatal(err)
		}
		return back.Query()
	}
	exchange := func(t *testing.T, code, verifier string) (int, string) {
		t.Helper()
		res, err := http.PostForm(server.URL+"/token", url.Values{"app_id": {appID}, "code": {code}, "code_verifier": {verifier}, "redirect_uri": {redirectURI}})
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = res.Body.Close() }()
		body, err := io.ReadAll(res.Body)
		if err != nil {
			t.Fatal(err)
		}
		return res.StatusCode, string(body)
	}

	t.Run("a linked person gets a working session", func(t *testing.T) {
		verifier := oauth2.GenerateVerifier()
		result := signInAs(t, "person", "state-1", verifier)
		if result.Get("code") == "" {
			t.Fatalf("refused: %v", result)
		}
		status, body := exchange(t, result.Get("code"), verifier)
		var parsed struct {
			CustomToken string `json:"custom_token"`
		}
		if err := json.Unmarshal([]byte(body), &parsed); err != nil || parsed.CustomToken == "" {
			t.Fatalf("exchange = %d", status)
		}
		httpStatus, idToken, refreshToken := exchangeCustomToken(t, parsed.CustomToken)
		if idToken == "" {
			t.Fatalf("real sign-in = %d", httpStatus)
		}
		verified, err := authClient.VerifyIDTokenAndCheckRevoked(ctx, refresh(t, refreshToken))
		if err != nil {
			t.Fatal(err)
		}
		if verified.UID != uid || verified.Claims["org"] != orgID || verified.Claims["practice"] != "stored-practice" {
			t.Errorf("verified = %+v", verified)
		}
	})

	t.Run("someone with no link is refused", func(t *testing.T) {
		result := signInAs(t, "unlinked", "state-2", oauth2.GenerateVerifier())
		if result.Get("code") != "" || result.Get("error") != "access_denied" {
			t.Errorf("result = %v", result)
		}
	})

	t.Run("a code works once, under real transactions", func(t *testing.T) {
		verifier := oauth2.GenerateVerifier()
		code := signInAs(t, "person", "state-3", verifier).Get("code")
		var wins atomic.Int32
		var wg sync.WaitGroup
		for range 8 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if status, _ := exchange(t, code, verifier); status == http.StatusOK {
					wins.Add(1)
				}
			}()
		}
		wg.Wait()
		if got := wins.Load(); got != 1 {
			t.Errorf("%d exchanges succeeded", got)
		}
	})
}
