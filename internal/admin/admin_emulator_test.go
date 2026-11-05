//go:build emulator

// These tests call the admin server with a real MCP client, against the dev stack's emulators, so they
// need `go run ./cmd/dev` running.
package admin_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	firebaseauth "firebase.google.com/go/v4/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/teal-mongoose/auth-mcp/internal/admin"
	"github.com/teal-mongoose/auth-mcp/internal/broker"
	"github.com/teal-mongoose/auth-mcp/internal/devenv"
	"github.com/teal-mongoose/auth-mcp/internal/fixtures"
	"github.com/teal-mongoose/auth-mcp/internal/mockidp"
	"github.com/teal-mongoose/auth-mcp/internal/seed"
)

const allowedOrigin = "http://127.0.0.1:8713"

var (
	store   *broker.Store
	clients map[string]*firebaseauth.Client
)

func TestMain(m *testing.M) {
	ctx := context.Background()
	if err := devenv.SetEmulatorEnv(); err != nil {
		fatal(err)
	}
	var err error
	clients, err = devenv.AuthClients(ctx)
	if err != nil {
		fatal(err)
	}
	fs, err := devenv.FirestoreClient(ctx)
	if err != nil {
		fatal(err)
	}
	store = broker.NewStore(fs)
	if err := seed.Run(ctx, devenv.SafetyConfig(), clients, store); err != nil {
		fatal(fmt.Errorf("seeding: %w; is `go run ./cmd/dev` running?", err))
	}
	code := m.Run()
	_ = fs.Close()
	os.Exit(code)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

func reseedAfter(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		if err := seed.Run(context.Background(), devenv.SafetyConfig(), clients, store); err != nil {
			t.Error(err)
		}
	})
}

// syncBuffer collects log output from concurrent requests.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

type testServer struct {
	url  string
	logs *syncBuffer
}

func newServer(t *testing.T) *testServer {
	t.Helper()
	logs := &syncBuffer{}
	handler := admin.New(admin.Config{
		Store:          store,
		Auth:           clients,
		AdminProject:   devenv.BrokerProject,
		AdminOrg:       devenv.AdminOrg,
		AllowedOrigins: []string{allowedOrigin},
		Logger:         slog.New(slog.NewJSONHandler(logs, nil)),
	}).Handler()
	mux := http.NewServeMux()
	mux.Handle("/mcp", handler)
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return &testServer{url: server.URL + "/mcp", logs: logs}
}

func hostFor(projectID string) string {
	for _, project := range devenv.Projects() {
		if project.ID == projectID {
			return project.AuthEmulatorHost
		}
	}
	panic("no project " + projectID)
}

// idToken signs in the way a browser does, with extra claims on the custom token.
func idToken(t *testing.T, projectID, uid string, claims map[string]any) string {
	t.Helper()
	customToken, err := clients[projectID].CustomTokenWithClaims(context.Background(), uid, claims)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(map[string]any{"token": customToken, "returnSecureToken": true})
	if err != nil {
		t.Fatal(err)
	}
	res, err := http.Post("http://"+hostFor(projectID)+"/identitytoolkit.googleapis.com/v1/accounts:signInWithCustomToken?key=fake",
		"application/json", bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		IDToken string `json:"idToken"`
	}
	if err := json.Unmarshal(body, &result); err != nil || result.IDToken == "" {
		t.Fatalf("sign-in for %s: %s", uid, body)
	}
	return result.IDToken
}

func adminToken(t *testing.T) string {
	t.Helper()
	return idToken(t, devenv.BrokerProject, "seed-admin", map[string]any{"org": fixtures.OrgHealthspaces})
}

const initializeBody = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}`

// post sends a raw MCP initialize request.
func post(t *testing.T, target string, change func(*http.Request)) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, target, strings.NewReader(initializeBody))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	change(req)
	res, err := http.DefaultClient.Do(req)
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

// unsignedToken builds a token by hand. The emulator doesn't check signatures, so this reaches the
// checks on the claims themselves.
func unsignedToken(t *testing.T, claims map[string]any) string {
	t.Helper()
	encode := func(value any) string {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(raw)
	}
	return encode(map[string]any{"alg": "none", "typ": "JWT"}) + "." + encode(claims) + "."
}

func TestPermissions(t *testing.T) {
	server := newServer(t)
	broker := devenv.BrokerProject
	org := map[string]any{"org": fixtures.OrgHealthspaces}

	tests := []struct {
		name  string
		token func(*testing.T) string
		raw   string // A whole Authorization header, if set.
		want  int
	}{
		{name: "admin", token: adminToken, want: http.StatusOK},
		{name: "no header", want: http.StatusUnauthorized},
		{name: "not a bearer token", raw: "Basic abc123", want: http.StatusUnauthorized},
		{name: "garbage", raw: "Bearer not-a-token", want: http.StatusUnauthorized},
		{name: "expired", token: func(t *testing.T) string {
			now := time.Now()
			return unsignedToken(t, map[string]any{
				"iss": "https://securetoken.google.com/" + broker, "aud": broker, "sub": "seed-admin", "user_id": "seed-admin",
				"iat": now.Add(-2 * time.Hour).Unix(), "exp": now.Add(-time.Hour).Unix(), "auth_time": now.Add(-2 * time.Hour).Unix(),
				"admin": true, "org": fixtures.OrgHealthspaces,
			})
		}, want: http.StatusUnauthorized},
		{name: "account that doesn't exist", token: func(t *testing.T) string {
			now := time.Now()
			return unsignedToken(t, map[string]any{
				"iss": "https://securetoken.google.com/" + broker, "aud": broker, "sub": "nobody", "user_id": "nobody",
				"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(), "auth_time": now.Unix(),
				"admin": true, "org": fixtures.OrgHealthspaces,
			})
		}, want: http.StatusUnauthorized},
		{name: "admin in an app's project", token: func(t *testing.T) string {
			return idToken(t, devenv.AppAProject, "seed-customer-a", map[string]any{"admin": true, "org": fixtures.OrgHealthspaces})
		}, want: http.StatusUnauthorized},
		{name: "staff, not an admin", token: func(t *testing.T) string {
			return idToken(t, broker, "seed-staff", org)
		}, want: http.StatusForbidden},
		{name: "admin false", token: func(t *testing.T) string {
			return idToken(t, broker, "seed-staff", map[string]any{"org": fixtures.OrgHealthspaces, "admin": false})
		}, want: http.StatusForbidden},
		{name: "admin as the string true", token: func(t *testing.T) string {
			return idToken(t, broker, "seed-staff", map[string]any{"org": fixtures.OrgHealthspaces, "admin": "true"})
		}, want: http.StatusForbidden},
		{name: "admin with no org", token: func(t *testing.T) string {
			return idToken(t, broker, "seed-admin", nil)
		}, want: http.StatusForbidden},
		{name: "admin in a customer's org", token: func(t *testing.T) string {
			return idToken(t, broker, "seed-admin", map[string]any{"org": fixtures.OrgCustomerA})
		}, want: http.StatusForbidden},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			header := tt.raw
			if tt.token != nil {
				header = "Bearer " + tt.token(t)
			}
			res, body := post(t, server.url, func(req *http.Request) {
				if header != "" {
					req.Header.Set("Authorization", header)
				}
			})
			if res.StatusCode != tt.want {
				t.Errorf("status = %d, want %d: %s", res.StatusCode, tt.want, body)
			}
			if tt.want != http.StatusOK && len(body) > 40 {
				t.Errorf("a refusal said a lot: %s", body)
			}
		})
	}
}

func TestDisabledAndRevokedAdminsAreRefused(t *testing.T) {
	server := newServer(t)
	ctx := context.Background()
	client := clients[devenv.BrokerProject]
	reseedAfter(t)

	status := func(t *testing.T, token string) int {
		t.Helper()
		res, _ := post(t, server.url, func(req *http.Request) { req.Header.Set("Authorization", "Bearer "+token) })
		return res.StatusCode
	}

	t.Run("revoked", func(t *testing.T) {
		token := adminToken(t)
		if got := status(t, token); got != http.StatusOK {
			t.Fatalf("before revoking = %d", got)
		}
		time.Sleep(1100 * time.Millisecond) // Revocation works to the second.
		if err := client.RevokeRefreshTokens(ctx, "seed-admin"); err != nil {
			t.Fatal(err)
		}
		if got := status(t, token); got != http.StatusUnauthorized {
			t.Errorf("after revoking = %d", got)
		}
	})

	t.Run("disabled", func(t *testing.T) {
		if err := seed.Run(ctx, devenv.SafetyConfig(), clients, store); err != nil {
			t.Fatal(err)
		}
		token := adminToken(t)
		if _, err := client.UpdateUser(ctx, "seed-admin", (&firebaseauth.UserToUpdate{}).Disabled(true)); err != nil {
			t.Fatal(err)
		}
		if got := status(t, token); got != http.StatusUnauthorized {
			t.Errorf("after disabling = %d", got)
		}
	})
}

func TestOrigins(t *testing.T) {
	server := newServer(t)
	token := adminToken(t)

	t.Run("allowed origin can read the response", func(t *testing.T) {
		res, _ := post(t, server.url, func(req *http.Request) {
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("Origin", allowedOrigin)
		})
		if res.StatusCode != http.StatusOK {
			t.Errorf("status = %d", res.StatusCode)
		}
		if got := res.Header.Get("Access-Control-Allow-Origin"); got != allowedOrigin {
			t.Errorf("Access-Control-Allow-Origin = %q", got)
		}
	})

	t.Run("another origin is refused, even with an admin's token", func(t *testing.T) {
		res, body := post(t, server.url, func(req *http.Request) {
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("Origin", "https://evil.test")
		})
		if res.StatusCode != http.StatusForbidden {
			t.Errorf("status = %d: %s", res.StatusCode, body)
		}
		if got := res.Header.Get("Access-Control-Allow-Origin"); got != "" {
			t.Errorf("Access-Control-Allow-Origin = %q", got)
		}
	})

	t.Run("allowed origin in a refusal can read why", func(t *testing.T) {
		res, _ := post(t, server.url, func(req *http.Request) { req.Header.Set("Origin", allowedOrigin) })
		if res.StatusCode != http.StatusUnauthorized || res.Header.Get("Access-Control-Allow-Origin") != allowedOrigin {
			t.Errorf("status = %d, Access-Control-Allow-Origin = %q", res.StatusCode, res.Header.Get("Access-Control-Allow-Origin"))
		}
	})

	preflight := func(t *testing.T, origin string) *http.Response {
		t.Helper()
		req, err := http.NewRequest(http.MethodOptions, server.url, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Origin", origin)
		req.Header.Set("Access-Control-Request-Method", "POST")
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = res.Body.Close()
		return res
	}

	t.Run("preflight from the allowed origin", func(t *testing.T) {
		res := preflight(t, allowedOrigin)
		if res.StatusCode != http.StatusNoContent || res.Header.Get("Access-Control-Allow-Origin") != allowedOrigin {
			t.Errorf("status = %d, Access-Control-Allow-Origin = %q", res.StatusCode, res.Header.Get("Access-Control-Allow-Origin"))
		}
		if !strings.Contains(res.Header.Get("Access-Control-Allow-Headers"), "Authorization") {
			t.Errorf("Access-Control-Allow-Headers = %q", res.Header.Get("Access-Control-Allow-Headers"))
		}
	})

	t.Run("preflight from another origin", func(t *testing.T) {
		res := preflight(t, "https://evil.test")
		if res.StatusCode != http.StatusForbidden || res.Header.Get("Access-Control-Allow-Origin") != "" {
			t.Errorf("status = %d, Access-Control-Allow-Origin = %q", res.StatusCode, res.Header.Get("Access-Control-Allow-Origin"))
		}
	})

	t.Run("another host name, as in DNS rebinding", func(t *testing.T) {
		res, _ := post(t, server.url, func(req *http.Request) {
			req.Header.Set("Authorization", "Bearer "+token)
			req.Host = "evil.test"
		})
		if res.StatusCode != http.StatusForbidden {
			t.Errorf("status = %d", res.StatusCode)
		}
	})
}

func TestResponsesAreNotCached(t *testing.T) {
	server := newServer(t)
	res, _ := post(t, server.url, func(req *http.Request) { req.Header.Set("Authorization", "Bearer "+adminToken(t)) })
	if got := res.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q", got)
	}
}

func TestServerIsStatelessAndAnswersInJSON(t *testing.T) {
	server := newServer(t)
	res, _ := post(t, server.url, func(req *http.Request) { req.Header.Set("Authorization", "Bearer "+adminToken(t)) })
	if got := res.Header.Get("Mcp-Session-Id"); got != "" {
		t.Errorf("Mcp-Session-Id = %q, want no session", got)
	}
	if got := res.Header.Get("Content-Type"); !strings.HasPrefix(got, "application/json") {
		t.Errorf("Content-Type = %q", got)
	}
}

func TestHugeRequestIsRejected(t *testing.T) {
	server := newServer(t)
	req, err := http.NewRequest(http.MethodPost, server.url, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"x":"`+strings.Repeat("a", 128<<10)+`"}}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Authorization", "Bearer "+adminToken(t))
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d", res.StatusCode)
	}
}

// bearerTransport adds a token to every request, as an admin screen does.
type bearerTransport struct {
	token string
}

func (b bearerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.Header.Set("Authorization", "Bearer "+b.token)
	return http.DefaultTransport.RoundTrip(req)
}

// session is a real MCP client session as an admin.
func session(t *testing.T, server *testServer) *mcp.ClientSession {
	t.Helper()
	client := mcp.NewClient(&mcp.Implementation{Name: "test-admin", Version: "1"}, nil)
	transport := &mcp.StreamableClientTransport{
		Endpoint:   server.url,
		HTTPClient: &http.Client{Transport: bearerTransport{token: adminToken(t)}},
	}
	s, err := client.Connect(context.Background(), transport, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// call runs a tool, and returns its structured output, whether it reported an error, and all of the
// text the caller received.
func call(t *testing.T, s *mcp.ClientSession, tool string, args map[string]any) (map[string]any, bool, string) {
	t.Helper()
	result, err := s.CallTool(context.Background(), &mcp.CallToolParams{Name: tool, Arguments: args})
	if err != nil {
		t.Fatalf("%s: %v", tool, err)
	}
	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	output := map[string]any{}
	if result.StructuredContent != nil {
		structured, err := json.Marshal(result.StructuredContent)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(structured, &output); err != nil {
			t.Fatal(err)
		}
	}
	return output, result.IsError, string(raw)
}

func mustCall(t *testing.T, s *mcp.ClientSession, tool string, args map[string]any) map[string]any {
	t.Helper()
	output, isError, raw := call(t, s, tool, args)
	if isError {
		t.Fatalf("%s(%v) failed: %s", tool, args, raw)
	}
	return output
}

func TestToolList(t *testing.T) {
	s := session(t, newServer(t))
	result, err := s.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}

	got := []string{}
	for _, tool := range result.Tools {
		got = append(got, tool.Name)
		if tool.Annotations == nil || !tool.Annotations.ReadOnlyHint {
			t.Errorf("%s isn't marked read-only", tool.Name)
		}
		if tool.Description == "" {
			t.Errorf("%s has no description", tool.Name)
		}
	}
	slices.Sort(got)
	want := []string{"get_connection", "get_org", "get_user", "get_user_links", "list_apps", "list_connections", "list_orgs", "list_sign_in_events", "list_users"}
	if !slices.Equal(got, want) {
		t.Errorf("tools = %v, want %v", got, want)
	}
}

func TestListAppsOrgsAndConnections(t *testing.T) {
	s := session(t, newServer(t))

	apps := mustCall(t, s, "list_apps", nil)["apps"].([]any)
	if len(apps) != len(fixtures.Apps()) {
		t.Errorf("%d apps, want %d", len(apps), len(fixtures.Apps()))
	}
	first := apps[0].(map[string]any)
	if first["id"] != fixtures.AppAdmin || first["project_id"] != devenv.BrokerProject {
		t.Errorf("first app = %v", first)
	}

	orgs := mustCall(t, s, "list_orgs", nil)["orgs"].([]any)
	if len(orgs) != len(fixtures.Orgs()) {
		t.Errorf("%d orgs, want %d", len(orgs), len(fixtures.Orgs()))
	}

	connections := mustCall(t, s, "list_connections", nil)["connections"].([]any)
	if len(connections) != len(fixtures.Connections()) {
		t.Errorf("%d connections, want %d", len(connections), len(fixtures.Connections()))
	}

	org := mustCall(t, s, "get_org", map[string]any{"org_id": fixtures.OrgCustomerC})
	if org["org"].(map[string]any)["name"] != "Customer C" {
		t.Errorf("org = %v", org["org"])
	}
	orgConnections := org["connections"].([]any)
	if len(orgConnections) != 1 || orgConnections[0].(map[string]any)["id"] != fixtures.ConnectionMicrosoftC {
		t.Errorf("org connections = %v", orgConnections)
	}

	connection := mustCall(t, s, "get_connection", map[string]any{"connection_id": fixtures.ConnectionMicrosoftC})["connection"].(map[string]any)
	if connection["tenant_id"] != "tenant-customer-c" || connection["org_id"] != fixtures.OrgCustomerC || connection["enabled"] != true {
		t.Errorf("connection = %v", connection)
	}
}

func TestGetUser(t *testing.T) {
	s := session(t, newServer(t))

	t.Run("by uid", func(t *testing.T) {
		user := mustCall(t, s, "get_user", map[string]any{"app_id": fixtures.AppA, "uid": "seed-customer-a"})["user"].(map[string]any)
		if user["email"] != "user@customer-a.test" || user["disabled"] != false {
			t.Errorf("user = %v", user)
		}
		claims := user["claims"].(map[string]any)
		if claims["practice"] != "customer-a" || claims["clinic"] != "main" || claims["admin"] != false {
			t.Errorf("claims = %v", claims)
		}
		if user["created_at"] == nil {
			t.Errorf("no created_at: %v", user)
		}
	})

	t.Run("by email", func(t *testing.T) {
		user := mustCall(t, s, "get_user", map[string]any{"app_id": fixtures.AppB, "email": "user@customer-a.test"})["user"].(map[string]any)
		if user["uid"] != "seed-customer-a-in-b" {
			t.Errorf("uid = %v", user["uid"])
		}
	})

	t.Run("shows providers", func(t *testing.T) {
		user := mustCall(t, s, "get_user", map[string]any{"app_id": fixtures.AppA, "uid": "seed-staff"})["user"].(map[string]any)
		providers := user["provider_ids"].([]any)
		if len(providers) != 1 || providers[0] != "google.com" {
			t.Errorf("provider_ids = %v", providers)
		}
	})

	t.Run("disabled account says so", func(t *testing.T) {
		user := mustCall(t, s, "get_user", map[string]any{"app_id": fixtures.AppA, "uid": "seed-disabled"})["user"].(map[string]any)
		if user["disabled"] != true {
			t.Errorf("user = %v", user)
		}
	})

	t.Run("hidden claim shows its name only", func(t *testing.T) {
		output, _, raw := call(t, s, "get_user", map[string]any{"app_id": fixtures.AppA, "uid": "seed-odd-claims"})
		user := output["user"].(map[string]any)
		if _, shown := user["claims"].(map[string]any)["password"]; shown {
			t.Errorf("claims = %v", user["claims"])
		}
		hidden := user["hidden_claims"].([]any)
		if len(hidden) != 1 || hidden[0] != "password" {
			t.Errorf("hidden_claims = %v", hidden)
		}
		if strings.Contains(raw, "generic-hidden-value") {
			t.Errorf("the value is in the output: %s", raw)
		}
	})
}

func TestBadToolRequests(t *testing.T) {
	s := session(t, newServer(t))
	tests := []struct {
		name string
		tool string
		args map[string]any
		want string
	}{
		{"get_user with neither", "get_user", map[string]any{"app_id": fixtures.AppA}, "exactly one"},
		{"get_user with both", "get_user", map[string]any{"app_id": fixtures.AppA, "uid": "x", "email": "x@y.test"}, "exactly one"},
		{"get_user with a bad email", "get_user", map[string]any{"app_id": fixtures.AppA, "email": "not-an-email"}, "isn't an email"},
		{"get_user with a huge uid", "get_user", map[string]any{"app_id": fixtures.AppA, "uid": strings.Repeat("a", 200)}, "too long"},
		{"get_user with an unknown uid", "get_user", map[string]any{"app_id": fixtures.AppA, "uid": "nobody"}, "no user found"},
		{"get_user with an unknown email", "get_user", map[string]any{"app_id": fixtures.AppA, "email": "nobody@customer-a.test"}, "no user found"},
		{"user in another project isn't found", "get_user", map[string]any{"app_id": fixtures.AppB, "uid": "seed-customer-a"}, "no user found"},
		{"get_user with an unknown app", "get_user", map[string]any{"app_id": "nope", "uid": "x"}, "no app"},
		{"list_users with an unknown app", "list_users", map[string]any{"app_id": "nope"}, "no app"},
		{"list_users with too high a limit", "list_users", map[string]any{"app_id": fixtures.AppA, "limit": 101}, "limit must be"},
		{"list_users with a negative limit", "list_users", map[string]any{"app_id": fixtures.AppA, "limit": -1}, "limit must be"},
		{"list_sign_in_events with too high a limit", "list_sign_in_events", map[string]any{"limit": 101}, "limit must be"},
		{"get_user_links with an unknown app", "get_user_links", map[string]any{"app_id": "nope", "uid": "x"}, "no app"},
		{"get_org with an unknown id", "get_org", map[string]any{"org_id": "nope"}, "no org"},
		{"get_connection with an unknown id", "get_connection", map[string]any{"connection_id": "nope"}, "no connection"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, isError, raw := call(t, s, tt.tool, tt.args)
			if !isError {
				t.Fatalf("no error: %s", raw)
			}
			if !strings.Contains(raw, tt.want) {
				t.Errorf("result = %s, want it to contain %q", raw, tt.want)
			}
		})
	}
}

func TestUnknownToolsAndWritesDoNotExist(t *testing.T) {
	s := session(t, newServer(t))
	for _, tool := range []string{"set_custom_claims", "delete_user", "create_user", "disable_user"} {
		result, err := s.CallTool(context.Background(), &mcp.CallToolParams{Name: tool})
		if err == nil && !result.IsError {
			t.Errorf("%s ran", tool)
		}
	}
}

func TestListUsersPagesThroughEveryone(t *testing.T) {
	s := session(t, newServer(t))

	want := len(fixtures.Accounts()[devenv.AppAProject])
	seen := map[string]bool{}
	token := ""
	pages := 0
	for {
		args := map[string]any{"app_id": fixtures.AppA, "limit": 2}
		if token != "" {
			args["page_token"] = token
		}
		output := mustCall(t, s, "list_users", args)
		users := output["users"].([]any)
		if len(users) > 2 {
			t.Fatalf("page of %d users, with a limit of 2", len(users))
		}
		for _, user := range users {
			uid := user.(map[string]any)["uid"].(string)
			if seen[uid] {
				t.Errorf("%s appeared twice", uid)
			}
			seen[uid] = true
		}
		pages++
		next, _ := output["next_page_token"].(string)
		if next == "" {
			break
		}
		token = next
		if pages > want+1 {
			t.Fatal("paging didn't finish")
		}
	}
	if len(seen) != want {
		t.Errorf("saw %d users, want %d: %v", len(seen), want, seen)
	}
	if pages < 2 {
		t.Errorf("%d pages, want several", pages)
	}
}

func TestListUsersWithDefaults(t *testing.T) {
	s := session(t, newServer(t))
	users := mustCall(t, s, "list_users", map[string]any{"app_id": fixtures.AppB})["users"].([]any)
	if len(users) != len(fixtures.Accounts()[devenv.AppBProject]) {
		t.Errorf("%d users", len(users))
	}
}

func TestGetUserLinks(t *testing.T) {
	s := session(t, newServer(t))

	links := mustCall(t, s, "get_user_links", map[string]any{"app_id": fixtures.AppA, "uid": "seed-customer-a"})["links"].([]any)
	if len(links) != 1 {
		t.Fatalf("links = %v", links)
	}
	link := links[0].(map[string]any)
	if link["connection_id"] != fixtures.ConnectionOktaA || link["subject"] != fixtures.ConnectionOktaA+"|okta-a-user" {
		t.Errorf("link = %v", link)
	}

	// The same uid-like value in another project has no links.
	other := mustCall(t, s, "get_user_links", map[string]any{"app_id": fixtures.AppB, "uid": "seed-customer-a"})["links"].([]any)
	if len(other) != 0 {
		t.Errorf("links in the wrong project = %v", other)
	}
}

func TestListSignInEvents(t *testing.T) {
	s := session(t, newServer(t))

	// Run a refused sign-in through the real broker, so there's an event to find.
	handler := broker.New(broker.Config{BaseURL: "http://127.0.0.1:1", Store: store, Auth: clients}).Handler()
	web := httptest.NewServer(handler)
	defer web.Close()
	for range 3 {
		res, err := http.Get(web.URL + "/callback?state=made-up&code=whatever")
		if err != nil {
			t.Fatal(err)
		}
		_ = res.Body.Close()
	}

	events := mustCall(t, s, "list_sign_in_events", map[string]any{"limit": 2})["events"].([]any)
	if len(events) != 2 {
		t.Fatalf("%d events, want the limit of 2", len(events))
	}
	newest := events[0].(map[string]any)
	if newest["outcome"] != broker.OutcomeRefused || newest["reason"] != "unknown_or_used_state" {
		t.Errorf("newest event = %v", newest)
	}
	if _, err := time.Parse(time.RFC3339, newest["time"].(string)); err != nil {
		t.Errorf("time = %v", newest["time"])
	}
}

func TestNothingSecretInAnyOutputOrLog(t *testing.T) {
	server := newServer(t)
	s := session(t, server)
	ctx := context.Background()
	reseedAfter(t)

	// Give an account a password, so that the SDK's record holds a hash and a salt.
	client := clients[devenv.BrokerProject]
	if _, err := client.UpdateUser(ctx, "seed-staff", (&firebaseauth.UserToUpdate{}).Password("generic-test-password")); err != nil {
		t.Fatal(err)
	}
	passwordHash := ""
	exported := client.Users(ctx, "")
	for {
		user, err := exported.Next()
		if err != nil {
			break
		}
		if user.UID == "seed-staff" {
			passwordHash = user.PasswordHash
		}
	}
	if passwordHash == "" {
		t.Fatal("the account has no password hash, so this test wouldn't prove anything")
	}

	calls := []struct {
		tool string
		args map[string]any
	}{
		{"list_apps", nil},
		{"list_orgs", nil},
		{"get_org", map[string]any{"org_id": fixtures.OrgCustomerA}},
		{"list_connections", nil},
		{"get_connection", map[string]any{"connection_id": fixtures.ConnectionOktaA}},
		{"get_user", map[string]any{"app_id": fixtures.AppAdmin, "uid": "seed-staff"}},
		{"get_user", map[string]any{"app_id": fixtures.AppA, "uid": "seed-odd-claims"}},
		{"list_users", map[string]any{"app_id": fixtures.AppAdmin}},
		{"list_users", map[string]any{"app_id": fixtures.AppA}},
		{"get_user_links", map[string]any{"app_id": fixtures.AppA, "uid": "seed-customer-a"}},
		{"list_sign_in_events", map[string]any{"limit": 100}},
		{"get_user", map[string]any{"app_id": fixtures.AppA, "uid": "nobody"}},
	}

	forbidden := []string{
		"generic-hidden-value", "generic-test-password", "passwordHash", "PasswordHash", "password_hash",
		"passwordSalt", "PasswordSalt", "password_salt", "fakeHash", "salt=",
		"client_secret", "ClientSecret", passwordHash,
	}
	for _, mock := range mockidp.Providers() {
		forbidden = append(forbidden, mock.ClientSecret)
	}

	var all strings.Builder
	for _, c := range calls {
		_, _, raw := call(t, s, c.tool, c.args)
		all.WriteString(raw)
	}
	logs := server.logs.String()

	for _, secret := range forbidden {
		if strings.Contains(all.String(), secret) {
			t.Errorf("tool output contains %q", secret)
		}
		if strings.Contains(logs, secret) {
			t.Errorf("logs contain %q", secret)
		}
	}
	if strings.Contains(logs, "eyJ") {
		t.Errorf("logs look like they contain a token: %s", logs)
	}
	if strings.Contains(logs, "@customer-a.test") {
		t.Errorf("logs contain tool output: %s", logs)
	}
}

func TestEveryCallIsLogged(t *testing.T) {
	server := newServer(t)
	s := session(t, server)

	mustCall(t, s, "get_user", map[string]any{"app_id": fixtures.AppA, "uid": "seed-customer-a"})
	call(t, s, "get_user", map[string]any{"app_id": fixtures.AppA, "uid": "nobody"})
	mustCall(t, s, "get_user", map[string]any{"app_id": fixtures.AppA, "email": "user@customer-a.test"})

	type line struct {
		Caller string `json:"caller"`
		Tool   string `json:"tool"`
		Target string `json:"target"`
		Result string `json:"result"`
	}
	var lines []line
	for _, raw := range strings.Split(strings.TrimSpace(server.logs.String()), "\n") {
		var parsed line
		if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
			t.Fatal(err)
		}
		if parsed.Tool != "" {
			lines = append(lines, parsed)
		}
	}
	want := []line{
		{"seed-admin", "get_user", fixtures.AppA + "/seed-customer-a", "ok"},
		{"seed-admin", "get_user", fixtures.AppA + "/nobody", "refused"},
		{"seed-admin", "get_user", fixtures.AppA + "/(by email)", "ok"},
	}
	if !slices.Equal(lines, want) {
		t.Errorf("log lines = %+v, want %+v", lines, want)
	}
}

func TestInternalErrorsStayInTheLog(t *testing.T) {
	server := newServer(t)
	s := session(t, server)
	ctx := context.Background()

	err := store.PutApp(ctx, broker.App{ID: "broken-app", Name: "Broken", ProjectID: "demo-no-such-project-secret-name", RedirectURIs: []string{"http://127.0.0.1:1/"}})
	if err != nil {
		t.Fatal(err)
	}
	fs, err := devenv.FirestoreClient(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := fs.Collection("apps").Doc("broken-app").Delete(ctx); err != nil {
			t.Error(err)
		}
		_ = fs.Close()
	})

	_, isError, raw := call(t, s, "list_users", map[string]any{"app_id": "broken-app"})
	if !isError {
		t.Fatalf("no error: %s", raw)
	}
	if strings.Contains(raw, "demo-no-such-project-secret-name") {
		t.Errorf("the caller saw internal detail: %s", raw)
	}
	if !strings.Contains(server.logs.String(), "demo-no-such-project-secret-name") {
		t.Errorf("the log is missing the detail: %s", server.logs.String())
	}
}
