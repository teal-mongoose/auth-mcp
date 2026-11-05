//go:build emulator

// These tests need the local stack, so they run only with the emulator build tag:
//
//	go run ./cmd/dev
//	go test -tags=emulator ./...
package seed

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"cloud.google.com/go/firestore"
	"firebase.google.com/go/v4/auth"

	"github.com/teal-mongoose/auth-mcp/internal/broker"
	"github.com/teal-mongoose/auth-mcp/internal/devenv"
	"github.com/teal-mongoose/auth-mcp/internal/fixtures"
	"github.com/teal-mongoose/auth-mcp/internal/mockidp"
	"github.com/teal-mongoose/auth-mcp/internal/safety"
)

func setup(t *testing.T) (context.Context, map[string]*auth.Client) {
	t.Helper()
	if err := devenv.SetEmulatorEnv(); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	clients, err := devenv.AuthClients(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := runSeed(ctx, t, devenv.SafetyConfig(), clients); err != nil {
		t.Fatalf("Run() = %v; is `go run ./cmd/dev` running?", err)
	}
	return ctx, clients
}

func runSeed(ctx context.Context, t *testing.T, cfg safety.Config, clients map[string]*auth.Client) error {
	t.Helper()
	fs, err := devenv.FirestoreClient(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fs.Close() }()
	return Run(ctx, cfg, clients, broker.NewStore(fs))
}

func TestSeedIsRepeatableAndComplete(t *testing.T) {
	ctx, clients := setup(t)

	if err := runSeed(ctx, t, devenv.SafetyConfig(), clients); err != nil {
		t.Fatalf("second Run() = %v", err)
	}

	for project, accounts := range fixtures.Accounts() {
		for _, account := range accounts {
			user, err := clients[project].GetUser(ctx, account.UID)
			if err != nil {
				t.Errorf("%s: GetUser(%s) = %v", project, account.UID, err)
				continue
			}
			if user.Email != account.Email || user.Disabled != account.Disabled {
				t.Errorf("%s: %s = %s disabled=%v, want %s disabled=%v", project, account.UID, user.Email, user.Disabled, account.Email, account.Disabled)
			}
		}
	}
}

func TestSeedRefusesAnUnsafeConfig(t *testing.T) {
	ctx, clients := setup(t)

	cfg := devenv.SafetyConfig()
	cfg.BindAddr = "0.0.0.0:8701"
	err := runSeed(ctx, t, cfg, clients)
	if err == nil || !strings.Contains(err.Error(), "refusing to seed") {
		t.Fatalf("Run() = %v, want a refusal", err)
	}
}

func TestProjectsAreIsolated(t *testing.T) {
	ctx, clients := setup(t)

	if _, err := clients[devenv.AppAProject].GetUser(ctx, "seed-customer-b"); !auth.IsUserNotFound(err) {
		t.Errorf("customer B's account in app A: err = %v, want not found", err)
	}
	if _, err := clients[devenv.BrokerProject].GetUser(ctx, "seed-customer-a"); !auth.IsUserNotFound(err) {
		t.Errorf("customer A's account in the broker project: err = %v, want not found", err)
	}

	inA, err := clients[devenv.AppAProject].GetUserByEmail(ctx, "user@customer-a.test")
	if err != nil {
		t.Fatal(err)
	}
	inB, err := clients[devenv.AppBProject].GetUserByEmail(ctx, "user@customer-a.test")
	if err != nil {
		t.Fatal(err)
	}
	if inA.UID != "seed-customer-a" || inB.UID != "seed-customer-a-in-b" {
		t.Errorf("same email resolved to uids %q and %q, want one per project", inA.UID, inB.UID)
	}
}

func TestExistingUserFoundByProviderIdentity(t *testing.T) {
	ctx, clients := setup(t)

	tests := []struct{ providerID, providerUID, wantUID string }{
		{"google.com", "google-staff", "seed-staff"},
		{"microsoft.com", "oid-customer-c", "seed-customer-c"},
	}
	for _, tt := range tests {
		result, err := clients[devenv.AppAProject].GetUsers(ctx, []auth.UserIdentifier{
			auth.ProviderIdentifier{ProviderID: tt.providerID, ProviderUID: tt.providerUID},
		})
		if err != nil {
			t.Fatal(err)
		}
		if len(result.Users) != 1 || result.Users[0].UID != tt.wantUID {
			t.Errorf("%s/%s: found %d users, want %s", tt.providerID, tt.providerUID, len(result.Users), tt.wantUID)
		}
	}
}

// signIn exchanges a custom token the way a browser does, using an API key and no project in the
// path, against one project's own emulator.
func signIn(t *testing.T, host, customToken string) (idToken string, status int, body string) {
	t.Helper()
	payload, err := json.Marshal(map[string]any{"token": customToken, "returnSecureToken": true})
	if err != nil {
		t.Fatal(err)
	}
	url := fmt.Sprintf("http://%s/identitytoolkit.googleapis.com/v1/accounts:signInWithCustomToken?key=fake", host)
	res, err := http.Post(url, "application/json", bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	raw, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		IDToken string `json:"idToken"`
	}
	_ = json.Unmarshal(raw, &parsed)
	return parsed.IDToken, res.StatusCode, string(raw)
}

func audience(t *testing.T, idToken string) string {
	t.Helper()
	parts := strings.Split(idToken, ".")
	if len(parts) < 2 {
		t.Fatalf("not a JWT: %q", idToken)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims struct {
		Aud string `json:"aud"`
	}
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatal(err)
	}
	return claims.Aud
}

func TestEachProjectSignsInToItself(t *testing.T) {
	ctx, clients := setup(t)

	uids := map[string]string{
		devenv.BrokerProject: "seed-admin",
		devenv.AppAProject:   "seed-customer-a",
		devenv.AppBProject:   "seed-customer-b",
	}
	for _, project := range devenv.Projects() {
		customToken, err := clients[project.ID].CustomToken(ctx, uids[project.ID])
		if err != nil {
			t.Fatal(err)
		}
		idToken, status, body := signIn(t, project.AuthEmulatorHost, customToken)
		if idToken == "" {
			t.Fatalf("%s: sign-in = %d: %s", project.ID, status, body)
		}

		if got := audience(t, idToken); got != project.ID {
			t.Errorf("%s: token audience = %q, want the project itself", project.ID, got)
		}

		verified, err := clients[project.ID].VerifyIDTokenAndCheckRevoked(ctx, idToken)
		if err != nil {
			t.Errorf("%s: its own token failed verification: %v", project.ID, err)
		} else if verified.UID != uids[project.ID] {
			t.Errorf("%s: verified uid = %q, want %q", project.ID, verified.UID, uids[project.ID])
		}

		for _, other := range devenv.Projects() {
			if other.ID == project.ID {
				continue
			}
			if _, err := clients[other.ID].VerifyIDToken(ctx, idToken); err == nil {
				t.Errorf("%s accepted a token from %s", other.ID, project.ID)
			}
		}
	}
}

func TestStoredClaimsReachTheToken(t *testing.T) {
	ctx, clients := setup(t)

	client := clients[devenv.BrokerProject]
	customToken, err := client.CustomToken(ctx, "seed-admin")
	if err != nil {
		t.Fatal(err)
	}
	idToken, status, body := signIn(t, devenv.BrokerAuthHost, customToken)
	if idToken == "" {
		t.Fatalf("sign-in = %d: %s", status, body)
	}
	verified, err := client.VerifyIDTokenAndCheckRevoked(ctx, idToken)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Claims["admin"] != true {
		t.Errorf("admin claim = %v, want true", verified.Claims["admin"])
	}
}

func TestDisabledAccountCannotSignIn(t *testing.T) {
	ctx, clients := setup(t)

	customToken, err := clients[devenv.AppAProject].CustomToken(ctx, "seed-disabled")
	if err != nil {
		t.Fatal(err)
	}
	if idToken, status, body := signIn(t, devenv.AppAAuthHost, customToken); idToken != "" {
		t.Fatalf("disabled account signed in: %d %s", status, body)
	}
}

func TestFirestoreEmulatorWorks(t *testing.T) {
	ctx, _ := setup(t)

	client, err := firestore.NewClient(ctx, devenv.BrokerProject)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()

	doc := client.Collection("emulator-check").Doc("round-trip")
	if _, err := doc.Set(ctx, map[string]any{"ok": true}); err != nil {
		t.Fatal(err)
	}
	snap, err := doc.Get(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if snap.Data()["ok"] != true {
		t.Errorf("read back %v", snap.Data())
	}
	if _, err := doc.Delete(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestStackIsReachable(t *testing.T) {
	setup(t)

	urls := []string{"http://" + devenv.BindAddr + "/healthz", "http://" + devenv.TestAppAAddr + "/", "http://" + devenv.TestAppBAddr + "/", "http://" + devenv.TestAdminAddr + "/"}
	for _, provider := range mockidp.Providers() {
		urls = append(urls, "http://"+provider.Addr+"/oidc/.well-known/openid-configuration")
	}
	for _, url := range urls {
		res, err := http.Get(url)
		if err != nil {
			t.Errorf("GET %s: %v", url, err)
			continue
		}
		_ = res.Body.Close()
		if res.StatusCode >= 300 {
			t.Errorf("GET %s = %d", url, res.StatusCode)
		}
	}
}
