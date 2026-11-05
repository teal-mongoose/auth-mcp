// Package devenv describes the local Firebase setup: emulator-only projects and their addresses.
// Nothing here can reach a real project.
package devenv

import (
	"context"
	"fmt"
	"os"
	"sync"

	firebase "firebase.google.com/go/v4"
	"firebase.google.com/go/v4/auth"

	"github.com/teal-mongoose/auth-mcp/internal/safety"
)

// Project ids. The demo- prefix makes Firebase treat them as emulator-only.
const (
	BrokerProject = "demo-auth-mcp"
	AppAProject   = "demo-test-app-a"
	AppBProject   = "demo-test-app-b"
)

// Addresses used by the stack, all on this machine.
const (
	BrokerAuthHost = "127.0.0.1:9399"
	AppAAuthHost   = "127.0.0.1:9398"
	AppBAuthHost   = "127.0.0.1:9397"
	FirestoreHost  = "127.0.0.1:8280"
	BindAddr       = "127.0.0.1:8701"
)

const (
	authEmulatorEnv      = "FIREBASE_AUTH_EMULATOR_HOST"
	firestoreEmulatorEnv = "FIRESTORE_EMULATOR_HOST"
)

// Projects lists every Firebase project in the stack.
func Projects() []safety.Project {
	return []safety.Project{
		{ID: BrokerProject, AuthEmulatorHost: BrokerAuthHost},
		{ID: AppAProject, AuthEmulatorHost: AppAAuthHost},
		{ID: AppBProject, AuthEmulatorHost: AppBAuthHost},
	}
}

// Emulator is one Firebase emulator process.
type Emulator struct {
	Project string
	Config  string // Relative to the repo root.
	Only    string
	Hosts   []string
}

// Emulators lists the emulator processes the stack runs, one per project.
func Emulators() []Emulator {
	return []Emulator{
		{Project: BrokerProject, Config: "firebase.json", Only: "auth,firestore", Hosts: []string{BrokerAuthHost, FirestoreHost}},
		{Project: AppAProject, Config: "firebase/app-a.json", Only: "auth", Hosts: []string{AppAAuthHost}},
		{Project: AppBProject, Config: "firebase/app-b.json", Only: "auth", Hosts: []string{AppBAuthHost}},
	}
}

// SetEmulatorEnv fills in the emulator variables if they're unset. A value already set is kept, so
// that the safety check gets to refuse a bad one rather than this overwriting it.
func SetEmulatorEnv() error {
	for name, value := range map[string]string{authEmulatorEnv: BrokerAuthHost, firestoreEmulatorEnv: FirestoreHost} {
		if os.Getenv(name) != "" {
			continue
		}
		if err := os.Setenv(name, value); err != nil {
			return err
		}
	}
	return nil
}

// SafetyConfig returns the startup safety config from the current environment.
func SafetyConfig() safety.Config {
	return safety.FromEnv(BindAddr, Projects())
}

var authClientMu sync.Mutex

// AuthClient returns an Admin SDK client for one project's own Auth emulator.
//
// The SDK reads the emulator address from the environment once, when the client is created. So the
// variable is switched only for that moment, under a lock.
func AuthClient(ctx context.Context, project safety.Project) (*auth.Client, error) {
	authClientMu.Lock()
	defer authClientMu.Unlock()

	previous, wasSet := os.LookupEnv(authEmulatorEnv)
	if err := os.Setenv(authEmulatorEnv, project.AuthEmulatorHost); err != nil {
		return nil, err
	}
	defer func() {
		if wasSet {
			_ = os.Setenv(authEmulatorEnv, previous)
		} else {
			_ = os.Unsetenv(authEmulatorEnv)
		}
	}()

	app, err := firebase.NewApp(ctx, &firebase.Config{ProjectID: project.ID})
	if err != nil {
		return nil, fmt.Errorf("firebase app for %s: %w", project.ID, err)
	}
	client, err := app.Auth(ctx)
	if err != nil {
		return nil, fmt.Errorf("auth client for %s: %w", project.ID, err)
	}
	return client, nil
}

// AuthClients returns a client for every project, keyed by project id.
func AuthClients(ctx context.Context) (map[string]*auth.Client, error) {
	clients := map[string]*auth.Client{}
	for _, project := range Projects() {
		client, err := AuthClient(ctx, project)
		if err != nil {
			return nil, err
		}
		clients[project.ID] = client
	}
	return clients, nil
}
