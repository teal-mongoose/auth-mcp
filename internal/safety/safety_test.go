package safety

import (
	"strings"
	"testing"
)

func projects() []Project {
	return []Project{
		{ID: "demo-auth-mcp", AuthEmulatorHost: "127.0.0.1:9399"},
		{ID: "demo-test-app-a", AuthEmulatorHost: "127.0.0.1:9398"},
	}
}

func good() Config {
	return Config{
		AuthEmulatorHost:      "127.0.0.1:9399",
		FirestoreEmulatorHost: "localhost:8280",
		BindAddr:              "127.0.0.1:8701",
		Projects:              projects(),
	}
}

func TestCheckAcceptsLocalEmulatorSetup(t *testing.T) {
	if err := Check(good()); err != nil {
		t.Fatalf("Check() = %v, want nil", err)
	}
}

func TestCheckRefuses(t *testing.T) {
	tests := []struct {
		name   string
		change func(*Config)
		want   string
	}{
		{"auth emulator unset", func(c *Config) { c.AuthEmulatorHost = "" }, "FIREBASE_AUTH_EMULATOR_HOST must be set"},
		{"auth emulator remote", func(c *Config) { c.AuthEmulatorHost = "10.0.0.5:9399" }, "must point at this machine"},
		{"auth emulator lookalike name", func(c *Config) { c.AuthEmulatorHost = "localhost.example.com:9399" }, "must point at this machine"},
		{"auth emulator with scheme", func(c *Config) { c.AuthEmulatorHost = "http://127.0.0.1:9399" }, "not host:port"},
		{"auth emulator without port", func(c *Config) { c.AuthEmulatorHost = "127.0.0.1" }, "not host:port"},
		{"firestore emulator unset", func(c *Config) { c.FirestoreEmulatorHost = "" }, "FIRESTORE_EMULATOR_HOST must be set"},
		{"firestore emulator remote", func(c *Config) { c.FirestoreEmulatorHost = "example.com:8280" }, "must point at this machine"},
		{"bind to all interfaces", func(c *Config) { c.BindAddr = "0.0.0.0:8701" }, "must use 127.0.0.1"},
		{"bind with empty host", func(c *Config) { c.BindAddr = ":8701" }, "must use 127.0.0.1"},
		{"bind to localhost name", func(c *Config) { c.BindAddr = "localhost:8701" }, "must use 127.0.0.1"},
		{"bind without port", func(c *Config) { c.BindAddr = "127.0.0.1" }, "not host:port"},
		{"service account key", func(c *Config) { c.CredentialsFile = `C:\keys\real.json` }, "GOOGLE_APPLICATION_CREDENTIALS"},
		{"no projects", func(c *Config) { c.Projects = nil }, "no projects"},
		{"real project", func(c *Config) {
			c.Projects = append(projects(), Project{ID: "hvisit-staging", AuthEmulatorHost: "127.0.0.1:9397"})
		}, `"hvisit-staging" must start with demo-`},
		{"demo in the middle", func(c *Config) {
			c.Projects = []Project{{ID: "not-demo-project", AuthEmulatorHost: "127.0.0.1:9397"}}
		}, "must start with demo-"},
		{"project emulator unset", func(c *Config) {
			c.Projects = []Project{{ID: "demo-test-app-a"}}
		}, "Auth emulator for demo-test-app-a must be set"},
		{"project emulator remote", func(c *Config) {
			c.Projects = []Project{{ID: "demo-test-app-a", AuthEmulatorHost: "10.0.0.5:9398"}}
		}, "must point at this machine"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := good()
			tt.change(&c)
			err := Check(c)
			if err == nil {
				t.Fatal("Check() = nil, want an error")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Check() = %q, want it to contain %q", err, tt.want)
			}
		})
	}
}

func TestCheckReportsEveryProblem(t *testing.T) {
	err := Check(Config{BindAddr: "0.0.0.0:8701", CredentialsFile: "key.json"})
	if err == nil {
		t.Fatal("Check() = nil, want an error")
	}
	for _, want := range []string{"FIREBASE_AUTH_EMULATOR_HOST", "FIRESTORE_EMULATOR_HOST", "127.0.0.1", "GOOGLE_APPLICATION_CREDENTIALS", "no projects"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("Check() = %q, want it to mention %q", err, want)
		}
	}
}

func TestFromEnv(t *testing.T) {
	t.Setenv("FIREBASE_AUTH_EMULATOR_HOST", "127.0.0.1:9399")
	t.Setenv("FIRESTORE_EMULATOR_HOST", "127.0.0.1:8280")
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "")

	if err := Check(FromEnv("127.0.0.1:8701", projects())); err != nil {
		t.Fatalf("Check(FromEnv()) = %v, want nil", err)
	}

	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "key.json")
	if err := Check(FromEnv("127.0.0.1:8701", projects())); err == nil {
		t.Fatal("Check(FromEnv()) = nil with a key file set, want an error")
	}
}
