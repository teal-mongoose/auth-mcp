package live

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/teal-mongoose/auth-mcp/internal/broker"
)

func good() Config {
	return Config{
		ProjectID:      "auth-mcp-test-1",
		ServiceAccount: "firebase-adminsdk-abc@auth-mcp-test-1.iam.gserviceaccount.com",
		BaseURL:        "http://localhost:8701",
		BindAddr:       "127.0.0.1:8701",
	}
}

func TestCheckAccepts(t *testing.T) {
	if err := Check(good()); err != nil {
		t.Errorf("local: %v", err)
	}
	deployed := good()
	deployed.BaseURL = "https://auth.example"
	deployed.BindAddr = ":8080"
	if err := Check(deployed); err != nil {
		t.Errorf("https: %v", err)
	}
}

func TestCheckRefuses(t *testing.T) {
	tests := []struct {
		name   string
		change func(*Config)
		want   string
	}{
		{"auth emulator mode", func(c *Config) { c.AuthEmulatorHost = "127.0.0.1:9399" }, "FIREBASE_AUTH_EMULATOR_HOST must not be set"},
		{"firestore emulator mode", func(c *Config) { c.FirestoreEmulatorHost = "127.0.0.1:8280" }, "FIRESTORE_EMULATOR_HOST must not be set"},
		{"key file", func(c *Config) { c.CredentialsFile = "key.json" }, "GOOGLE_APPLICATION_CREDENTIALS must not be set"},
		{"no project", func(c *Config) { c.ProjectID = "" }, "throwaway project"},
		{"a real project", func(c *Config) { c.ProjectID = "hvisit-staging" }, "throwaway project"},
		{"a production project", func(c *Config) { c.ProjectID = "hpoo-prod" }, "throwaway project"},
		{"name containing the prefix", func(c *Config) { c.ProjectID = "x-auth-mcp-test-1" }, "throwaway project"},
		{"prefix alone", func(c *Config) { c.ProjectID = "auth-mcp-test-" }, "throwaway project"},
		{"emulator project", func(c *Config) { c.ProjectID = "demo-auth-mcp" }, "throwaway project"},
		{"no service account", func(c *Config) { c.ServiceAccount = "" }, "AUTH_MCP_SERVICE_ACCOUNT must be set"},
		{"another project's service account", func(c *Config) {
			c.ServiceAccount = "firebase-adminsdk-abc@hvisit-staging.iam.gserviceaccount.com"
		}, "must belong to the project"},
		{"base URL over http elsewhere", func(c *Config) { c.BaseURL = "http://auth.example" }, "must use https"},
		{"base URL with a path", func(c *Config) { c.BaseURL = "http://localhost:8701/x" }, "no path"},
		{"base URL lookalike of localhost", func(c *Config) { c.BaseURL = "http://localhost.evil.test" }, "must use https"},
		{"local base URL bound to every interface", func(c *Config) { c.BindAddr = "0.0.0.0:8701" }, "must use 127.0.0.1"},
		{"local base URL with no host to bind", func(c *Config) { c.BindAddr = ":8701" }, "must use 127.0.0.1"},
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

func TestClientsAndHandlerRefuseAnUnsafeConfig(t *testing.T) {
	c := good()
	c.AuthEmulatorHost = "127.0.0.1:9399"
	if _, _, _, err := Clients(context.Background(), c); err == nil || !strings.Contains(err.Error(), "refusing") {
		t.Errorf("Clients() = %v", err)
	}
	if _, _, err := NewHandler(context.Background(), c); err == nil || !strings.Contains(err.Error(), "refusing") {
		t.Errorf("NewHandler() = %v", err)
	}
}

func TestFromEnv(t *testing.T) {
	t.Setenv("AUTH_MCP_PROJECT_ID", "auth-mcp-test-1")
	t.Setenv("AUTH_MCP_SERVICE_ACCOUNT", "a@auth-mcp-test-1.iam.gserviceaccount.com")
	t.Setenv("AUTH_MCP_BASE_URL", "")
	t.Setenv("AUTH_MCP_BIND_ADDR", "")
	t.Setenv("FIREBASE_AUTH_EMULATOR_HOST", "")
	t.Setenv("FIRESTORE_EMULATOR_HOST", "")
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "")
	if err := Check(FromEnv()); err != nil {
		t.Fatalf("Check(FromEnv()) = %v", err)
	}

	// The real variables are what stop this, even with a good config otherwise.
	t.Setenv("FIREBASE_AUTH_EMULATOR_HOST", "127.0.0.1:9399")
	if err := Check(FromEnv()); err == nil {
		t.Fatal("Check(FromEnv()) = nil in emulator mode")
	}
}

func TestSetupFromEnv(t *testing.T) {
	t.Setenv("AUTH_MCP_GOOGLE_CLIENT_ID", "client")
	t.Setenv("AUTH_MCP_STAFF_DOMAINS", " one.example, two.example ,")
	setup, err := SetupFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if setup.GoogleClientID != "client" || len(setup.StaffDomains) != 2 || setup.StaffDomains[1] != "two.example" {
		t.Errorf("setup = %+v", setup)
	}

	t.Setenv("AUTH_MCP_STAFF_DOMAINS", " , ")
	if _, err := SetupFromEnv(); err == nil {
		t.Error("accepted no domains")
	}
	t.Setenv("AUTH_MCP_STAFF_DOMAINS", "one.example")
	t.Setenv("AUTH_MCP_GOOGLE_CLIENT_ID", "")
	if _, err := SetupFromEnv(); err == nil {
		t.Error("accepted no client id")
	}
}

func TestSecretNameMatchesTheConnection(t *testing.T) {
	if got := broker.SecretEnvName(ConnectionGoogle); got != "AUTH_MCP_SECRET_STAFF_GOOGLE" {
		t.Errorf("SecretEnvName = %q, which .env.example needs to match", got)
	}
}

func writeEnv(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), ".env.live")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadEnvFile(t *testing.T) {
	t.Setenv("LIVE_TEST_SET_ALREADY", "from the environment")
	for _, name := range []string{"LIVE_TEST_PLAIN", "LIVE_TEST_QUOTED", "LIVE_TEST_EQUALS"} {
		t.Setenv(name, "")
		if err := os.Unsetenv(name); err != nil {
			t.Fatal(err)
		}
	}

	path := writeEnv(t, `
# A comment
LIVE_TEST_PLAIN = plain value
LIVE_TEST_QUOTED="quoted value"
LIVE_TEST_EQUALS=a=b
LIVE_TEST_SET_ALREADY=from the file
`)
	if err := LoadEnvFile(path); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{
		"LIVE_TEST_PLAIN":       "plain value",
		"LIVE_TEST_QUOTED":      "quoted value",
		"LIVE_TEST_EQUALS":      "a=b",
		"LIVE_TEST_SET_ALREADY": "from the environment",
	} {
		if got := os.Getenv(name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
}

func TestLoadEnvFileErrorsDoNotQuoteTheFile(t *testing.T) {
	path := writeEnv(t, "LIVE_TEST_FINE=1\nsuper-secret-value-with-no-equals\n")
	err := LoadEnvFile(path)
	if err == nil {
		t.Fatal("LoadEnvFile() = nil")
	}
	if strings.Contains(err.Error(), "super-secret") {
		t.Errorf("the error quotes the file: %v", err)
	}
	if !strings.Contains(err.Error(), "line 2") {
		t.Errorf("the error doesn't say where: %v", err)
	}
}

func TestLoadEnvFileMissing(t *testing.T) {
	if err := LoadEnvFile(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Fatal("LoadEnvFile() = nil for a missing file")
	}
}
