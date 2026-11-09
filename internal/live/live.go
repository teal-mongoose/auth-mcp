// Package live wires the server to a real Firebase project, as opposed to the local emulators.
//
// It refuses to run in emulator mode, where the Admin SDK doesn't check token signatures. It also refuses
// any project but throwaway auth-mcp-test-... ones and the staging project, because this machine's default
// credentials can reach real projects. Serving a real app's project will need its own explicit entry.
package live

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"

	"cloud.google.com/go/firestore"
	firebase "firebase.google.com/go/v4"
	"firebase.google.com/go/v4/auth"
	"google.golang.org/api/option"

	"github.com/teal-mongoose/auth-mcp/internal/admin"
	"github.com/teal-mongoose/auth-mcp/internal/broker"
	"github.com/teal-mongoose/auth-mcp/internal/connector"
)

// Fixed ids for the test setup.
const (
	OrgStaff         = "healthspaces"
	ConnectionGoogle = "staff-google"
	AppTest          = "test-app"
	AppAdmin         = "test-admin"
)

const (
	defaultBaseURL  = "http://localhost:8701"
	defaultBindAddr = "127.0.0.1:8701"
	// TestAppOrigin and AdminOrigin are where cmd/testpages serves its pages.
	TestAppOrigin = "http://localhost:8711"
	AdminOrigin   = "http://localhost:8713"
)

// allowedProjects are throwaway test projects and, by its exact name, the staging project. It's owned by the
// teal mongoose Google account, outside the healthspaces.com organization.
var allowedProjects = regexp.MustCompile(`^(auth-mcp-test-[a-z0-9-]+|auth-mcp-staging-tm)$`)

// Config says how to run against a real project.
type Config struct {
	ProjectID string
	// ServiceAccount is the account custom tokens are signed as, through Google's IAM API. No key file
	// is involved: the caller's own credentials need permission to sign as this account.
	ServiceAccount string
	BaseURL        string
	BindAddr       string
	AdminOrigins   []string

	// These must all be empty. They're here so that Check can refuse them.
	AuthEmulatorHost      string
	FirestoreEmulatorHost string
	CredentialsFile       string
}

// FromEnv builds a Config from the environment.
func FromEnv() Config {
	return Config{
		ProjectID:             os.Getenv("AUTH_MCP_PROJECT_ID"),
		ServiceAccount:        os.Getenv("AUTH_MCP_SERVICE_ACCOUNT"),
		BaseURL:               envOr("AUTH_MCP_BASE_URL", defaultBaseURL),
		BindAddr:              bindAddrFromEnv(),
		AdminOrigins:          adminOriginsFromEnv(),
		AuthEmulatorHost:      os.Getenv("FIREBASE_AUTH_EMULATOR_HOST"),
		FirestoreEmulatorHost: os.Getenv("FIRESTORE_EMULATOR_HOST"),
		CredentialsFile:       os.Getenv("GOOGLE_APPLICATION_CREDENTIALS"),
	}
}

// bindAddrFromEnv uses AUTH_MCP_BIND_ADDR if set, then Cloud Run's PORT, then this machine's default.
func bindAddrFromEnv() string {
	if addr := os.Getenv("AUTH_MCP_BIND_ADDR"); addr != "" {
		return addr
	}
	if port := os.Getenv("PORT"); port != "" {
		return ":" + port
	}
	return defaultBindAddr
}

// adminOriginsFromEnv reads AUTH_MCP_ADMIN_ORIGINS, separated by commas. When it's unset, the local admin
// screen is allowed only if the broker itself is local.
func adminOriginsFromEnv() []string {
	value, set := os.LookupEnv("AUTH_MCP_ADMIN_ORIGINS")
	if !set {
		if IsLocalBaseURL(envOr("AUTH_MCP_BASE_URL", defaultBaseURL)) {
			return []string{AdminOrigin}
		}
		return nil
	}
	var origins []string
	for _, origin := range strings.Split(value, ",") {
		if origin = strings.TrimSpace(origin); origin != "" {
			origins = append(origins, origin)
		}
	}
	return origins
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

// Check returns every reason not to run against this project, or nil if there are none.
func Check(c Config) error {
	var errs []error

	if c.AuthEmulatorHost != "" {
		errs = append(errs, errors.New("FIREBASE_AUTH_EMULATOR_HOST must not be set: in that mode, token signatures aren't checked"))
	}
	if c.FirestoreEmulatorHost != "" {
		errs = append(errs, errors.New("FIRESTORE_EMULATOR_HOST must not be set"))
	}
	if c.CredentialsFile != "" {
		errs = append(errs, errors.New("GOOGLE_APPLICATION_CREDENTIALS must not be set: this setup uses no key file"))
	}

	if !allowedProjects.MatchString(c.ProjectID) {
		errs = append(errs, fmt.Errorf("AUTH_MCP_PROJECT_ID %q must be a throwaway auth-mcp-test-something project, or auth-mcp-staging-tm", c.ProjectID))
	}
	if c.ServiceAccount == "" {
		errs = append(errs, errors.New("AUTH_MCP_SERVICE_ACCOUNT must be set"))
	} else if !strings.HasSuffix(c.ServiceAccount, "@"+c.ProjectID+".iam.gserviceaccount.com") {
		errs = append(errs, errors.New("AUTH_MCP_SERVICE_ACCOUNT must belong to the project in AUTH_MCP_PROJECT_ID"))
	}

	base, err := url.Parse(c.BaseURL)
	switch {
	case err != nil || base.Host == "" || base.Path != "":
		errs = append(errs, fmt.Errorf("AUTH_MCP_BASE_URL %q must be a scheme and host, with no path", c.BaseURL))
	case IsLocalBaseURL(c.BaseURL):
		host, _, err := net.SplitHostPort(c.BindAddr)
		if err != nil || host != "127.0.0.1" {
			errs = append(errs, fmt.Errorf("with a local base URL, AUTH_MCP_BIND_ADDR %q must use 127.0.0.1", c.BindAddr))
		}
	case base.Scheme != "https":
		errs = append(errs, fmt.Errorf("AUTH_MCP_BASE_URL %q must use https, unless it's on this machine", c.BaseURL))
	}

	return errors.Join(errs...)
}

// IsLocalBaseURL says whether the broker is only reachable on this machine, over plain http.
func IsLocalBaseURL(value string) bool {
	u, err := url.Parse(value)
	if err != nil || u.Scheme != "http" {
		return false
	}
	return u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1"
}

// Clients returns Admin SDK and Firestore clients for the project. Run Check first. The returned function
// releases their resources.
func Clients(ctx context.Context, cfg Config) (*auth.Client, *firestore.Client, func(), error) {
	if err := Check(cfg); err != nil {
		return nil, nil, nil, fmt.Errorf("refusing to connect:\n%w", err)
	}

	// With a person's credentials, Google needs to be told which project these calls count against.
	quota := option.WithQuotaProject(cfg.ProjectID)

	app, err := firebase.NewApp(ctx, &firebase.Config{ProjectID: cfg.ProjectID, ServiceAccountID: cfg.ServiceAccount}, quota)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("firebase app: %w", err)
	}
	authClient, err := app.Auth(ctx)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("auth client: %w", err)
	}
	fs, err := firestore.NewClient(ctx, cfg.ProjectID, quota)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("firestore client: %w", err)
	}
	return authClient, fs, func() { _ = fs.Close() }, nil
}

// NewHandler builds the whole server's handler: the sign-in flow, and the admin MCP server at /mcp. The
// returned function releases its resources.
func NewHandler(ctx context.Context, cfg Config) (http.Handler, func(), error) {
	authClient, fs, closeClients, err := Clients(ctx, cfg)
	if err != nil {
		return nil, nil, err
	}
	store := broker.NewStore(fs)
	clients := map[string]*auth.Client{cfg.ProjectID: authClient}

	mux := http.NewServeMux()
	mux.Handle("/", broker.New(broker.Config{
		BaseURL:            cfg.BaseURL,
		Store:              store,
		Auth:               clients,
		AllowLocalRedirect: IsLocalBaseURL(cfg.BaseURL),
	}).Handler())
	mux.Handle("/mcp", admin.New(admin.Config{
		Store:          store,
		Auth:           clients,
		AdminProject:   cfg.ProjectID,
		AdminOrg:       OrgStaff,
		AllowedOrigins: cfg.AdminOrigins,
	}).Handler())
	return mux, closeClients, nil
}

// Setup describes what cmd/auth-setup saves to the project.
type Setup struct {
	GoogleClientID string
	StaffDomains   []string
}

// SetupFromEnv builds a Setup from the environment.
func SetupFromEnv() (Setup, error) {
	setup := Setup{GoogleClientID: os.Getenv("AUTH_MCP_GOOGLE_CLIENT_ID")}
	for _, domain := range strings.Split(os.Getenv("AUTH_MCP_STAFF_DOMAINS"), ",") {
		if domain = strings.TrimSpace(domain); domain != "" {
			setup.StaffDomains = append(setup.StaffDomains, domain)
		}
	}
	var errs []error
	if setup.GoogleClientID == "" {
		errs = append(errs, errors.New("AUTH_MCP_GOOGLE_CLIENT_ID must be set"))
	}
	if len(setup.StaffDomains) == 0 {
		errs = append(errs, errors.New("AUTH_MCP_STAFF_DOMAINS must be set"))
	}
	return setup, errors.Join(errs...)
}

// Save writes the staff org, the Google connection and the two test apps. It's safe to run repeatedly.
func (s Setup) Save(ctx context.Context, cfg Config, store *broker.Store) error {
	err := store.PutOrg(ctx, broker.Org{ID: OrgStaff, Name: "Healthspaces", Domains: s.StaffDomains})
	if err != nil {
		return fmt.Errorf("saving org: %w", err)
	}
	err = store.PutConnection(ctx, broker.Connection{
		ID:               ConnectionGoogle,
		OrgID:            OrgStaff,
		Name:             "Healthspaces staff (Google)",
		Kind:             connector.KindGoogle,
		Issuer:           "https://accounts.google.com",
		ClientID:         s.GoogleClientID,
		Enabled:          true,
		ShowOnSignInPage: true,
	})
	if err != nil {
		return fmt.Errorf("saving connection: %w", err)
	}
	for _, app := range []broker.App{
		{ID: AppTest, Name: "Test App", ProjectID: cfg.ProjectID, RedirectURIs: []string{TestAppOrigin + "/"}},
		{ID: AppAdmin, Name: "Test Admin", ProjectID: cfg.ProjectID, RedirectURIs: []string{AdminOrigin + "/"}},
	} {
		if err := store.PutApp(ctx, app); err != nil {
			return fmt.Errorf("saving app %s: %w", app.ID, err)
		}
	}
	return nil
}

// LoadEnvFile sets variables from a file of KEY=VALUE lines, without replacing any already set. Errors
// never quote a line, because the file holds secrets.
func LoadEnvFile(path string) error {
	// An empty path means the settings are already in the environment, as on Cloud Run.
	if path == "" {
		return nil
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()

	scanner := bufio.NewScanner(file)
	for number := 1; scanner.Scan(); number++ {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, value, found := strings.Cut(line, "=")
		name = strings.TrimSpace(name)
		if !found || name == "" {
			return fmt.Errorf("%s: line %d isn't KEY=VALUE", path, number)
		}
		if _, set := os.LookupEnv(name); set {
			continue
		}
		value = strings.TrimSpace(value)
		if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
			value = value[1 : len(value)-1]
		}
		if err := os.Setenv(name, value); err != nil {
			return fmt.Errorf("%s: line %d couldn't be set", path, number)
		}
	}
	return scanner.Err()
}
