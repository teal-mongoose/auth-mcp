// Package mockidp runs local stand-ins for Google, Microsoft and Okta, for development and tests.
//
// It wraps mockoidc, adding per-provider claims such as Microsoft's tid and oid, and a small page
// for choosing who to sign in as. Mocks only behave as they are built here, so passing against them
// says nothing about a real provider's quirks.
package mockidp

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"slices"
	"sync"

	"github.com/golang-jwt/jwt/v5"
	"github.com/oauth2-proxy/mockoidc"
)

// Identity is someone a mock provider can sign in. Extra claims go into every ID token, which is
// how provider-specific claims are set, and how a provider can send a claim it shouldn't.
type Identity struct {
	Subject       string
	Email         string
	Name          string
	EmailVerified bool
	Extra         map[string]any
}

// ID implements mockoidc.User.
func (i Identity) ID() string { return i.Subject }

// Userinfo implements mockoidc.User.
func (i Identity) Userinfo(scopes []string) ([]byte, error) {
	return json.Marshal(i.claims(scopes, map[string]any{"sub": i.Subject}))
}

// Claims implements mockoidc.User.
func (i Identity) Claims(scopes []string, base *mockoidc.IDTokenClaims) (jwt.Claims, error) {
	raw, err := json.Marshal(base)
	if err != nil {
		return nil, err
	}
	claims := map[string]any{}
	if err := json.Unmarshal(raw, &claims); err != nil {
		return nil, err
	}
	return jwt.MapClaims(i.claims(scopes, claims)), nil
}

func (i Identity) claims(scopes []string, claims map[string]any) map[string]any {
	if slices.Contains(scopes, "email") {
		claims["email"] = i.Email
		claims["email_verified"] = i.EmailVerified
	}
	if slices.Contains(scopes, "profile") {
		claims["name"] = i.Name
	}
	for name, value := range i.Extra {
		claims[name] = value
	}
	return claims
}

// Config describes one mock provider. Addr must include a port, and port 0 picks a free one.
type Config struct {
	Name         string
	Addr         string
	ClientID     string
	ClientSecret string
	Identities   []Identity
}

// Provider is a running mock provider.
type Provider struct {
	config Config
	oidc   *mockoidc.MockOIDC

	mu      sync.Mutex // Also guards mockoidc's session store, which has no lock of its own.
	pending string
}

// Start runs a provider in the background until Shutdown.
func Start(cfg Config) (*Provider, error) {
	oidc, err := mockoidc.NewServer(nil)
	if err != nil {
		return nil, err
	}
	oidc.ClientID = cfg.ClientID
	oidc.ClientSecret = cfg.ClientSecret

	p := &Provider{config: cfg, oidc: oidc}
	if err := oidc.AddMiddleware(p.middleware); err != nil {
		return nil, err
	}

	listener, err := net.Listen("tcp", cfg.Addr)
	if err != nil {
		return nil, fmt.Errorf("mock provider %s: %w", cfg.Name, err)
	}
	if err := oidc.Start(listener, nil); err != nil {
		return nil, fmt.Errorf("mock provider %s: %w", cfg.Name, err)
	}
	return p, nil
}

// Issuer returns the provider's OIDC issuer URL.
func (p *Provider) Issuer() string { return p.oidc.Issuer() }

// Shutdown stops the provider.
func (p *Provider) Shutdown() error { return p.oidc.Shutdown() }

// SignInNext makes the next authorization request sign in this subject without showing the page.
func (p *Provider) SignInNext(subject string) error {
	if _, ok := p.identity(subject); !ok {
		return fmt.Errorf("mock provider %s has no identity %q", p.config.Name, subject)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.pending = subject
	return nil
}

func (p *Provider) identity(subject string) (Identity, bool) {
	for _, identity := range p.config.Identities {
		if identity.Subject == subject {
			return identity, true
		}
	}
	return Identity{}, false
}

func (p *Provider) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		defer p.mu.Unlock()

		if r.URL.Path != mockoidc.AuthorizationEndpoint {
			next.ServeHTTP(w, r)
			return
		}

		subject := r.URL.Query().Get("mock_user")
		if subject == "" {
			subject = p.pending
		}
		if subject == "" {
			p.renderChooser(w, r)
			return
		}

		identity, ok := p.identity(subject)
		if !ok {
			http.Error(w, "unknown mock_user", http.StatusBadRequest)
			return
		}
		p.pending = ""
		p.oidc.QueueUser(identity)
		next.ServeHTTP(w, r)

		// A rejected request doesn't use the queued user. Clear it, so the next sign-in can't get it.
		p.oidc.UserQueue.Lock()
		p.oidc.UserQueue.Queue = nil
		p.oidc.UserQueue.Unlock()
	})
}

var chooserPage = template.Must(template.New("chooser").Parse(`<!doctype html>
<html lang="en">
<meta charset="utf-8">
<title>{{.Name}} (mock)</title>
<body style="font-family: system-ui; max-width: 32rem; margin: 3rem auto">
<h1>{{.Name}} (mock)</h1>
<p>Local test provider. Choose who to sign in as.</p>
<ul>
{{range .Choices}}<li><a href="{{.URL}}">{{.Email}}</a></li>
{{end}}</ul>
</body>
</html>
`))

type chooserChoice struct {
	Email string
	URL   string
}

func (p *Provider) renderChooser(w http.ResponseWriter, r *http.Request) {
	data := struct {
		Name    string
		Choices []chooserChoice
	}{Name: p.config.Name}

	for _, identity := range p.config.Identities {
		query := url.Values{}
		for name, values := range r.URL.Query() {
			query[name] = values
		}
		query.Set("mock_user", identity.Subject)
		data.Choices = append(data.Choices, chooserChoice{
			Email: identity.Email,
			URL:   mockoidc.AuthorizationEndpoint + "?" + query.Encode(),
		})
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := chooserPage.Execute(w, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
