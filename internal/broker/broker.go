// Package broker is the sign-in flow apps use.
//
// An app sends someone to GET /authorize. They sign in at a provider, and come back to GET /callback.
// If the broker knows them, the app gets a single-use code at its registered redirect URI, and
// exchanges it at POST /token for a Firebase custom token in its own project. From there, Firebase
// sessions, claims and security rules work as usual.
//
// A custom token is created only at exchange. It's never stored, and never appears in a URL.
package broker

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"firebase.google.com/go/v4/auth"

	"github.com/teal-mongoose/auth-mcp/internal/connector"
)

const (
	pendingTTL      = 10 * time.Minute
	codeTTL         = time.Minute
	maxTokenBody    = 16 << 10
	maxAppStateSize = 1024
	bindingPrefix   = "auth_mcp_binding_"
)

// Refusal reasons the broker adds to those from connector. They're for admins, and apps don't see them.
const (
	reasonUnknownState      = "unknown_or_used_state"
	reasonPendingExpired    = "signin_expired"
	reasonBrowserMismatch   = "different_browser"
	reasonConnectionMissing = "connection_unavailable"
	reasonProviderDown      = "provider_unavailable"
	reasonNotLinked         = "not_linked"
	reasonAccountMissing    = "account_missing"
	reasonAccountDisabled   = "account_disabled"
	reasonCodeUnknown       = "unknown_or_used_code"
	reasonCodeExpired       = "code_expired"
	reasonCodeWrongApp      = "code_for_another_app"
	reasonCodeWrongRedirect = "code_for_another_redirect"
	reasonCodeWrongVerifier = "wrong_pkce_verifier"
)

// Errors apps see, following OAuth's names.
const (
	errorAccessDenied    = "access_denied"
	errorInvalidRequest  = "invalid_request"
	errorInvalidGrant    = "invalid_grant"
	errorTemporarilyDown = "temporarily_unavailable"
	errorServerError     = "server_error"
)

const (
	secretEnvPrefix          = "AUTH_MCP_SECRET_"
	browserProblemMessage    = "This sign-in link isn't valid in this browser. Go back to the app and try again."
	expiredProblemMessage    = "This sign-in has expired or was already used. Go back to the app and try again."
	unknownAppProblemMessage = "This app or return address isn't registered."
)

var (
	challengePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
	verifierPattern  = regexp.MustCompile(`^[A-Za-z0-9._~-]{43,128}$`)
)

// Config is what a Broker needs.
type Config struct {
	// BaseURL is the broker's public URL, without a trailing slash.
	BaseURL string
	Store   *Store
	// Auth has an Admin SDK client per Firebase project, keyed by project id.
	Auth map[string]*auth.Client
	// Secret returns a connection's client secret. Defaults to SecretFromEnv.
	Secret func(connectionID string) (connector.Secret, error)
	// Now defaults to time.Now.
	Now func() time.Time
}

// SecretEnvName is the environment variable holding a connection's client secret.
func SecretEnvName(connectionID string) string {
	return secretEnvPrefix + strings.ToUpper(strings.ReplaceAll(connectionID, "-", "_"))
}

// SecretFromEnv reads a connection's client secret from the environment.
func SecretFromEnv(connectionID string) (connector.Secret, error) {
	secret := os.Getenv(SecretEnvName(connectionID))
	if secret == "" {
		return "", fmt.Errorf("%s is not set", SecretEnvName(connectionID))
	}
	return connector.Secret(secret), nil
}

// Broker serves the sign-in flow.
type Broker struct {
	config Config

	mu         sync.Mutex
	connectors map[string]cachedConnector
}

type cachedConnector struct {
	updated   time.Time
	connector *connector.Connector
}

// New returns a Broker.
func New(cfg Config) *Broker {
	if cfg.Secret == nil {
		cfg.Secret = SecretFromEnv
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")
	return &Broker{config: cfg, connectors: map[string]cachedConnector{}}
}

// Handler returns the broker's HTTP handler.
func (b *Broker) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /authorize", b.authorize)
	mux.HandleFunc("GET /callback", b.callback)
	mux.HandleFunc("POST /token", b.token)
	return securityHeaders(mux)
}

// securityHeaders keeps states and codes in URLs from leaking, and stops these pages being framed.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Cache-Control", "no-store")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

func (b *Broker) authorize(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	query := r.URL.Query()
	appID := query.Get("app_id")
	redirectURI := query.Get("redirect_uri")

	// Until the redirect URI is known to be registered, problems must never redirect anywhere.
	app, err := b.config.Store.App(ctx, appID)
	if errors.Is(err, ErrNotFound) {
		renderProblem(w, http.StatusBadRequest, unknownAppProblemMessage)
		return
	}
	if err != nil {
		b.serverError(w, "reading app", err)
		return
	}
	if !slices.Contains(app.RedirectURIs, redirectURI) {
		renderProblem(w, http.StatusBadRequest, unknownAppProblemMessage)
		return
	}

	appState := query.Get("state")
	challenge := query.Get("code_challenge")
	if appState == "" || len(appState) > maxAppStateSize ||
		query.Get("code_challenge_method") != "S256" || !challengePattern.MatchString(challenge) {
		redirectResult(w, r, redirectURI, url.Values{"error": {errorInvalidRequest}, "state": {appState}})
		return
	}

	connectionID := query.Get("connection")
	if connectionID == "" {
		b.renderChooser(w, r, app)
		return
	}

	conn, err := b.connectorFor(ctx, connectionID)
	if err != nil {
		b.refuseConnection(w, r, err, app.ID, connectionID, redirectURI, appState)
		return
	}

	authURL, pending := conn.Begin()
	binding := rand.Text()
	err = b.config.Store.putPending(ctx, pending.State, pendingSignIn{
		AppID:        app.ID,
		ConnectionID: connectionID,
		RedirectURI:  redirectURI,
		AppState:     appState,
		Challenge:    challenge,
		Nonce:        pending.Nonce,
		Verifier:     pending.Verifier,
		BindingHash:  hash(binding),
		ExpiresAt:    b.config.Now().Add(pendingTTL),
	})
	if err != nil {
		b.serverError(w, "saving pending sign-in", err)
		return
	}

	http.SetCookie(w, b.bindingCookie(pending.State, binding, int(pendingTTL.Seconds())))
	http.Redirect(w, r, authURL, http.StatusFound)
}

// bindingCookie ties a sign-in to the browser that started it, so that someone can't trick another
// person's browser into finishing the attacker's sign-in. Each sign-in has its own, so several tabs
// can sign in at once.
func (b *Broker) bindingCookie(state, value string, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name:     bindingPrefix + hash(state)[:16],
		Value:    value,
		Path:     "/callback",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   strings.HasPrefix(b.config.BaseURL, "https://"),
		SameSite: http.SameSiteLaxMode,
	}
}

func (b *Broker) callback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	query := r.URL.Query()
	state := query.Get("state")

	// Consuming here means a callback works once, whatever happens next.
	pending, err := b.config.Store.consumePending(ctx, state)
	if errors.Is(err, ErrNotFound) {
		b.record(ctx, Event{Outcome: OutcomeRefused, Reason: reasonUnknownState})
		renderProblem(w, http.StatusBadRequest, expiredProblemMessage)
		return
	}
	if err != nil {
		b.serverError(w, "reading pending sign-in", err)
		return
	}
	http.SetCookie(w, b.bindingCookie(state, "", -1))

	base := Event{AppID: pending.AppID, ConnectionID: pending.ConnectionID, Outcome: OutcomeRefused}

	cookie, err := r.Cookie(bindingPrefix + hash(state)[:16])
	if err != nil || !equalSecrets(hash(cookie.Value), pending.BindingHash) {
		base.Reason = reasonBrowserMismatch
		b.record(ctx, base)
		renderProblem(w, http.StatusBadRequest, browserProblemMessage)
		return
	}

	deny := func(event Event) {
		b.record(ctx, event)
		redirectResult(w, r, pending.RedirectURI, url.Values{"error": {errorAccessDenied}, "state": {pending.AppState}})
	}

	if b.config.Now().After(pending.ExpiresAt) {
		base.Reason = reasonPendingExpired
		deny(base)
		return
	}

	conn, err := b.connectorFor(ctx, pending.ConnectionID)
	if err != nil {
		b.refuseConnection(w, r, err, pending.AppID, pending.ConnectionID, pending.RedirectURI, pending.AppState)
		return
	}

	identity, err := conn.Complete(ctx, connector.Pending{
		State:    state,
		Nonce:    pending.Nonce,
		Verifier: pending.Verifier,
	}, connector.Callback{
		State: query.Get("state"),
		Code:  query.Get("code"),
		Error: query.Get("error"),
	})
	if err != nil {
		var refused *connector.Refused
		if !errors.As(err, &refused) {
			b.serverError(w, "completing sign-in", err)
			return
		}
		base.Reason = string(refused.Reason)
		deny(base)
		return
	}
	base.Subject = identity.Subject
	base.Email = identity.Email

	app, err := b.config.Store.App(ctx, pending.AppID)
	if err != nil {
		b.serverError(w, "reading app", err)
		return
	}

	uid, reason, err := b.resolve(ctx, app, identity)
	if err != nil {
		b.serverError(w, "finding account", err)
		return
	}
	if reason != "" {
		base.Reason = reason
		base.UID = uid
		deny(base)
		return
	}

	code := rand.Text() + rand.Text()
	err = b.config.Store.putCode(ctx, code, authCode{
		AppID:       app.ID,
		ProjectID:   app.ProjectID,
		UID:         uid,
		RedirectURI: pending.RedirectURI,
		Challenge:   pending.Challenge,
		ExpiresAt:   b.config.Now().Add(codeTTL),
	})
	if err != nil {
		b.serverError(w, "saving code", err)
		return
	}

	base.Outcome = OutcomeSignedIn
	base.UID = uid
	b.record(ctx, base)
	redirectResult(w, r, pending.RedirectURI, url.Values{"code": {code}, "state": {pending.AppState}})
}

// resolve finds the person's account in the app's project. If it returns a reason, they're refused.
//
// Only a link or the provider's stable identity can match. Email never can.
func (b *Broker) resolve(ctx context.Context, app App, identity connector.Identity) (uid, reason string, err error) {
	client, ok := b.config.Auth[app.ProjectID]
	if !ok {
		return "", "", fmt.Errorf("no auth client for project %s", app.ProjectID)
	}

	uid, err = b.config.Store.LinkedUID(ctx, identity.ConnectionID, identity.Subject, app.ProjectID)
	if errors.Is(err, ErrNotFound) {
		uid, err = b.linkExistingUser(ctx, client, app, identity)
		if errors.Is(err, ErrNotFound) {
			return "", reasonNotLinked, nil
		}
	}
	if err != nil {
		return "", "", err
	}

	reason, err = accountProblem(ctx, client, uid)
	return uid, reason, err
}

// linkExistingUser finds someone who signed in with this provider before the broker existed, so they
// keep their uid, data and claims.
func (b *Broker) linkExistingUser(ctx context.Context, client *auth.Client, app App, identity connector.Identity) (string, error) {
	if identity.ExistingProviderID == "" {
		return "", ErrNotFound
	}
	result, err := client.GetUsers(ctx, []auth.UserIdentifier{auth.ProviderIdentifier{
		ProviderID:  identity.ExistingProviderID,
		ProviderUID: identity.ExistingProviderUID,
	}})
	if err != nil {
		return "", err
	}
	if len(result.Users) != 1 {
		return "", ErrNotFound
	}
	uid := result.Users[0].UID
	err = b.config.Store.PutLink(ctx, Link{
		ConnectionID: identity.ConnectionID,
		Subject:      identity.Subject,
		ProjectID:    app.ProjectID,
		UID:          uid,
		CreatedAt:    b.config.Now(),
	})
	return uid, err
}

func accountProblem(ctx context.Context, client *auth.Client, uid string) (string, error) {
	user, err := client.GetUser(ctx, uid)
	if auth.IsUserNotFound(err) {
		return reasonAccountMissing, nil
	}
	if err != nil {
		return "", err
	}
	if user.Disabled {
		return reasonAccountDisabled, nil
	}
	return "", nil
}

type tokenResponse struct {
	CustomToken string `json:"custom_token,omitempty"`
	Error       string `json:"error,omitempty"`
}

func (b *Broker) token(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	r.Body = http.MaxBytesReader(w, r.Body, maxTokenBody)
	if err := r.ParseForm(); err != nil {
		writeToken(w, http.StatusBadRequest, tokenResponse{Error: errorInvalidRequest})
		return
	}
	appID := r.PostForm.Get("app_id")
	code := r.PostForm.Get("code")
	verifier := r.PostForm.Get("code_verifier")
	redirectURI := r.PostForm.Get("redirect_uri")

	app, err := b.config.Store.App(ctx, appID)
	if errors.Is(err, ErrNotFound) {
		writeToken(w, http.StatusBadRequest, tokenResponse{Error: errorInvalidRequest})
		return
	}
	if err != nil {
		b.tokenServerError(w, "reading app", err)
		return
	}

	// A browser only lets a page read this response if the broker names that page's origin here. A
	// page from elsewhere is turned away before it can use up a code.
	w.Header().Add("Vary", "Origin")
	if origin := r.Header.Get("Origin"); origin != "" {
		if !originRegistered(app, origin) {
			writeToken(w, http.StatusForbidden, tokenResponse{Error: errorInvalidRequest})
			return
		}
		w.Header().Set("Access-Control-Allow-Origin", origin)
	}

	if code == "" || !verifierPattern.MatchString(verifier) {
		writeToken(w, http.StatusBadRequest, tokenResponse{Error: errorInvalidRequest})
		return
	}

	// The code is used up by this attempt whether or not it succeeds.
	doc, err := b.config.Store.consumeCode(ctx, code)
	if errors.Is(err, ErrNotFound) {
		b.refuseToken(ctx, w, Event{AppID: appID, Reason: reasonCodeUnknown})
		return
	}
	if err != nil {
		b.tokenServerError(w, "reading code", err)
		return
	}

	event := Event{AppID: appID, UID: doc.UID}
	switch {
	case b.config.Now().After(doc.ExpiresAt):
		event.Reason = reasonCodeExpired
	case doc.AppID != appID:
		event.Reason = reasonCodeWrongApp
	case doc.RedirectURI != redirectURI:
		event.Reason = reasonCodeWrongRedirect
	case !equalSecrets(challengeFor(verifier), doc.Challenge):
		event.Reason = reasonCodeWrongVerifier
	}
	if event.Reason != "" {
		b.refuseToken(ctx, w, event)
		return
	}

	client, ok := b.config.Auth[doc.ProjectID]
	if !ok {
		b.tokenServerError(w, "finding project", fmt.Errorf("no auth client for project %s", doc.ProjectID))
		return
	}

	// They may have been disabled since signing in.
	reason, err := accountProblem(ctx, client, doc.UID)
	if err != nil {
		b.tokenServerError(w, "checking account", err)
		return
	}
	if reason != "" {
		event.Reason = reason
		b.refuseToken(ctx, w, event)
		return
	}

	customToken, err := client.CustomToken(ctx, doc.UID)
	if err != nil {
		b.tokenServerError(w, "creating token", err)
		return
	}
	writeToken(w, http.StatusOK, tokenResponse{CustomToken: customToken})
}

func (b *Broker) tokenServerError(w http.ResponseWriter, doing string, err error) {
	slog.Error(doing, "error", err)
	writeToken(w, http.StatusInternalServerError, tokenResponse{Error: errorServerError})
}

func (b *Broker) refuseToken(ctx context.Context, w http.ResponseWriter, event Event) {
	event.Outcome = OutcomeRefused
	b.record(ctx, event)
	writeToken(w, http.StatusBadRequest, tokenResponse{Error: errorInvalidGrant})
}

func writeToken(w http.ResponseWriter, status int, response tokenResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		slog.Error("writing token response", "error", err)
	}
}

func originRegistered(app App, origin string) bool {
	for _, redirectURI := range app.RedirectURIs {
		u, err := url.Parse(redirectURI)
		if err == nil && u.Scheme+"://"+u.Host == origin {
			return true
		}
	}
	return false
}

var errConnectionUnavailable = errors.New("connection missing or disabled")

// connectorFor returns the connector for an enabled connection. It reads the connection every time,
// so that disabling one takes effect at once.
func (b *Broker) connectorFor(ctx context.Context, id string) (*connector.Connector, error) {
	connection, updated, err := b.config.Store.Connection(ctx, id)
	if errors.Is(err, ErrNotFound) {
		return nil, errConnectionUnavailable
	}
	if err != nil {
		return nil, err
	}
	if !connection.Enabled {
		return nil, errConnectionUnavailable
	}

	b.mu.Lock()
	cached, ok := b.connectors[id]
	b.mu.Unlock()
	if ok && cached.updated.Equal(updated) {
		return cached.connector, nil
	}

	secret, err := b.config.Secret(id)
	if err != nil {
		return nil, err
	}
	conn, err := connector.New(ctx, connector.Config{
		ID:           id,
		Kind:         connection.Kind,
		Issuer:       connection.Issuer,
		ClientID:     connection.ClientID,
		ClientSecret: secret,
		RedirectURL:  b.config.BaseURL + "/callback",
		Domains:      connection.Domains,
		TenantID:     connection.TenantID,
	})
	if err != nil {
		return nil, err
	}

	b.mu.Lock()
	b.connectors[id] = cachedConnector{updated: updated, connector: conn}
	b.mu.Unlock()
	return conn, nil
}

func (b *Broker) refuseConnection(w http.ResponseWriter, r *http.Request, err error, appID, connectionID, redirectURI, appState string) {
	event := Event{Outcome: OutcomeRefused, AppID: appID, ConnectionID: connectionID, Reason: reasonConnectionMissing}
	result := errorAccessDenied
	if !errors.Is(err, errConnectionUnavailable) {
		// Not necessarily the provider, but this person can only try again later either way.
		slog.Error("preparing connection", "connection", connectionID, "error", err)
		event.Reason = reasonProviderDown
		result = errorTemporarilyDown
	}
	b.record(r.Context(), event)
	redirectResult(w, r, redirectURI, url.Values{"error": {result}, "state": {appState}})
}

// record saves an event. A failure to save is logged, but doesn't change the sign-in's outcome.
func (b *Broker) record(ctx context.Context, event Event) {
	event.Time = b.config.Now()
	slog.Info("sign-in", "outcome", event.Outcome, "reason", event.Reason, "app", event.AppID, "connection", event.ConnectionID)
	if err := b.config.Store.addEvent(ctx, event); err != nil {
		slog.Error("saving sign-in event", "error", err)
	}
}

func (b *Broker) serverError(w http.ResponseWriter, doing string, err error) {
	slog.Error(doing, "error", err)
	renderProblem(w, http.StatusInternalServerError, "Something went wrong. Please try again.")
}

// redirectResult sends the browser to a registered redirect URI with params added.
func redirectResult(w http.ResponseWriter, r *http.Request, redirectURI string, params url.Values) {
	target, err := url.Parse(redirectURI)
	if err != nil {
		renderProblem(w, http.StatusInternalServerError, "Something went wrong. Please try again.")
		return
	}
	query := target.Query()
	for name, values := range params {
		query[name] = values
	}
	target.RawQuery = query.Encode()
	http.Redirect(w, r, target.String(), http.StatusFound)
}

func hash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func challengeFor(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func equalSecrets(a, b string) bool {
	return a != "" && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

var problemPage = template.Must(template.New("problem").Parse(`<!doctype html>
<html lang="en">
<meta charset="utf-8">
<title>Sign-in problem</title>
<body style="font-family: system-ui; max-width: 32rem; margin: 3rem auto">
<h1>Sign-in problem</h1>
<p>{{.}}</p>
</body>
</html>
`))

func renderProblem(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := problemPage.Execute(w, message); err != nil {
		slog.Error("rendering problem page", "error", err)
	}
}

var chooserPage = template.Must(template.New("chooser").Parse(`<!doctype html>
<html lang="en">
<meta charset="utf-8">
<title>Sign in to {{.App}}</title>
<body style="font-family: system-ui; max-width: 32rem; margin: 3rem auto">
<h1>Sign in to {{.App}}</h1>
<ul>
{{range .Choices}}<li><a href="{{.URL}}">{{.Name}}</a></li>
{{end}}</ul>
</body>
</html>
`))

type chooserChoice struct {
	Name string
	URL  string
}

func (b *Broker) renderChooser(w http.ResponseWriter, r *http.Request, app App) {
	connections, err := b.config.Store.Connections(r.Context())
	if err != nil {
		b.serverError(w, "listing connections", err)
		return
	}

	choices := []chooserChoice{}
	for _, connection := range connections {
		if !connection.Enabled {
			continue
		}
		query := r.URL.Query()
		query.Set("connection", connection.ID)
		choices = append(choices, chooserChoice{Name: connection.Name, URL: "/authorize?" + query.Encode()})
	}
	slices.SortFunc(choices, func(a, b chooserChoice) int { return strings.Compare(a.Name, b.Name) })

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	err = chooserPage.Execute(w, struct {
		App     string
		Choices []chooserChoice
	}{App: app.Name, Choices: choices})
	if err != nil {
		slog.Error("rendering chooser", "error", err)
	}
}
