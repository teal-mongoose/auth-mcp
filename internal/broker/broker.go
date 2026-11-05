// Package broker is the sign-in flow apps use.
//
// An app sends someone to GET /authorize. If they aren't sent to a specific connection, the sign-in page
// asks for their email and POST /authorize routes them by its domain. They sign in at a provider, and
// come back to GET /callback.
// If the broker knows them, the app gets a single-use code at its registered redirect URI, and
// exchanges it at POST /token for a Firebase custom token in its own project. From there, Firebase
// sessions, claims and security rules work as usual. The token carries an org claim, which comes from
// the connection, never from anything the provider sends.
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
	// baseCSP allows no scripts and no framing.
	baseCSP = "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'"
	// noFormsCSP is for every page without a form. The sign-in page leaves form-action out, because
	// browsers apply it to redirects too, and its form redirects to the person's provider.
	noFormsCSP = baseCSP + "; form-action 'none'"
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
	reasonWrongCallback     = "callback_for_another_connection"
	reasonRedirectRemoved   = "redirect_no_longer_registered"
	reasonUnknownDomain     = "unknown_domain"
	reasonAmbiguousDomain   = "ambiguous_domain"
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
	notAnEmailMessage        = "Enter your full work email address."
	noSignInMessage          = "We can't find a sign-in for that address. Check it, or ask your administrator."
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
	// AllowLocalProviders accepts mock providers on this machine. See connector.Config.AllowLocal.
	AllowLocalProviders bool
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
	connectionUpdated time.Time
	orgUpdated        time.Time
	connector         *connector.Connector
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
	mux.HandleFunc("POST /authorize", b.route)
	mux.HandleFunc("GET /callback/{connection}", b.callback)
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
		h.Set("Content-Security-Policy", noFormsCSP)
		next.ServeHTTP(w, r)
	})
}

// authRequest is a checked request from an app to start a sign-in.
type authRequest struct {
	app         App
	redirectURI string
	state       string
	challenge   string
}

// values returns the request's parameters, for carrying them through the sign-in page.
func (req authRequest) values() url.Values {
	return url.Values{
		"app_id":                {req.app.ID},
		"redirect_uri":          {req.redirectURI},
		"state":                 {req.state},
		"code_challenge":        {req.challenge},
		"code_challenge_method": {"S256"},
	}
}

// parseAuthRequest checks a request to start a sign-in. If it returns false, it has already responded.
func (b *Broker) parseAuthRequest(w http.ResponseWriter, r *http.Request, values url.Values) (authRequest, bool) {
	redirectURI := values.Get("redirect_uri")

	// Until the redirect URI is known to be registered, problems must never redirect anywhere.
	app, err := b.config.Store.App(r.Context(), values.Get("app_id"))
	if errors.Is(err, ErrNotFound) {
		renderProblem(w, http.StatusBadRequest, unknownAppProblemMessage)
		return authRequest{}, false
	}
	if err != nil {
		b.serverError(w, "reading app", err)
		return authRequest{}, false
	}
	if !slices.Contains(app.RedirectURIs, redirectURI) {
		renderProblem(w, http.StatusBadRequest, unknownAppProblemMessage)
		return authRequest{}, false
	}

	state := values.Get("state")
	challenge := values.Get("code_challenge")
	if state == "" || len(state) > maxAppStateSize ||
		values.Get("code_challenge_method") != "S256" || !challengePattern.MatchString(challenge) {
		redirectResult(w, r, redirectURI, url.Values{"error": {errorInvalidRequest}, "state": {state}})
		return authRequest{}, false
	}

	return authRequest{app: app, redirectURI: redirectURI, state: state, challenge: challenge}, true
}

func (b *Broker) authorize(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	req, ok := b.parseAuthRequest(w, r, query)
	if !ok {
		return
	}

	if connectionID := query.Get("connection"); connectionID != "" {
		b.startSignIn(w, r, req, connectionID)
		return
	}
	b.renderSignInPage(w, r, req, "")
}

// route sends someone to their org's connection, going by the domain of the email they typed. It's a
// POST so that the address stays out of URLs and logs. The address is unverified, so it only decides
// where to send them. The provider decides who they are.
func (b *Broker) route(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	r.Body = http.MaxBytesReader(w, r.Body, maxTokenBody)
	if err := r.ParseForm(); err != nil {
		renderProblem(w, http.StatusBadRequest, unknownAppProblemMessage)
		return
	}
	req, ok := b.parseAuthRequest(w, r, r.PostForm)
	if !ok {
		return
	}

	domain, ok := connector.EmailDomain(strings.TrimSpace(r.PostForm.Get("email")))
	if !ok {
		b.renderSignInPage(w, r, req, notAnEmailMessage)
		return
	}

	orgs, err := b.config.Store.OrgsForDomain(ctx, domain)
	if err != nil {
		b.serverError(w, "finding org", err)
		return
	}
	switch len(orgs) {
	case 0:
		b.record(ctx, Event{Outcome: OutcomeRefused, Reason: reasonUnknownDomain, AppID: req.app.ID})
		b.renderSignInPage(w, r, req, noSignInMessage)
		return
	case 1:
	default:
		// Picking one could send someone to another customer's provider.
		slog.Error("several orgs claim one domain", "domain", domain)
		b.record(ctx, Event{Outcome: OutcomeRefused, Reason: reasonAmbiguousDomain, AppID: req.app.ID})
		b.renderSignInPage(w, r, req, noSignInMessage)
		return
	}
	org := orgs[0]

	connections, err := b.config.Store.ConnectionsForOrg(ctx, org.ID)
	if err != nil {
		b.serverError(w, "listing connections", err)
		return
	}
	connections = slices.DeleteFunc(connections, func(c Connection) bool { return !c.Enabled })

	switch len(connections) {
	case 0:
		b.record(ctx, Event{Outcome: OutcomeRefused, Reason: reasonConnectionMissing, AppID: req.app.ID, OrgID: org.ID})
		b.renderSignInPage(w, r, req, noSignInMessage)
	case 1:
		b.startSignIn(w, r, req, connections[0].ID)
	default:
		renderSignInChoices(w, req, connections, "", false)
	}
}

// startSignIn sends the browser to a connection's provider.
func (b *Broker) startSignIn(w http.ResponseWriter, r *http.Request, req authRequest, connectionID string) {
	// Anyone can send anything here, so an invalid id goes no further, not even into the event.
	if !ValidID(connectionID) {
		connectionID = ""
	}
	conn, _, err := b.connectorFor(r.Context(), connectionID)
	if err != nil {
		b.refuseConnection(w, r, err, req.app.ID, connectionID, req.redirectURI, req.state)
		return
	}

	authURL, pending := conn.Begin()
	binding := rand.Text()
	err = b.config.Store.putPending(r.Context(), pending.State, pendingSignIn{
		AppID:        req.app.ID,
		ConnectionID: connectionID,
		RedirectURI:  req.redirectURI,
		AppState:     req.state,
		Challenge:    req.challenge,
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

	// Each connection has its own callback URL, registered at its own provider. A sign-in started at one
	// connection coming back through another's URL is an identity provider mix-up: a malicious connection
	// sent someone on to an honest provider. Going on would post the honest provider's code to the
	// malicious connection's token endpoint.
	if pending.ConnectionID != r.PathValue("connection") {
		base.Reason = reasonWrongCallback
		b.record(ctx, base)
		renderProblem(w, http.StatusBadRequest, browserProblemMessage)
		return
	}

	cookie, err := r.Cookie(bindingPrefix + hash(state)[:16])
	if err != nil || !equalSecrets(hash(cookie.Value), pending.BindingHash) {
		base.Reason = reasonBrowserMismatch
		b.record(ctx, base)
		renderProblem(w, http.StatusBadRequest, browserProblemMessage)
		return
	}

	app, err := b.config.Store.App(ctx, pending.AppID)
	if err != nil {
		b.serverError(w, "reading app", err)
		return
	}
	// The address may have been removed, perhaps because it was compromised, since this sign-in began.
	if !slices.Contains(app.RedirectURIs, pending.RedirectURI) {
		base.Reason = reasonRedirectRemoved
		b.record(ctx, base)
		renderProblem(w, http.StatusBadRequest, unknownAppProblemMessage)
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

	conn, connection, err := b.connectorFor(ctx, pending.ConnectionID)
	if err != nil {
		b.refuseConnection(w, r, err, pending.AppID, pending.ConnectionID, pending.RedirectURI, pending.AppState)
		return
	}
	base.OrgID = connection.OrgID

	identity, err := conn.Complete(ctx, connector.Pending{
		State:    state,
		Nonce:    pending.Nonce,
		Verifier: pending.Verifier,
	}, connector.Callback{
		State:  query.Get("state"),
		Code:   query.Get("code"),
		Error:  query.Get("error"),
		Issuer: query.Get("iss"),
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
		OrgID:       connection.OrgID,
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

	event := Event{AppID: appID, UID: doc.UID, OrgID: doc.OrgID}
	switch {
	case b.config.Now().After(doc.ExpiresAt):
		event.Reason = reasonCodeExpired
	case doc.AppID != appID:
		event.Reason = reasonCodeWrongApp
	case doc.RedirectURI != redirectURI:
		event.Reason = reasonCodeWrongRedirect
	case !slices.Contains(app.RedirectURIs, doc.RedirectURI):
		event.Reason = reasonRedirectRemoved
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

	customToken, err := client.CustomTokenWithClaims(ctx, doc.UID, map[string]any{"org": doc.OrgID})
	if err != nil {
		b.tokenServerError(w, "creating token", err)
		return
	}
	event.Outcome = OutcomeTokenIssued
	b.record(ctx, event)
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

// connectorFor returns the connector for an enabled connection, and the connection. It reads the
// connection and its org every time, so that disabling one or changing a domain applies to the next
// step of any sign-in. A code that's already been issued still works for its short life.
func (b *Broker) connectorFor(ctx context.Context, id string) (*connector.Connector, Connection, error) {
	connection, connectionUpdated, err := b.config.Store.Connection(ctx, id)
	if errors.Is(err, ErrNotFound) {
		return nil, Connection{}, errConnectionUnavailable
	}
	if err != nil {
		return nil, Connection{}, err
	}
	if !connection.Enabled {
		return nil, Connection{}, errConnectionUnavailable
	}

	org, orgUpdated, err := b.config.Store.Org(ctx, connection.OrgID)
	if errors.Is(err, ErrNotFound) {
		return nil, Connection{}, errConnectionUnavailable
	}
	if err != nil {
		return nil, Connection{}, err
	}

	b.mu.Lock()
	cached, ok := b.connectors[id]
	b.mu.Unlock()
	if ok && cached.connectionUpdated.Equal(connectionUpdated) && cached.orgUpdated.Equal(orgUpdated) {
		return cached.connector, connection, nil
	}

	secret, err := b.config.Secret(id)
	if err != nil {
		return nil, Connection{}, err
	}
	conn, err := connector.New(ctx, connector.Config{
		ID:           id,
		Kind:         connection.Kind,
		Issuer:       connection.Issuer,
		ClientID:     connection.ClientID,
		ClientSecret: secret,
		RedirectURL:  b.config.BaseURL + "/callback/" + id,
		Domains:      org.Domains,
		TenantID:     connection.TenantID,
		AllowLocal:   b.config.AllowLocalProviders,
	})
	if err != nil {
		return nil, Connection{}, err
	}

	b.mu.Lock()
	b.connectors[id] = cachedConnector{connectionUpdated: connectionUpdated, orgUpdated: orgUpdated, connector: conn}
	b.mu.Unlock()
	return conn, connection, nil
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

// record saves an event. A failure to save is logged, but doesn't change the sign-in's outcome. It
// outlasts the request, so that a client hanging up can't keep its attempt off the record.
func (b *Broker) record(ctx context.Context, event Event) {
	ctx = context.WithoutCancel(ctx)
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

var signInPage = template.Must(template.New("signin").Parse(`<!doctype html>
<html lang="en">
<meta charset="utf-8">
<title>Sign in to {{.App}}</title>
<body style="font-family: system-ui; max-width: 32rem; margin: 3rem auto">
<h1>Sign in to {{.App}}</h1>
{{if .Message}}<p role="alert">{{.Message}}</p>
{{end}}{{if .ShowEmail}}<form method="post" action="/authorize">
{{range .Hidden}}<input type="hidden" name="{{.Name}}" value="{{.Value}}">
{{end}}<label>Work email <input type="email" name="email" autocomplete="email" required autofocus></label>
<button type="submit">Continue</button>
</form>
{{end}}{{if .Choices}}<ul>
{{range .Choices}}<li><a href="{{.URL}}">{{.Name}}</a></li>
{{end}}</ul>
{{end}}</body>
</html>
`))

type signInChoice struct {
	Name string
	URL  string
}

type hiddenField struct {
	Name  string
	Value string
}

// renderSignInPage asks for an email, and lists the connections marked to show there, such as staff's.
func (b *Broker) renderSignInPage(w http.ResponseWriter, r *http.Request, req authRequest, message string) {
	connections, err := b.config.Store.Connections(r.Context())
	if err != nil {
		b.serverError(w, "listing connections", err)
		return
	}
	connections = slices.DeleteFunc(connections, func(c Connection) bool { return !c.Enabled || !c.ShowOnSignInPage })
	renderSignInChoices(w, req, connections, message, true)
}

func renderSignInChoices(w http.ResponseWriter, req authRequest, connections []Connection, message string, showEmail bool) {
	values := req.values()

	hidden := make([]hiddenField, 0, len(values))
	for name := range values {
		hidden = append(hidden, hiddenField{Name: name, Value: values.Get(name)})
	}
	slices.SortFunc(hidden, func(a, b hiddenField) int { return strings.Compare(a.Name, b.Name) })

	choices := make([]signInChoice, 0, len(connections))
	for _, connection := range connections {
		query := req.values()
		query.Set("connection", connection.ID)
		choices = append(choices, signInChoice{Name: connection.Name, URL: "/authorize?" + query.Encode()})
	}
	slices.SortFunc(choices, func(a, b signInChoice) int { return strings.Compare(a.Name, b.Name) })

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", baseCSP)
	err := signInPage.Execute(w, struct {
		App       string
		Message   string
		ShowEmail bool
		Hidden    []hiddenField
		Choices   []signInChoice
	}{App: req.app.Name, Message: message, ShowEmail: showEmail, Hidden: hidden, Choices: choices})
	if err != nil {
		slog.Error("rendering sign-in page", "error", err)
	}
}
