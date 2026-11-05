// Package admin is the MCP server that Healthspaces admins use to inspect the broker. Its tools are
// read-only.
//
// Every request needs a Firebase ID token from the broker's own project, from a sign-in through the
// broker within the last several hours, for someone in the Healthspaces org whose account has admin:
// true right now. Tokens from other projects are refused, so an admin in an app's project has no access
// here. The server only reads the token. It never passes it on.
package admin

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"time"

	firebaseauth "firebase.google.com/go/v4/auth"
	mcpauth "github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/teal-mongoose/auth-mcp/internal/broker"
)

const (
	adminScope      = "admin"
	maxRequestBytes = 64 << 10
	// defaultMaxSessionAge limits how long ago an admin can have signed in. Refresh tokens don't expire,
	// so without this, a session could outlast someone's access at their provider, or a stolen token
	// could work indefinitely.
	defaultMaxSessionAge = 12 * time.Hour
	// brokerSignInProvider is how Firebase records a sign-in through a custom token, as the broker issues.
	brokerSignInProvider = "custom"
)

// Config is what the admin server needs.
type Config struct {
	Store *broker.Store
	// Auth has an Admin SDK client per Firebase project, keyed by project id.
	Auth map[string]*firebaseauth.Client
	// AdminProject is the Firebase project whose tokens are accepted.
	AdminProject string
	// AdminOrg is the org admins must belong to.
	AdminOrg string
	// AllowedOrigins are the only web origins that may call the server from a browser.
	AllowedOrigins []string
	// Logger defaults to slog.Default.
	Logger *slog.Logger
	// MaxSessionAge defaults to defaultMaxSessionAge.
	MaxSessionAge time.Duration
	// Now defaults to time.Now.
	Now func() time.Time
}

// Server is the admin MCP server.
type Server struct {
	config Config
	mcp    *mcp.Server
}

// New returns a Server.
func New(cfg Config) *Server {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.MaxSessionAge == 0 {
		cfg.MaxSessionAge = defaultMaxSessionAge
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	s := &Server{
		config: cfg,
		mcp:    mcp.NewServer(&mcp.Implementation{Name: "auth-mcp", Version: "0.1.0"}, nil),
	}
	s.addTools()
	return s
}

// Handler returns the HTTP handler for the MCP endpoint.
func (s *Server) Handler() http.Handler {
	streamable := mcp.NewStreamableHTTPHandler(
		func(*http.Request) *mcp.Server { return s.mcp },
		&mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true, MaxRequestBodyBytes: maxRequestBytes},
	)
	authenticated := mcpauth.RequireBearerToken(s.verify, &mcpauth.RequireBearerTokenOptions{Scopes: []string{adminScope}})(streamable)
	return s.originCheck(authenticated)
}

// originCheck turns away web pages that aren't on the allowlist, before anything else happens. Requests
// with no Origin don't come from a web page, and are left to the token check.
func (s *Server) originCheck(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w = &noStoreWriter{ResponseWriter: w}
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Add("Vary", "Origin")

		origin := r.Header.Get("Origin")
		if origin != "" {
			if !slices.Contains(s.config.AllowedOrigins, origin) {
				http.Error(w, "origin not allowed", http.StatusForbidden)
				return
			}
			h.Set("Access-Control-Allow-Origin", origin)
		}

		if r.Method == http.MethodOptions {
			h.Set("Access-Control-Allow-Methods", "POST")
			h.Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Accept, Mcp-Protocol-Version")
			h.Set("Access-Control-Max-Age", "600")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// noStoreWriter forbids caching tool output, which holds people's details. The SDK sets its own
// Cache-Control, which allows storing, so this has to be applied just as the headers go out.
type noStoreWriter struct {
	http.ResponseWriter
	wroteHeader bool
}

func (w *noStoreWriter) WriteHeader(status int) {
	if !w.wroteHeader {
		w.Header().Set("Cache-Control", "no-store")
		w.wroteHeader = true
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *noStoreWriter) Write(data []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(data)
}

// Unwrap lets http.ResponseController reach the underlying writer.
func (w *noStoreWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// verify checks a token. Its errors reach the client as they are, so they say nothing about why. A
// valid token from someone who isn't an admin gets no scope, which the middleware answers with a 403.
func (s *Server) verify(ctx context.Context, token string, _ *http.Request) (*mcpauth.TokenInfo, error) {
	client, ok := s.config.Auth[s.config.AdminProject]
	if !ok {
		s.config.Logger.Error("no auth client for the admin project", "project", s.config.AdminProject)
		return nil, errors.New("could not check the token")
	}

	verified, err := client.VerifyIDTokenAndCheckRevoked(ctx, token)
	if err != nil {
		// IsIDTokenInvalid also covers expired and revoked tokens, and disabled accounts.
		if firebaseauth.IsIDTokenInvalid(err) || firebaseauth.IsUserNotFound(err) {
			s.config.Logger.Info("admin access refused", "reason", "invalid token")
			return nil, mcpauth.ErrInvalidToken
		}
		s.config.Logger.Error("checking token", "error", err)
		return nil, errors.New("could not check the token")
	}

	if s.config.Now().Sub(time.Unix(verified.AuthTime, 0)) > s.config.MaxSessionAge {
		s.config.Logger.Info("admin access refused", "caller", verified.UID, "reason", "session too old")
		return nil, mcpauth.ErrInvalidToken
	}

	info := &mcpauth.TokenInfo{UserID: verified.UID, Expiration: time.Unix(verified.Expires, 0)}
	allowed, err := s.isAdmin(ctx, client, verified)
	if err != nil {
		s.config.Logger.Error("checking account", "error", err)
		return nil, errors.New("could not check the token")
	}
	if allowed {
		info.Scopes = []string{adminScope}
	} else {
		s.config.Logger.Info("admin access refused", "caller", verified.UID, "reason", "not an admin")
	}
	return info, nil
}

// isAdmin applies the rules beyond the token being valid.
//
// The org only comes from a sign-in through the broker, so the sign-in must have been one. Otherwise,
// someone could sign in to the project directly, skipping the broker's checks and any provider MFA.
// The admin claim is read from the live account, so that removing it takes effect at once, rather than
// when the token expires.
func (s *Server) isAdmin(ctx context.Context, client *firebaseauth.Client, token *firebaseauth.Token) (bool, error) {
	if s.config.AdminOrg == "" || token.Claims["org"] != s.config.AdminOrg {
		return false, nil
	}
	if token.Firebase.SignInProvider != brokerSignInProvider || token.Firebase.Tenant != "" {
		return false, nil
	}
	user, err := client.GetUser(ctx, token.UID)
	if err != nil {
		return false, err
	}
	return user.CustomClaims["admin"] == true, nil
}
