// Package admin is the MCP server that Healthspaces admins use to inspect the broker. Its tools are
// read-only.
//
// Every request needs a Firebase ID token from the broker's own project, for someone with admin: true
// and the Healthspaces org. Tokens from other projects are refused, so an admin in an app's project
// has no access here. The server only reads the token. It never passes it on.
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
			return nil, mcpauth.ErrInvalidToken
		}
		s.config.Logger.Error("checking token", "error", err)
		return nil, errors.New("could not check the token")
	}

	info := &mcpauth.TokenInfo{UserID: verified.UID, Expiration: time.Unix(verified.Expires, 0)}
	if verified.Claims["admin"] == true && verified.Claims["org"] == s.config.AdminOrg {
		info.Scopes = []string{adminScope}
	}
	return info, nil
}
