// Package server runs the auth-mcp HTTP server.
package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/teal-mongoose/auth-mcp/internal/safety"
)

const shutdownTimeout = 5 * time.Second

// Server is a checked, listening server that isn't serving yet.
type Server struct {
	listener net.Listener
	http     *http.Server
}

// New runs the startup safety check, and starts listening only if it passes.
func New(cfg safety.Config) (*Server, error) {
	if err := safety.Check(cfg); err != nil {
		return nil, fmt.Errorf("refusing to start:\n%w", err)
	}

	listener, err := net.Listen("tcp", cfg.BindAddr)
	if err != nil {
		return nil, err
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	return &Server{
		listener: listener,
		http: &http.Server{
			Handler:           mux,
			ReadHeaderTimeout: 5 * time.Second,
		},
	}, nil
}

// Addr returns the address the server is listening on.
func (s *Server) Addr() string {
	return s.listener.Addr().String()
}

// Serve handles requests until ctx is cancelled, then shuts down.
func (s *Server) Serve(ctx context.Context) error {
	failed := make(chan error, 1)
	go func() {
		failed <- s.http.Serve(s.listener)
	}()

	select {
	case err := <-failed:
		return err
	case <-ctx.Done():
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := s.http.Shutdown(shutdownCtx); err != nil {
		return err
	}
	if err := <-failed; !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
