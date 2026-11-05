// Package server runs the auth-mcp HTTP server.
package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"
)

const shutdownTimeout = 5 * time.Second

// Server is a checked, listening server that isn't serving yet.
type Server struct {
	listener net.Listener
}

// New runs the startup check, and starts listening only if it passes.
func New(bindAddr string, check func() error) (*Server, error) {
	if err := check(); err != nil {
		return nil, fmt.Errorf("refusing to start:\n%w", err)
	}

	listener, err := net.Listen("tcp", bindAddr)
	if err != nil {
		return nil, err
	}

	return &Server{listener: listener}, nil
}

// Addr returns the address the server is listening on.
func (s *Server) Addr() string {
	return s.listener.Addr().String()
}

// Serve answers health checks, and passes everything else to handler, until ctx is cancelled. Then
// it shuts down.
func (s *Server) Serve(ctx context.Context, handler http.Handler) error {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	mux.Handle("/", handler)

	httpServer := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	failed := make(chan error, 1)
	go func() {
		failed <- httpServer.Serve(s.listener)
	}()

	select {
	case err := <-failed:
		return err
	case <-ctx.Done():
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		return err
	}
	if err := <-failed; !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
