package server

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"testing"
)

func TestNewRefusesAndDoesNotListen(t *testing.T) {
	// Pick a free port, so a listener appearing on it can only come from New.
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := probe.Addr().String()
	if err := probe.Close(); err != nil {
		t.Fatal(err)
	}

	srv, err := New(addr, func() error { return errors.New("hvisit-staging isn't allowed") })
	if err == nil {
		t.Fatalf("New() started on %s, want a refusal", srv.Addr())
	}
	if !strings.Contains(err.Error(), "refusing to start") || !strings.Contains(err.Error(), "hvisit-staging") {
		t.Fatalf("New() error = %q, want a refusal naming the project", err)
	}

	if conn, err := net.Dial("tcp", addr); err == nil {
		_ = conn.Close()
		t.Fatalf("something is listening on %s after a refusal", addr)
	}
}

func TestServeAnswersHealthCheckThenShutsDown(t *testing.T) {
	srv, err := New("127.0.0.1:0", func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- srv.Serve(ctx, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusTeapot)
		}))
	}()

	res, err := http.Get("http://" + srv.Addr() + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	if err := res.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusNoContent {
		t.Fatalf("GET /healthz = %d, want %d", res.StatusCode, http.StatusNoContent)
	}

	passed, err := http.Get("http://" + srv.Addr() + "/anything-else")
	if err != nil {
		t.Fatal(err)
	}
	if err := passed.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if passed.StatusCode != http.StatusTeapot {
		t.Fatalf("GET /anything-else = %d, want it passed to the handler", passed.StatusCode)
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Serve() = %v, want nil after shutdown", err)
	}
}
