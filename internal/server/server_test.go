package server

import (
	"context"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/teal-mongoose/auth-mcp/internal/safety"
)

func config(bindAddr string) safety.Config {
	return safety.Config{
		AuthEmulatorHost:      "127.0.0.1:9399",
		FirestoreEmulatorHost: "127.0.0.1:8280",
		BindAddr:              bindAddr,
		Projects:              []safety.Project{{ID: "demo-auth-mcp", AuthEmulatorHost: "127.0.0.1:9399"}},
	}
}

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

	cfg := config(addr)
	cfg.Projects = []safety.Project{{ID: "hvisit-staging", AuthEmulatorHost: "127.0.0.1:9399"}}

	srv, err := New(cfg)
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
	srv, err := New(config("127.0.0.1:0"))
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
