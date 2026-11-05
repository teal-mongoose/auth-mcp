// Command testpages serves the test app and admin screen against a real Firebase project, to go with
// cmd/auth-mcp. These pages are test tools, and aren't part of the server.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"time"

	"github.com/teal-mongoose/auth-mcp/internal/adminscreen"
	"github.com/teal-mongoose/auth-mcp/internal/live"
	"github.com/teal-mongoose/auth-mcp/internal/testapp"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	envFile := flag.String("env-file", ".env.live", "file of settings and secrets")
	flag.Parse()
	if err := live.LoadEnvFile(*envFile); err != nil {
		return err
	}

	cfg := live.FromEnv()
	if err := live.Check(cfg); err != nil {
		return fmt.Errorf("refusing to start:\n%w", err)
	}
	apiKey := os.Getenv("AUTH_MCP_FIREBASE_API_KEY")
	authDomain := os.Getenv("AUTH_MCP_FIREBASE_AUTH_DOMAIN")
	if apiKey == "" || authDomain == "" {
		return errors.New("AUTH_MCP_FIREBASE_API_KEY and AUTH_MCP_FIREBASE_AUTH_DOMAIN must be set")
	}

	testApp := testapp.Handler(testapp.Config{
		AppID:              live.AppTest,
		Name:               "Test App",
		ProjectID:          cfg.ProjectID,
		APIKey:             apiKey,
		AuthDomain:         authDomain,
		BrokerURL:          cfg.BaseURL,
		RedirectURI:        live.TestAppOrigin + "/",
		DirectGoogleSignIn: true,
	})
	adminScreen := adminscreen.Handler(adminscreen.Config{
		AppID:       live.AppAdmin,
		Name:        "Test Admin",
		ProjectID:   cfg.ProjectID,
		APIKey:      apiKey,
		BrokerURL:   cfg.BaseURL,
		RedirectURI: live.AdminOrigin + "/",
	})

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	failed := make(chan error, 2)
	for origin, handler := range map[string]http.Handler{live.TestAppOrigin: testApp, live.AdminOrigin: adminScreen} {
		u, err := url.Parse(origin)
		if err != nil {
			return err
		}
		listener, err := net.Listen("tcp", "127.0.0.1:"+u.Port())
		if err != nil {
			return err
		}
		pages := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second}
		defer func() { _ = pages.Close() }()
		go func() { failed <- pages.Serve(listener) }()
		fmt.Println("Serving", origin)
	}

	select {
	case <-ctx.Done():
		return nil
	case err := <-failed:
		return err
	}
}
