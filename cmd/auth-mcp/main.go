// Command auth-mcp runs the server against a real Firebase project. It refuses to start in emulator mode,
// or against anything but a throwaway auth-mcp-test-... project. For the local stack, use cmd/dev.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"

	"github.com/teal-mongoose/auth-mcp/internal/live"
	"github.com/teal-mongoose/auth-mcp/internal/server"
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

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	cfg := live.FromEnv()
	srv, err := server.New(cfg.BindAddr, func() error { return live.Check(cfg) })
	if err != nil {
		return err
	}

	handler, closeHandler, err := live.NewHandler(ctx, cfg)
	if err != nil {
		return err
	}
	defer closeHandler()

	slog.Info("auth-mcp listening", "addr", srv.Addr(), "project", cfg.ProjectID)
	return srv.Serve(ctx, handler)
}
