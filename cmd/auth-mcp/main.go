// Command auth-mcp runs the server on its own. It refuses to start unless the emulator variables
// are set and safe, so use cmd/dev for the whole local stack.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"

	"github.com/teal-mongoose/auth-mcp/internal/devenv"
	"github.com/teal-mongoose/auth-mcp/internal/server"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	srv, err := server.New(devenv.SafetyConfig())
	if err != nil {
		return err
	}

	handler, closeHandler, err := devenv.NewHandler(ctx, devenv.BaseURL)
	if err != nil {
		return err
	}
	defer closeHandler()

	slog.Info("auth-mcp listening", "addr", srv.Addr())
	return srv.Serve(ctx, handler)
}
