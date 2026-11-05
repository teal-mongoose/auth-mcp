// Command auth-setup prepares a throwaway auth-mcp-test-... project for testing with real Google sign-in.
//
//	auth-setup save                  Saves the staff org, the Google connection and the test apps
//	auth-setup grant-admin <email>   Gives an existing account admin: true in this project
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/teal-mongoose/auth-mcp/internal/broker"
	"github.com/teal-mongoose/auth-mcp/internal/live"
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

	ctx := context.Background()
	cfg := live.FromEnv()
	authClient, fs, closeClients, err := live.Clients(ctx, cfg)
	if err != nil {
		return err
	}
	defer closeClients()

	switch flag.Arg(0) {
	case "save":
		setup, err := live.SetupFromEnv()
		if err != nil {
			return err
		}
		if err := setup.Save(ctx, cfg, broker.NewStore(fs)); err != nil {
			return err
		}
		fmt.Printf("Saved the org, connection and test apps to %s.\n", cfg.ProjectID)
		return nil

	case "grant-admin":
		email := flag.Arg(1)
		if email == "" {
			return errors.New("usage: auth-setup grant-admin <email>")
		}
		user, err := authClient.GetUserByEmail(ctx, email)
		if err != nil {
			return fmt.Errorf("finding %s: %w", email, err)
		}
		// Setting claims replaces them all, so keep what's there.
		claims := map[string]any{}
		for name, value := range user.CustomClaims {
			claims[name] = value
		}
		claims["admin"] = true
		if err := authClient.SetCustomUserClaims(ctx, user.UID, claims); err != nil {
			return err
		}
		fmt.Printf("%s (%s) is now an admin in %s. Sign in again for it to apply.\n", email, user.UID, cfg.ProjectID)
		return nil

	default:
		return errors.New("usage: auth-setup save | grant-admin <email>")
	}
}
