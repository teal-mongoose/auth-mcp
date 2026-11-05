// Package seed loads the generic test accounts into the Auth emulators.
package seed

import (
	"context"
	"errors"
	"fmt"

	"firebase.google.com/go/v4/auth"

	"github.com/teal-mongoose/auth-mcp/internal/fixtures"
	"github.com/teal-mongoose/auth-mcp/internal/safety"
)

// Run checks that everything it would touch is an emulator, then replaces the seed accounts. The
// emulator won't import over an existing uid, so they're deleted first, which also makes this safe
// to run repeatedly.
func Run(ctx context.Context, cfg safety.Config, clients map[string]*auth.Client) error {
	if err := safety.Check(cfg); err != nil {
		return fmt.Errorf("refusing to seed:\n%w", err)
	}

	for project, accounts := range fixtures.Accounts() {
		client, ok := clients[project]
		if !ok {
			return fmt.Errorf("no auth client for %s", project)
		}

		users := make([]*auth.UserToImport, 0, len(accounts))
		uids := make([]string, 0, len(accounts))
		for _, account := range accounts {
			users = append(users, toImport(account))
			uids = append(uids, account.UID)
		}

		if _, err := client.DeleteUsers(ctx, uids); err != nil {
			return fmt.Errorf("clearing %s: %w", project, err)
		}

		result, err := client.ImportUsers(ctx, users)
		if err != nil {
			return fmt.Errorf("seeding %s: %w", project, err)
		}
		if result.FailureCount > 0 {
			errs := make([]error, 0, len(result.Errors))
			for _, failure := range result.Errors {
				errs = append(errs, fmt.Errorf("%s: %s", accounts[failure.Index].Email, failure.Reason))
			}
			return fmt.Errorf("seeding %s: %w", project, errors.Join(errs...))
		}
	}
	return nil
}

func toImport(account fixtures.Account) *auth.UserToImport {
	user := (&auth.UserToImport{}).
		UID(account.UID).
		Email(account.Email).
		EmailVerified(true).
		DisplayName(account.Name).
		Disabled(account.Disabled)

	if account.Claims != nil {
		user = user.CustomClaims(account.Claims)
	}
	if account.ProviderID != "" {
		user = user.ProviderData([]*auth.UserProvider{{
			ProviderID:  account.ProviderID,
			UID:         account.ProviderUID,
			Email:       account.Email,
			DisplayName: account.Name,
		}})
	}
	return user
}
