# Working in this repository

The central sign-in broker for HealthSpaces apps, written in Go. Read `README.md` for how to run it,
and `../mcp-auth-plan.md` for the plan and its decisions.

- **No real Firebase projects except a throwaway `auth-mcp-test-...` one and `auth-mcp-staging`.** This PC's
  default credentials can reach real projects, so never loosen the project check in `internal/live` beyond
  naming a project exactly. No service account keys. Deploys go only to staging, through `deploy/`, with the
  owner's go-ahead (see `STAGING.md`). Don't read `.env.live`, and don't enter passwords: the owner does Google sign-ins. Moving past
  this is Steps A-C in the plan, and each needs the owner's go-ahead.
- **Don't change `@teal-mongoose/core` from this work.** It stays as it is until this server is ready
  to deploy.
- **Security checks are never loosened to make something pass.** That covers `internal/safety`, and
  the sign-in checks as they arrive. Keep `SkipIssuerCheck` off, and never use email to identify
  anyone.
- **New provider kinds must pin their issuer**, and each connection keeps its own callback URL. Those two
  rules are what stop one connection impersonating or stealing from another. See `SECURITY-REVIEW.md`.
- **Keep test code out of the server.** Mock providers and accounts belong in `internal/fixtures` and
  `internal/mockidp`, which `cmd/auth-mcp` must not import.
- **This PC's App Control policy is IT's.** If it blocks a Go build, report it and don't work around it.
- Other projects' emulators may be running. Don't stop a process you didn't start.

Before calling a change done, with `go run ./cmd/dev` running:

```sh
gofmt -l . && go vet -tags=emulator ./... && golangci-lint run --build-tags=emulator ./... && go test -tags=emulator -count=1 -p 1 ./...
```
