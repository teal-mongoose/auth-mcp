# auth-mcp

The go-between for sign-in. Apps send people here to sign in with Google, Microsoft, Okta or a future
provider, and get back an ordinary Firebase login. Healthspaces admins manage it through MCP tools.

**Status: phase 2 of 7.** The local foundation and provider adapters exist, but nothing uses the
adapters yet: there are no sign-in endpoints or MCP tools. The full plan is in
[`../mcp-auth-plan.md`](../mcp-auth-plan.md).

Everything runs on this machine, with emulators, mock providers and generic test accounts. It can't
reach a real Firebase project.

## Run it

You need Go 1.27 or newer, Java (for the Firestore emulator) and the Firebase CLI.

```bash
go run ./cmd/dev
```

That starts everything below from the repo root, and Ctrl+C stops it all.

| What | Address |
| --- | --- |
| Server | `127.0.0.1:8701` |
| Auth emulator, `demo-auth-mcp` (broker) | `127.0.0.1:9399` |
| Auth emulator, `demo-test-app-a` | `127.0.0.1:9398` |
| Auth emulator, `demo-test-app-b` | `127.0.0.1:9397` |
| Firestore emulator, broker only | `127.0.0.1:8280` |
| Emulator UI, broker only | `127.0.0.1:4002` |
| Mock Google | `127.0.0.1:9401/oidc` |
| Mock Okta, customer A | `127.0.0.1:9402/oidc` |
| Mock Okta, customer B | `127.0.0.1:9403/oidc` |
| Mock Microsoft, customer C | `127.0.0.1:9404/oidc` |
| Mock Microsoft, other tenant | `127.0.0.1:9405/oidc` |

Emulators also use hub ports 4402-4404, logging ports 4502-4504 and websocket port 9152. These are
chosen so they don't clash with `core`, `video` or `telehealth-demo`.

Opening a mock provider's authorize URL without a chosen user shows a page for picking who to sign in
as. The accounts are in [`internal/fixtures/fixtures.go`](internal/fixtures/fixtures.go).

## Check it

```bash
gofmt -l .
```

```bash
go vet -tags=emulator ./...
```

```bash
golangci-lint run --build-tags=emulator ./...
```

```bash
go test ./...
```

With `go run ./cmd/dev` running, this also tests against the emulators:

```bash
go test -tags=emulator -count=1 ./...
```

## Things worth knowing

- **Adding a provider.** [`internal/connector`](internal/connector/connector.go) runs the OIDC flow and
  token checks. A provider adds a small adapter, like
  [`okta.go`](internal/connector/okta.go), saying which claims identify someone and what to refuse.
- **Callers of `connector.Complete` must keep `Pending` private, use it once and expire it.** That's
  what makes `state` single-use.
- **One emulator per project.** A single Auth emulator sends every API-key sign-in, which is how
  browsers sign in, to its default project. So each project has its own emulator, and
  `devenv.AuthClient` points each Admin SDK client at the right one.
- **The server refuses to start outside this setup.** With `FIREBASE_AUTH_EMULATOR_HOST` set, the
  Admin SDK skips ID token signature checks, so anyone able to reach the server could forge an admin
  token. See [`internal/safety/safety.go`](internal/safety/safety.go). A production build must do the
  reverse, and refuse to start with that variable set.
- **Test code stays out of the server.** `TestServerDoesNotLinkTestCode` fails if `cmd/auth-mcp` ever
  depends on the fixtures or mock providers.
- **Mocks prove the logic, not the providers.** They only behave as they're built here, and the
  emulator doesn't check custom token signatures or expiry. Step A of the plan covers both.

## Pinned versions

| Library | Version | Used from |
| --- | --- | --- |
| `firebase.google.com/go/v4` | v4.22.0 | Phase 1 |
| `cloud.google.com/go/firestore` | v1.29.2 | Phase 1 |
| `github.com/oauth2-proxy/mockoidc` | `v0.0.0-20261103160011-e06ed0b7cb7f` (no tagged release) | Phase 1, dev and tests only |
| `github.com/coreos/go-oidc/v3` | v3.21.0 | Phase 1 tests; server from phase 2 |
| `golang.org/x/oauth2` | v0.37.0 | Phase 1 tests; server from phase 2 |
| `github.com/modelcontextprotocol/go-sdk` | v1.8.0 | Not in `go.mod` until phase 5 |
