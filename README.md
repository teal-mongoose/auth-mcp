# auth-mcp

The go-between for sign-in. Apps send people here to sign in with Google, Microsoft, Okta or a future
provider, and get back an ordinary Firebase login. Healthspaces admins manage it through MCP tools.

**Status: all seven phases are done, against mock providers only.** Sign-in works end to end for staff
and several customers, and admins can inspect it through read-only MCP tools and a test admin screen.
It's never run against a real provider. See [`SECURITY-REVIEW.md`](SECURITY-REVIEW.md) for what's verified
and what isn't, [`STEP-A.md`](STEP-A.md) for testing with real Google and Firebase, and
[`../mcp-auth-plan.md`](../mcp-auth-plan.md) for the plan.

There are two ways to run it:

- **`cmd/dev`:** everything on this machine, with emulators, mock providers and generic test accounts. It
  can't reach a real Firebase project. This is what the rest of this page describes.
- **`cmd/auth-mcp`:** the real server, against a real throwaway project. See [`STEP-A.md`](STEP-A.md). It refuses
  emulator mode, key files, and any project but `auth-mcp-test-...` ones and `auth-mcp-staging-tm`. The same
  server runs on Cloud Run in staging: see [`STAGING.md`](STAGING.md).

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
| Test App A, project `demo-test-app-a` | `127.0.0.1:8711` |
| Test App B, project `demo-test-app-b` | `127.0.0.1:8712` |
| Test admin screen, project `demo-auth-mcp` | `127.0.0.1:8713` |

To try a sign-in, open a test app **at `127.0.0.1`**, not `localhost`, because browser storage differs
between them. These pages load the Firebase web SDK from `gstatic.com`, and the admin screen loads the
MCP SDK from `esm.sh`, so they need internet access.

Emulators also use hub ports 4402-4404, logging ports 4502-4504 and websocket port 9152. These are
chosen so they don't clash with `core`, `video` or `telehealth-demo`.

Opening a mock provider's authorize URL without a chosen user shows a page for picking who to sign in
as. The providers are in [`internal/mockidp/providers.go`](internal/mockidp/providers.go), and the
accounts, apps and connections in [`internal/fixtures/fixtures.go`](internal/fixtures/fixtures.go).

## How apps sign in

1. The app sends the browser to `GET /authorize`, with `app_id`, its registered `redirect_uri`,
   `state`, and an S256 `code_challenge`. Adding `connection` goes straight to that connection.
   Otherwise, the sign-in page asks for their email, and its domain picks the org and connection.
2. The person signs in at the provider, and the broker checks who they are. The typed email only
   decides where to send them. It isn't stored, and it isn't what identifies them.
3. The browser returns to the app's `redirect_uri` with `code` and `state`, or `error` and `state`.
   Apps only see `access_denied`. The reason is recorded in `sign_in_events` for admins.
4. The app checks `state`, then sends `POST /token` with `app_id`, `code`, `code_verifier` and
   `redirect_uri`. A code works once, and for one minute.
5. The app calls `signInWithCustomToken` with the returned `custom_token`. From there, Firebase works
   as usual, and the session's `org` claim names the person's org. It comes from the connection, and
   replaces any stored `org` claim.

[`internal/testapp/testapp.go`](internal/testapp/testapp.go) is a working example.

A person is recognized through a link, or through their existing Google account in the app's Firebase
project. Microsoft users need a link, because Firebase's record has no tenant to compare. Anyone else is
refused, and email is never used to match them.

**Registering a provider:** each connection has its own callback, `<base URL>/callback/<connection id>`.
Register exactly that URL at the provider. A sign-in that comes back through another connection's URL is
refused, which is what stops one connection stealing another's codes. Issuers are pinned: Google's own,
`https://login.microsoftonline.com/<tenant>/v2.0`, and Okta's own domains, so Okta custom domains aren't
accepted.

**Writing an app:** don't copy `internal/testapp` wholesale, because [some of it is for testing
only](SECURITY-REVIEW.md#if-anyone-copies-the-example-pages). Load nothing third-party on your redirect page,
and remove the code from the URL before doing anything else.

## Admin tools

The MCP server is at `POST /mcp`, using stateless Streamable HTTP. Its tools are all read-only:

| Tool | Purpose |
| --- | --- |
| `list_apps` | Registered apps and their return URLs |
| `list_orgs`, `get_org` | Customers, their domains and their connections |
| `list_connections`, `get_connection` | Provider connections and status, never secrets |
| `get_user` | Find a user in one app's project, by uid or email |
| `list_users` | Page through one app's users |
| `get_user_links` | A user's linked provider identities |
| `list_sign_in_events` | Recent sign-ins and refusals, with the reason |

Every request needs `Authorization: Bearer <Firebase ID token>`:

- The token must be from the broker's own project, so an admin in an app's project gets nothing here.
- It must carry `org: healthspaces`, from a sign-in through the broker, and the account must have
  `admin: true` right now. Anyone else gets a `403`.
- Missing, invalid, expired or revoked tokens, disabled accounts, and sign-ins over 12 hours old get a
  `401`.
- Browsers may only call it from an allowed origin, currently the Test Admin page.

Claim values are shown only for `admin`, `org`, `practice`, `clinic`, `roles` and `role`, and only if
they're a simple value or a list of short strings. Any other claim appears by name in `hidden_claims`. Each call logs who, which tool, what target and the result.

[`internal/adminscreen`](internal/adminscreen/static/app.js) is a test screen for these tools, covering
orgs, connections, users and sign-in events, using the official TypeScript MCP client. Sign in as
`admin@healthspaces.test` to use it. Staff see "Not allowed". It's only part of the dev stack, and
its browser behaviour has no automated tests: its Go tests only cover how it's served.

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

With `go run ./cmd/dev` running, this also tests against the emulators, including the whole sign-in
flow. `-p 1` matters, because packages reseed the same emulators:

```bash
go test -tags=emulator -count=1 -p 1 ./...
```

## Things worth knowing

- **Adding a provider.** [`internal/connector`](internal/connector/connector.go) runs the OIDC flow and
  token checks. A provider adds a small adapter, like
  [`okta.go`](internal/connector/okta.go), saying which claims identify someone and what to refuse.
- **Orgs own domains, and connections belong to an org.** Google and Okta connections accept only
  their org's domains, and Microsoft connections only their tenant. If two orgs claim a domain, nobody
  is routed there, because picking one could send someone to another customer's provider.
- **The sign-in page doesn't list customers.** It only lists connections marked `ShowOnSignInPage`,
  meaning staff's.
- **Client secrets are never stored in Firestore.** The broker reads each from an
  `AUTH_MCP_SECRET_<CONNECTION_ID>` environment variable, which the dev stack sets to mock values.
- **One emulator per project.** A single Auth emulator sends every API-key sign-in, which is how
  browsers sign in, to its default project. So each project has its own emulator, and
  `devenv.AuthClient` points each Admin SDK client at the right one.
- **The server refuses to start outside this setup.** With `FIREBASE_AUTH_EMULATOR_HOST` set, the
  Admin SDK skips ID token signature checks, so anyone able to reach the server could forge an admin
  token. See [`internal/safety/safety.go`](internal/safety/safety.go). The real server,
  [`internal/live`](internal/live/live.go), does the reverse, and refuses to start with that variable set.
- **Test code stays out of the server.** `TestServerDoesNotLinkTestCode` fails if `cmd/auth-mcp` ever
  depends on the emulator wiring, fixtures, mock providers or test pages.
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
| `github.com/modelcontextprotocol/go-sdk` | v1.8.0 | Phase 5 |
