# Security review

Phase 7 of [`../mcp-auth-plan.md`](../mcp-auth-plan.md), 2026-11-05.

**Result:** the review found one critical flaw, which is fixed, and several high and medium ones, which
are fixed or scheduled below. This service has only ever run against mock providers and emulators, so
nothing here says how it behaves with real ones.

## How it was reviewed

- **Two independent reviewers** read the code without being told what I thought of it: one on the
  sign-in path, one on the admin server and screen. They only read code, and didn't run attacks.
- **Attack tests.** The most serious finding was reproduced by a test before being fixed.
- **Scanners.** `govulncheck` for known vulnerabilities, `gosec` and others through `golangci-lint`, and
  a search for committed secrets.
- **Mutation checks.** Each security check was disabled in turn, to confirm a test fails without it.
  This shows the tests guard the checks that exist, but not that the right checks exist. The critical
  flaw had passed every earlier mutation check.

## Fixed

### Critical

**Identity provider mix-up.** All connections shared one callback URL. A malicious connection could send
someone on to an honest provider, and the code that came back was posted to the malicious connection's
token endpoint. The attacker could redeem it in their own sign-in and become that person, in any app, in
one click. `TestIdentityProviderMixUp` did this successfully against the old code, reaching `ACCOUNT
TAKEOVER`.

Each connection now has its own callback, `/callback/{connection}`, and a sign-in returning through
another connection's URL is refused before any exchange. **Every provider must register that exact URL.**

### High

- **Provider kinds weren't tied to real issuers.** A connection marked `google` or `microsoft` could use
  any server, which could then claim to be any existing user. Issuers are now pinned: Google's and the
  tenant's own at Microsoft exactly, and Okta's to Okta's own domains. Shared Microsoft tenants are
  refused, by name and by id. Mock providers need an explicit `AllowLocal` setting.
- **Admin sessions never aged out.** Refresh tokens don't expire, so a session could outlast someone's
  access at their provider, or a stolen token could work indefinitely. Admins now need to have signed in
  within 12 hours.

### Medium

- **Existing Microsoft users were matched on `oid` alone**, ignoring the tenant, because Firebase's record
  has none. They now need a link. Existing Google users are still matched, because Google's `sub` is
  global and its issuer is now pinned.
- **Removing someone's `admin` claim took up to an hour to apply.** It's now read from the live account.
- **Admin access didn't require a sign-in through the broker.** Someone with the right stored claims could
  sign in to the project directly, skipping the broker's checks and any provider MFA. A broker sign-in
  with no tenant is now required.
- **Discovered endpoints were unconstrained.** A provider could point its token endpoint at plain http,
  exposing the client secret. Endpoints must now use https, redirects aren't followed, and responses are
  limited to 1 MiB.

### Low

- IDs from URLs and tool inputs are validated, so they can't become Firestore paths or fill logs and
  events. The format also means no two connections can share a secret's environment variable.
- Removing a return address now stops sign-ins and exchanges already in progress.
- Server read, write and idle timeouts are set.
- Org domains are stored in lowercase, so that capitals can't slip past the duplicate-domain refusal.
- RFC 9207's `iss` parameter is checked when a provider sends it.
- Exchanges are recorded as `token_issued`, because `signed_in` only meant that a code was issued. Events
  are saved even if the client hangs up.
- Admin refusals are logged, and lookups by email log the uid found.
- Visible claims must be a simple shape, so a secret nested under an allowed name stays hidden.
- `get_user` properly validates email addresses, which also keeps bad input out of the error log.
- Tools refuse to run without the admin scope, in case the HTTP check is ever removed by accident.
- `x/net` is updated. The screen shows the subject in sign-ins and uses the uid as a user's heading, and
  tool descriptions warn that names and emails are untrusted.

## Not fixed yet

### Needed before Step C, onboarding customers

- **Which orgs can use which app.** `connection=` works for any enabled connection from any app. That gives
  a phisher a trusted first URL, reveals connection ids, and skips the duplicate-domain refusal. Today the
  link is what protects each app, so this must be closed before any automatic linking is added.
- **Sessions outliving removal at a customer's provider.** The 12-hour limit only covers admins.

### Needed before deploying

These are also listed in the plan.

- **An explicit list of allowed projects.** `cmd/auth-mcp` no longer imports `devenv`, a test keeps it that
  way, and it refuses to start in emulator mode. But it only accepts projects named `auth-mcp-test-...`, which
  must be replaced with an explicit list, and it only serves one project so far.
- **Rate limits**, which must count tool calls as well as requests, because the SDK accepts JSON-RPC
  batches. Consider refusing batches.
- **Binding cookie:** use a `__Host-` prefix and add HSTS.
- **A `recover` around tool handlers.** A panic in one would stop the whole process.
- **Paging and filters for sign-in events.** Anyone can currently push real events out of view by sending
  junk requests. Consider leaving such noise out of the event list.
- **Client authentication at `/token`** for apps with a backend. Without it, a code leaked by an app's
  page within its one minute can be redeemed by someone who started the flow.
- **Backoff per connection**, so that a failing provider doesn't cost a discovery request every time.
- **Blocking private addresses in outbound requests.** This matters if issuers ever become less tightly
  pinned, for example by allowing Okta custom domains.

### If anyone copies the example pages

`internal/testapp` and `internal/adminscreen` are test tools. Don't copy these parts into a real app:

- Both keep Firebase's refresh token in IndexedDB, and signing out doesn't revoke it. An admin screen should
  use in-memory persistence, revoke on sign-out and time out when idle.
- The admin screen's CSP allows all of `esm.sh`, which serves any npm package, so it wouldn't contain a
  script injection. Self-host the bundles, and use `script-src 'self'`.
- The test app has no CSP, and always connects to the Auth emulator.
- Their pages publish the whole config struct, so any secret later added to it would reach the browser.

Apps should also load nothing third-party on their redirect page, and remove the code from the URL first.

### AI clients

If an AI model ever calls these tools, names and emails in the output are text that outsiders control, so
they could carry instructions. Tool descriptions warn about this, but it isn't a guarantee. Decide how to
handle it before connecting one. Lengths and control characters aren't filtered yet.

## Scanner results

- **`govulncheck`:** no vulnerabilities in code this service calls. After updating `x/net`, the remaining one
  is `golang.org/x/crypto/openpgp`, which isn't imported.
- **`gosec`:** eight findings, none of them a real problem:
  - The two open-redirect reports are redirects to a registered address and to a pinned provider.
  - The cookie report is about `Secure`, which is set whenever the base URL uses https.
  - The two subprocess reports are in `cmd/dev`, with fixed arguments.
  - The three credential reports are the mock providers' values.
- **Other linters:** the rest are style issues in development code.
- **Committed secrets:** none found.

## What's verified, and how far

| Claim | Evidence |
| --- | --- |
| Sign-in checks refuse the attacks listed in the plan, and the mix-up | Tests against emulators and mock or fake providers |
| The tests guard the checks | 153 of 154 mutations caught. The other is the revocation check, below |
| Sign-in, the admin tools and the screen work in a browser | Done by hand, with no automated browser tests |
| Secrets, hashes and hidden claims stay out of output and logs | Tests that scan all tool output and logs |
| Test code isn't linked into the server | `TestServerDoesNotLinkTestCode` |

Two small safeguards have no test, because nothing can reach them today: tools refusing to run without the
admin scope, and events being saved after a client hangs up. The mutation runs were scripts outside the repo,
so they won't rerun automatically.

## Settled by Step A, on 2026-11-09

`go test -tags=live` against the throwaway project `auth-mcp-test-1` showed these on real Firebase and Firestore:

- Custom tokens are really signed, through Google's IAM API with no key file, and real Firebase accepts them. It
  refuses a tampered one.
- Unsigned and wrongly signed ID tokens are refused, so the server isn't in emulator mode.
- A session's `org` claim replaces a stored one and survives a refresh, and stored claims carry over.
- Revoking a session locks an admin out because the server checks: the plain check still accepted the revoked
  token. This was the one mutation the emulator couldn't catch.
- Every tool's query runs on real Firestore without extra indexes, and a code works once under real transactions.
- `list_users` with an unknown page token lists from wherever it would sort, rather than failing. That's harmless
  for a read-only admin tool.

## What still can't be known

- How Google behaves in a real sign-in, which needs a person: see `STEP-A.md`, section 3.
- How Microsoft and Okta behave, including what Firebase stores as the `microsoft.com` uid. That decides
  whether Microsoft users can ever be matched automatically.
- The final step of the mix-up attack at a real provider. The fix doesn't depend on that, because the code
  never reaches the other connection.
