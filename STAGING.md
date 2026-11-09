# Staging: the broker on Cloud Run, with Google sign-in

This puts the broker on the internet at `https://auth-staging.healthspaces.io`, in its own project,
`auth-mcp-staging`, owned by the teal mongoose Google account rather than the healthspaces.com organization,
with Google as its only provider. It's the broker alone: no app uses it yet, and nothing
in hVisit or `core` changes. The test page still runs on this PC, at `http://localhost:8711`, and signs in
through the deployed broker. Okta, Microsoft and other providers come last, once Google sign-in is fleshed
out.

**Safety:** the server, `cmd/auth-setup` and `cmd/testpages` accept only `auth-mcp-test-...` projects and
`auth-mcp-staging`, so they can't touch any other project. There's still no service account key: on Cloud
Run, the server signs as its own service account, `auth-mcp-run`, through Google's IAM API. The client
secret lives only in Secret Manager. Deploys build what's committed, so `.env.live`, `.env.staging` and
uncommitted changes never leave this PC.

## How it runs

| What | Where |
| --- | --- |
| Server | Cloud Run service `auth-mcp`, `us-central1`, 0 to 2 instances |
| Address | `https://auth-staging.healthspaces.io`, a Cloud Run domain mapping |
| Runs as | `auth-mcp-run@auth-mcp-staging.iam.gserviceaccount.com` |
| Its roles | Firestore user, Firebase Auth admin, and signing as itself, in this project only |
| Client secret | Secret Manager, `google-client-secret`, readable by `auth-mcp-run` only |
| Images | Artifact Registry, `us-central1-docker.pkg.dev/auth-mcp-staging/auth-mcp/server:<commit>` |
| Settings | The org, connection and test apps in Firestore, saved by `cmd/auth-setup` from this PC |

Differences from running on this PC:

- The binding cookie is `__Host-` prefixed and `Secure`, so only this exact host can set it, over https.
- Responses carry `Strict-Transport-Security`.
- No browser origin may call the admin MCP tools, because there's no admin screen yet. Set
  `AUTH_MCP_ADMIN_ORIGINS` (comma-separated) in the deploy script when there is one.
- Abandoned sign-ins and codes are deleted by a Firestore TTL policy.
- Requests are rate limited (`internal/live/limits.go`), per client and instance. Clients are told apart by
  the last `X-Forwarded-For` entry, which Cloud Run's front end adds. **That assumes nothing else is in
  front:** put a load balancer in front and every client would share one limit, so the client key must
  change with it.

## 1. What you set up

Do all of this as the teal mongoose account, which owns everything here. No healthspaces.com account has
access to the project. Because it's a single Google account with no organization, the sign-in client can't be
**Internal**, so the broker's own domain check is what keeps sign-in to `healthspaces.com`.

1. **Create the project** at the [Google Cloud console](https://console.cloud.google.com/projectcreate), with
   the id `auth-mcp-staging` exactly (click Edit under the name to set it). Location is "No organization". Link a
   billing account owned by teal mongoose: Cloud Run and Cloud Build need it. If the id is taken, tell me the one
   you get, because the server only accepts this exact name.
2. **Verify `healthspaces.io` for the teal mongoose account,** which the address mapping needs. In
   [Search Console](https://search.google.com/search-console), add a property of type **Domain**,
   `healthspaces.io`. It shows a TXT record: add it at GoDaddy for `healthspaces.io` (type **TXT**, name `@`, the
   value it gives), then click Verify. It can take a few minutes. It sits beside any other TXT records, and
   changes nothing else.
3. **Add Firebase to it** in the [Firebase console](https://console.firebase.google.com): Create a project, then
   near the bottom, **Add Firebase to a Google Cloud project**, and pick `auth-mcp-staging`. Google Analytics
   isn't needed. Then:
   - **Authentication:** click Get started, then enable **Google** under Sign-in method. Under Settings >
     Authorized domains, make sure `localhost` is listed, for the test page.
   - **Firestore Database:** create it in **production mode**, which denies all browser access. Use
     `us-central1` (or `nam5`).
   - **Project settings > Your apps:** add a **Web** app. Hosting isn't needed. Note its `apiKey`.
4. **Create the Google OAuth client** at
   [Google Auth Platform](https://console.cloud.google.com/auth/overview?project=auth-mcp-staging):
   - **Get started:** an app name such as "HealthSpaces sign-in (staging)", the teal mongoose account as the
     support email, Audience **External**, and a contact email.
   - **Audience:** leave it in **Testing**, and add `maxwell@healthspaces.com` as a test user. Only test users
     get past Google then, as a second gate. Adding a personal Gmail account too lets us check that the broker
     refuses it, which Step A couldn't.
   - **Clients > Create client:** type **Web application**, with this authorized redirect URI, exactly:
     `https://auth-staging.healthspaces.io/callback/staff-google`
5. **Store the client secret straight away.** Google shows it only once, when the client is created. In
   Security > Secret Manager (enable the API if asked), Create secret, named exactly `google-client-secret`, with
   the secret as its value and the other settings left as they are. Please don't paste it into chat.
6. **Fill in `.env.staging`.** Copy `.env.staging.example` to `.env.staging`, in this folder, and add the
   client ID and the `apiKey`. Git ignores it.
7. **Sign this PC in as the teal mongoose account,** in a gcloud profile of its own. This PC's usual gcloud
   account is left as it is, and the staging scripts refuse to run as a healthspaces.com account. From Git
   Bash, in `C:\hStuff\auth-mcp`, run each of these and sign in as teal mongoose in the browser that opens:

   ```bash
   deploy/teal-mongoose.sh gcloud auth login
   ```

   ```bash
   deploy/teal-mongoose.sh gcloud auth application-default login
   ```

   The profile lives in `%APPDATA%\teal-mongoose`.

Then tell me it's done.

## 2. What I run, and the steps between

1. **Prepare the project,** from Git Bash:

   ```bash
   deploy/staging-setup.sh
   ```

   It turns on the APIs, creates `auth-mcp-run` and its roles, the image repository and the TTL policies,
   gives `auth-mcp-run` access to your secret, and grants Cloud Build what it needs. It's safe to run again.

2. **I save the settings to Firestore,** from this PC:

   ```bash
   deploy/teal-mongoose.sh go run ./cmd/auth-setup -env-file .env.staging save
   ```

3. **I deploy:**

   ```bash
   deploy/deploy-staging.sh
   ```

4. **I map the address:**

   ```bash
   deploy/teal-mongoose.sh gcloud beta run domain-mappings create --service auth-mcp --domain auth-staging.healthspaces.io --region us-central1 --project auth-mcp-staging
   ```

5. **You add the DNS record at GoDaddy,** for `healthspaces.io`: type **CNAME**, name `auth-staging`, value
   `ghs.googlehosted.com.` Google then issues a certificate, which can take 15 minutes to an hour.

## 3. Checking it

Once `https://auth-staging.healthspaces.io/` loads with a valid certificate, I start the test page on this
PC:

```bash
go run ./cmd/testpages -env-file .env.staging
```

At `http://localhost:8711`, sign in with your `healthspaces.com` account through the broker.

| Check | Expected |
| --- | --- |
| Sign in through the broker | Back at the test page, signed in, with `org: healthspaces` |
| Sign in again | The same uid |
| Cancel at Google, or a personal account | `access_denied` at the test page |
| `curl -I https://auth-staging.healthspaces.io/authorize` | `Strict-Transport-Security` and the other headers |
| The binding cookie, in the browser's dev tools | `__Host-auth_mcp_binding_...`, `Secure`, `HttpOnly`, `Lax` |
| `POST /mcp` with no token | `401` |
| Cloud Run's logs | The sign-in, and no errors |

The `go test -tags=live` checks from Step A stay on the throwaway project: they create and delete accounts,
which staging doesn't need.

## Results, 2026-11-09

Set up and deployed as the teal mongoose account. The project's only member is that account, as Owner, beside
Google's own service accounts.

**DNS isn't there yet,** so staging currently runs at Cloud Run's own address,
`https://auth-mcp-26998740818.us-central1.run.app`, deployed with `AUTH_MCP_STAGING_ADDRESS=cloud-run`. The
broker's Google client has that address's callback as a second redirect URI, and `.env.staging` points the test
pages at it. When `auth-staging.healthspaces.io` resolves:

1. Add the GoDaddy CNAME, and wait for the certificate.
2. Redeploy with plain `deploy/deploy-staging.sh`.
3. Set `AUTH_MCP_BASE_URL` in `.env.staging` back to `https://auth-staging.healthspaces.io`.
4. Remove the `run.app` redirect URI from the broker's Google client.

| Check | Result |
| --- | --- |
| Server starts on Cloud Run, as `auth-mcp-run`, against `auth-mcp-staging` | Passed |
| `GET /authorize` with nothing | `400`, with HSTS, the CSP, `no-store`, `nosniff` and `DENY` |
| `POST /mcp` with no token | `401` |
| The test page's sign-in page, served from Cloud Run with the app read from Firestore | Passed |
| Real Google sign-in through the broker, before the user existed in staging's Firebase | Refused, `not_linked`, as designed |
| The same, after one direct Google sign-in created the user | Signed in, three times, each issuing one token |
| The client secret from Secret Manager | Works: Google accepted the code exchange |

**New users can't sign in through the broker yet.** It only recognizes someone through a link or an existing
Google user in the app's project, and creates no accounts. Existing users of an app already on Google sign-in are
fine. How new people get in, by creating accounts on first sign-in per connection, admins creating them, or
invitations, is to be decided at Step B or C. See the plan.

## Not done yet

- **No monitoring or alerts,** and sign-in events have no retention period.
- **No admins,** and no admin screen. `cmd/auth-setup grant-admin` can make one when needed.
- **Okta, Microsoft and other providers,** last, once Google sign-in is fleshed out.
