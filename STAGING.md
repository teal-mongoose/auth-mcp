# Staging: the broker on Cloud Run, with Google sign-in

This puts the broker on the internet at `https://auth-staging.healthspaces.io`, in its own project,
`auth-mcp-staging-tm`, owned by the teal mongoose Google account rather than the healthspaces.com organization,
with Google as its only provider. It's the broker alone: no app uses it yet, and nothing
in hVisit or `core` changes. The test page still runs on this PC, at `http://localhost:8711`, and signs in
through the deployed broker. Okta and Microsoft come after this.

**Safety:** the server, `cmd/auth-setup` and `cmd/testpages` accept only `auth-mcp-test-...` projects and
`auth-mcp-staging-tm`, so they can't touch any other project. There's still no service account key: on Cloud
Run, the server signs as its own service account, `auth-mcp-run`, through Google's IAM API. The client
secret lives only in Secret Manager. Deploys build what's committed, so `.env.live`, `.env.staging` and
uncommitted changes never leave this PC.

## How it runs

| What | Where |
| --- | --- |
| Server | Cloud Run service `auth-mcp`, `us-central1`, 0 to 2 instances |
| Address | `https://auth-staging.healthspaces.io`, a Cloud Run domain mapping |
| Runs as | `auth-mcp-run@auth-mcp-staging-tm.iam.gserviceaccount.com` |
| Its roles | Firestore user, Firebase Auth admin, and signing as itself, in this project only |
| Client secret | Secret Manager, `google-client-secret`, readable by `auth-mcp-run` only |
| Images | Artifact Registry, `us-central1-docker.pkg.dev/auth-mcp-staging-tm/auth-mcp/server:<commit>` |
| Settings | The org, connection and test apps in Firestore, saved by `cmd/auth-setup` from this PC |

Differences from running on this PC:

- The binding cookie is `__Host-` prefixed and `Secure`, so only this exact host can set it, over https.
- Responses carry `Strict-Transport-Security`.
- No browser origin may call the admin MCP tools, because there's no admin screen yet. Set
  `AUTH_MCP_ADMIN_ORIGINS` (comma-separated) in the deploy script when there is one.
- Abandoned sign-ins and codes are deleted by a Firestore TTL policy.

## 1. What you set up

Do all of this signed in to the console as the teal mongoose account, which owns the project. It's a single
Google account with no organization, which changes two things: the sign-in client can't be **Internal**, so the
broker's own domain check is what keeps sign-in to `healthspaces.com`; and this PC's `gcloud`, signed in as
`software@healthspaces.com`, needs to be made an Owner.

1. **Create the project** at the [Google Cloud console](https://console.cloud.google.com/projectcreate), with
   the id `auth-mcp-staging-tm` exactly (click Edit under the name to set it). Location is "No organization". Link a
   billing account owned by teal mongoose: Cloud Run and Cloud Build need it. If the id is taken, tell me the one
   you get, because the server only accepts this exact name.
2. **Make `software@healthspaces.com` an Owner:** IAM & Admin > IAM > Grant access, role **Owner**. Google
   emails it an invitation, which must be accepted from that inbox before it takes effect. That account is
   already a verified owner of `healthspaces.io`, which the address mapping needs.
3. **Add Firebase to it** in the [Firebase console](https://console.firebase.google.com): Create a project, then
   near the bottom, **Add Firebase to a Google Cloud project**, and pick `auth-mcp-staging-tm`. Google Analytics
   isn't needed. Then:
   - **Authentication:** click Get started, then enable **Google** under Sign-in method. Under Settings >
     Authorized domains, make sure `localhost` is listed, for the test page.
   - **Firestore Database:** create it in **production mode**, which denies all browser access. Use
     `us-central1` (or `nam5`).
   - **Project settings > Your apps:** add a **Web** app. Hosting isn't needed. Note its `apiKey`.
4. **Create the Google OAuth client** at
   [Google Auth Platform](https://console.cloud.google.com/auth/overview?project=auth-mcp-staging-tm):
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
   go run ./cmd/auth-setup -env-file .env.staging save
   ```

3. **I deploy:**

   ```bash
   deploy/deploy-staging.sh
   ```

4. **I map the address:**

   ```bash
   gcloud beta run domain-mappings create --service auth-mcp --domain auth-staging.healthspaces.io --region us-central1 --project auth-mcp-staging-tm
   ```

   This runs as `software@healthspaces.com`, which is a verified owner of `healthspaces.io`.

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

## Not done yet

- **No rate limits.** Anyone can reach `/authorize` and `/token`. At most 2 instances caps the cost, and
  codes only ever go to registered return addresses, which today are on this PC. Rate limits come before
  any real app uses it.
- **No monitoring or alerts,** and sign-in events have no retention period.
- **No admins,** and no admin screen. `cmd/auth-setup grant-admin` can make one when needed.
- **Okta and Microsoft,** next.
