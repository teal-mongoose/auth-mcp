# Step A: real Google and Firebase

This tests the broker against real Google sign-in and a real Firebase project, using a throwaway project
and your own account. Okta and Microsoft come later. The server still only runs on this PC.

**Safety:** the PC's default credentials can reach real projects, so `cmd/auth-mcp`, `cmd/auth-setup`,
`cmd/testpages` and the checks all refuse any project not named `auth-mcp-test-...`, emulator mode, and key
files. Nothing here touches your real projects.

## 1. What you set up

Replace `PROJECT` with your project's id, and `SERVICE_ACCOUNT` with the account from step 3.

1. **Create the project** in the [Firebase console](https://console.firebase.google.com), with an id starting
   with `auth-mcp-test-`. Google Analytics isn't needed.
2. **Turn on these in the console:**
   - **Authentication:** click Get started, then enable **Google** under Sign-in method. Under Settings >
     Authorized domains, make sure `localhost` is listed, and add it if not.
   - **Firestore Database:** create it in **production mode**, which denies all browser access. Any location
     is fine.
   - **Project settings > Your apps:** add a **Web** app. Hosting isn't needed. Note its `apiKey` and
     `authDomain`.
3. **Find the service account:** Project settings > Service accounts. It looks like
   `firebase-adminsdk-xxxxx@PROJECT.iam.gserviceaccount.com`. Don't generate a key.
4. **Allow signing without a key.** `YOUR_EMAIL` is the account you use with `gcloud`:

   ```bash
   gcloud services enable iamcredentials.googleapis.com identitytoolkit.googleapis.com firestore.googleapis.com --project PROJECT
   ```

   ```bash
   gcloud iam service-accounts add-iam-policy-binding SERVICE_ACCOUNT --member=user:YOUR_EMAIL --role=roles/iam.serviceAccountTokenCreator --project PROJECT
   ```

   ```bash
   gcloud auth application-default login
   ```

   Use the same account for that last sign-in. A new permission can take a few minutes to apply.
5. **Create the Google OAuth client** in the [Google Cloud console](https://console.cloud.google.com), with the
   project selected, under Google Auth Platform:
   - **Audience:** choose **Internal** if it's offered, which limits sign-in to your Workspace.
   - **Clients > Create client:** type **Web application**, with this authorized redirect URI, exactly:
     `http://localhost:8701/callback/staff-google`
6. **Fill in `.env.live`.** Copy `.env.example` to `.env.live`, in this folder, and fill it in. Git ignores it.
   `AUTH_MCP_STAFF_DOMAINS` is your Workspace domain. Please don't paste the client secret into chat.

Then tell me the project's id. I can check the rest without seeing any secrets.

## 2. What I run

```bash
go run ./cmd/auth-setup save
```

```bash
go test -tags=live -count=1 ./internal/live/
```

Those checks use temporary accounts, which they delete, and they don't involve Google. They cover what the
emulators couldn't prove:

- Custom tokens are really signed, without a key file, and real Firebase accepts them.
- Real Firebase refuses a tampered custom token, and the server refuses forged ID tokens.
- The `org` claim replaces a stored one and survives a token refresh, and stored claims carry over.
- Revoking a session or disabling an account locks an admin out, and removing `admin` applies at once.
- Every tool's query runs on real Firestore, and a bad page token gets a clear refusal.
- The whole sign-in flow works on real Firebase and Firestore, with a mock provider, and a code works once.
- An existing account is found by its `google.com` identity.

**Result, 2026-11-09:** saved to `auth-mcp-test-1`, and every check passes. The details are in
`SECURITY-REVIEW.md`, under "Settled by Step A".

## 3. What you do in a browser

Start the server and the pages, each in its own terminal:

```bash
go run ./cmd/auth-mcp
```

```bash
go run ./cmd/testpages
```

I can't enter passwords, so you do the Google sign-ins. Use `localhost`, not `127.0.0.1`.

| # | At | Do | Expect |
| --- | --- | --- | --- |
| 1 | `localhost:8713` | Sign in through the broker, with your email | Refused, because there's no account yet |
| 2 | `localhost:8711` | **Sign in directly with Google**, then note the `uid` and `linkedProviders`. Sign out | Signed in, with `signInProvider: google.com` |
| 3 | `localhost:8711` | **Sign in**, using your email | The **same uid**, with `org` set and `signInProvider: custom`. This is how an existing user would move across |
| 4 | `localhost:8711` | **Refresh token** | Same uid, and `org` is still there |
| 5 | `localhost:8713` | Sign in | "Not allowed", because you aren't an admin yet |
| 6 | Terminal | `go run ./cmd/auth-setup grant-admin YOUR_EMAIL` | Says you're now an admin |
| 7 | `localhost:8713` | Sign out and in again, then open each section | Everything works. Sign-ins shows these steps, including the refusal in step 1 |
| 8 | `localhost:8711` | Sign out, start signing in, then cancel at Google | Refused, with `provider_error` in Sign-ins, if Google returns to the broker |

If your audience is **External** rather than Internal, also try a personal Gmail listed as a test user. It
should be refused with `wrong_domain`. With Internal, Google stops it first, so the broker's check isn't
reached.

## 4. What this leaves unproven

- Okta and Microsoft, including what Firebase stores for Microsoft users.
- A deployed server: https, the `__Host-` cookie and signing on Cloud Run.
- Signing for several Firebase projects. This setup uses one project for the broker and the test apps.

## 5. Cleaning up

Delete the project in the Firebase console, which also removes its OAuth client, and delete `.env.live`. You can
also clear your local credentials:

```bash
gcloud auth application-default revoke
```
