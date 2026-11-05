// Package testapp is a small page that signs in through the broker the way a real app would, using
// the Firebase web SDK. It's used only by the dev stack.
package testapp

import (
	"html/template"
	"log/slog"
	"net/http"
)

// Config says which app the page is.
type Config struct {
	AppID     string
	Name      string
	ProjectID string
	APIKey    string
	// AuthDomain is needed for DirectGoogleSignIn.
	AuthDomain string
	// AuthEmulatorURL connects to an emulator. Leave it empty for a real project.
	AuthEmulatorURL string
	BrokerURL       string
	RedirectURI     string
	// DirectGoogleSignIn adds a button that signs in with Google through Firebase, skipping the broker.
	// That creates the kind of account someone has from before the broker existed.
	DirectGoogleSignIn bool
}

// Handler serves the page.
func Handler(cfg Config) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Referrer-Policy", "no-referrer")
		if err := page.Execute(w, cfg); err != nil {
			slog.Error("rendering test app", "error", err)
		}
	})
}

var page = template.Must(template.New("page").Parse(`<!doctype html>
<html lang="en">
<meta charset="utf-8">
<title>{{.Name}}</title>
<body style="font-family: system-ui; max-width: 40rem; margin: 3rem auto">
<h1>{{.Name}}</h1>
<p>Local test app in project <code>{{.ProjectID}}</code>.</p>
<p id="status">Loading...</p>
<p id="problem" style="color: #b00020"></p>
<pre id="session"></pre>
<p>
  <button id="sign-in" hidden>Sign in</button>
  <button id="refresh" hidden>Refresh token</button>
  <button id="sign-out" hidden>Sign out</button>
  {{if .DirectGoogleSignIn}}<button id="direct-google" hidden>Sign in directly with Google, skipping the broker</button>{{end}}
</p>
<script type="module">
import { initializeApp } from 'https://www.gstatic.com/firebasejs/12.19.0/firebase-app.js'
import {
	connectAuthEmulator, getAuth, getIdTokenResult, GoogleAuthProvider, onIdTokenChanged, signInWithCustomToken, signInWithPopup, signOut,
} from 'https://www.gstatic.com/firebasejs/12.19.0/firebase-auth.js'

const config = {{.}}
const element = (id) => document.getElementById(id)

const auth = getAuth(initializeApp({ apiKey: config.APIKey, authDomain: config.AuthDomain, projectId: config.ProjectID }))
if (config.AuthEmulatorURL) connectAuthEmulator(auth, config.AuthEmulatorURL, { disableWarnings: true })

const base64url = (bytes) => btoa(String.fromCharCode(...new Uint8Array(bytes)))
	.replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '')
const random = () => base64url(crypto.getRandomValues(new Uint8Array(32)))

let refreshes = 0

async function startSignIn() {
	const state = random()
	const verifier = random()
	sessionStorage.setItem('signin', JSON.stringify({ state, verifier }))
	const challenge = base64url(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier)))
	const query = new URLSearchParams({
		app_id: config.AppID,
		redirect_uri: config.RedirectURI,
		state,
		code_challenge: challenge,
		code_challenge_method: 'S256',
	})
	location.assign(config.BrokerURL + '/authorize?' + query)
}

// Finishes a sign-in if the broker has just sent the browser back here.
async function finishSignIn() {
	const params = new URLSearchParams(location.search)
	if (!params.has('code') && !params.has('error')) return
	history.replaceState(null, '', location.pathname)

	const saved = JSON.parse(sessionStorage.getItem('signin') ?? 'null')
	sessionStorage.removeItem('signin')
	if (!saved || saved.state !== params.get('state')) {
		element('problem').textContent = 'Refused: this response has the wrong state.'
		return
	}
	if (params.has('error')) {
		element('problem').textContent = 'The broker refused this sign-in: ' + params.get('error')
		return
	}

	const response = await fetch(config.BrokerURL + '/token', {
		method: 'POST',
		body: new URLSearchParams({
			app_id: config.AppID,
			code: params.get('code'),
			code_verifier: saved.verifier,
			redirect_uri: config.RedirectURI,
		}),
	})
	const result = await response.json()
	if (!response.ok) {
		element('problem').textContent = 'The broker refused the exchange: ' + result.error
		return
	}
	await signInWithCustomToken(auth, result.custom_token)
}

element('sign-in').onclick = startSignIn
const directGoogle = element('direct-google')
if (directGoogle) directGoogle.onclick = () => signInWithPopup(auth, new GoogleAuthProvider()).catch((err) => {
	element('problem').textContent = 'Direct sign-in failed: ' + err.message
})
element('sign-out').onclick = () => signOut(auth)
element('refresh').onclick = async () => {
	await auth.currentUser.getIdToken(true)
	refreshes++
	await show(auth.currentUser)
}

async function show(user) {
	element('sign-in').hidden = !!user
	if (directGoogle) directGoogle.hidden = !!user
	element('refresh').hidden = !user
	element('sign-out').hidden = !user
	if (!user) {
		element('status').textContent = 'Signed out'
		element('session').textContent = ''
		return
	}
	const token = await getIdTokenResult(user)
	const { aud, iss, sub, iat, exp, auth_time, firebase, user_id, ...customClaims } = token.claims
	element('status').textContent = 'Signed in'
	element('session').textContent = JSON.stringify({
		uid: user.uid,
		email: user.email,
		tokenAudience: aud,
		signInProvider: firebase?.sign_in_provider,
		linkedProviders: user.providerData.map((provider) => provider.providerId + ': ' + provider.uid),
		customClaims,
		tokenIssuedAt: new Date(iat * 1000).toISOString(),
		refreshes,
	}, null, 2)
}

try {
	await finishSignIn()
} catch (err) {
	element('problem').textContent = 'Sign-in failed: ' + err.message
}
onIdTokenChanged(auth, show)
</script>
</body>
</html>
`))
