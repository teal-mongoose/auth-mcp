// The test admin screen. It signs in through the broker like any app, then calls the admin MCP server
// with the official TypeScript MCP client.
//
// Names, emails and claims come from people and providers, so everything goes on the page as text,
// through el() below. Never build HTML from strings here.
import { initializeApp } from 'https://www.gstatic.com/firebasejs/12.19.0/firebase-app.js'
import {
	connectAuthEmulator, getAuth, onAuthStateChanged, signInWithCustomToken, signOut,
} from 'https://www.gstatic.com/firebasejs/12.19.0/firebase-auth.js'
// The CDN's default zod breaks this SDK version when it loads, so it's pinned to one that works.
import { Client } from 'https://esm.sh/@modelcontextprotocol/sdk@1.32.1/client/index.js?deps=zod@3.25.76'
import { StreamableHTTPClientTransport } from 'https://esm.sh/@modelcontextprotocol/sdk@1.32.1/client/streamableHttp.js?deps=zod@3.25.76'

const PAGE_SIZE = 3

const config = JSON.parse(document.getElementById('config').textContent)
const main = document.getElementById('main')
const nav = document.getElementById('nav')
const account = document.getElementById('account')
const problem = document.getElementById('problem')

const auth = getAuth(initializeApp({ apiKey: 'fake-api-key', projectId: config.ProjectID }))
connectAuthEmulator(auth, config.AuthEmulatorURL, { disableWarnings: true })

/** Builds an element. Strings become text, so they can't be read as HTML. */
function el(tag, attributes = {}, ...children) {
	const node = document.createElement(tag)
	for (const [name, value] of Object.entries(attributes)) {
		if (name.startsWith('on')) node.addEventListener(name.slice(2), value)
		else node.setAttribute(name, value)
	}
	node.append(...children.filter((child) => child !== null && child !== undefined))
	return node
}

function table(headers, rows) {
	return el('div', { class: 'table-wrap' }, el('table', {},
		el('thead', {}, el('tr', {}, ...headers.map((header) => el('th', { scope: 'col' }, header)))),
		el('tbody', {}, ...rows.map((cells) => el('tr', {}, ...cells.map((cell) => el('td', {}, cell))))),
	))
}

const button = (label, onclick) => el('button', { type: 'button', onclick }, label)
const yesNo = (value) => (value ? 'Yes' : 'No')
const showJSON = (value) => el('pre', {}, JSON.stringify(value, null, 2))

function showProblem(message) {
	problem.textContent = message
	problem.hidden = !message
}

// Signing in, the way any app does.

const base64url = (bytes) => btoa(String.fromCharCode(...new Uint8Array(bytes)))
	.replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '')
const random = () => base64url(crypto.getRandomValues(new Uint8Array(32)))

async function startSignIn() {
	const state = random()
	const verifier = random()
	sessionStorage.setItem('signin', JSON.stringify({ state, verifier }))
	const challenge = base64url(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier)))
	location.assign(config.BrokerURL + '/authorize?' + new URLSearchParams({
		app_id: config.AppID,
		redirect_uri: config.RedirectURI,
		state,
		code_challenge: challenge,
		code_challenge_method: 'S256',
	}))
}

async function finishSignIn() {
	const params = new URLSearchParams(location.search)
	if (!params.has('code') && !params.has('error')) return
	history.replaceState(null, '', location.pathname)

	const saved = JSON.parse(sessionStorage.getItem('signin') ?? 'null')
	sessionStorage.removeItem('signin')
	if (!saved || saved.state !== params.get('state')) {
		showProblem('That sign-in response could not be trusted. Please try again.')
		return
	}
	if (params.has('error')) {
		showProblem('Sign-in was refused. This account may not have access to this screen.')
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
		showProblem('Sign-in could not be completed. Please try again.')
		return
	}
	await signInWithCustomToken(auth, result.custom_token)
}

// Calling the MCP server.

/** The last HTTP status the server refused a request with, because the SDK's errors vary. */
let refusedStatus = 0

/** Sends each request with a fresh ID token. */
async function authorizedFetch(url, init = {}) {
	const headers = new Headers(init.headers)
	headers.set('Authorization', 'Bearer ' + await auth.currentUser.getIdToken())
	const response = await fetch(url, { ...init, headers })
	if (response.status === 401 || response.status === 403) refusedStatus = response.status
	return response
}

let client = null

async function connect() {
	refusedStatus = 0
	const next = new Client({ name: 'test-admin-screen', version: '1.0.0' })
	await next.connect(new StreamableHTTPClientTransport(new URL(config.BrokerURL + '/mcp'), { fetch: authorizedFetch }))
	client = next
}

async function callTool(name, args = {}) {
	const result = await client.callTool({ name, arguments: args })
	if (result.isError) throw new ToolError(result.content?.[0]?.text ?? 'That request failed.')
	return result.structuredContent
}

class ToolError extends Error {}

/** Shows what the server said about access, if that's what went wrong. Returns whether it did. */
function handleRefusal() {
	if (refusedStatus === 403) {
		showNotAllowed()
		return true
	}
	if (refusedStatus === 401) {
		showSessionEnded()
		return true
	}
	return false
}

function showNotAllowed() {
	client = null
	nav.hidden = true
	showProblem('')
	main.replaceChildren(
		el('h2', {}, 'Not allowed'),
		el('p', {}, 'You\'re signed in as ' + (auth.currentUser?.email ?? 'this account') + ', but this screen is only for Healthspaces admins.'),
		el('p', {}, 'Sign out to use a different account, or ask an admin for access.'),
	)
}

function showSessionEnded() {
	client = null
	nav.hidden = true
	showProblem('')
	main.replaceChildren(
		el('h2', {}, 'Please sign in again'),
		el('p', {}, 'This session is no longer valid. It may have been revoked, or the account may have been disabled.'),
		el('p', {}, 'Sign out, then sign in again. If that doesn\'t work, ask an admin to check this account.'),
	)
}

// Sections.

let currentSection = null
let viewVersion = 0

/** Shows a view. If another view has started since this one began, its result is dropped. */
async function show(view) {
	const version = ++viewVersion
	const previous = [...main.childNodes]
	showProblem('')
	main.replaceChildren(el('p', {}, 'Loading...'))
	try {
		const content = await view()
		if (version === viewVersion) main.replaceChildren(...content)
	} catch (err) {
		if (version !== viewVersion) return
		if (handleRefusal()) return
		// Keep what was on screen, so that a lookup that finds nothing can be corrected and tried again.
		main.replaceChildren(...previous)
		if (err instanceof ToolError) {
			showProblem(err.message)
			return
		}
		showProblem('The server couldn\'t be reached, or something went wrong. Please try again.')
		console.error(err)
	}
}

async function orgsView() {
	const { orgs } = await callTool('list_orgs')
	return [
		el('h2', {}, 'Orgs'),
		table(['Name', 'ID', 'Domains', ''], orgs.map((org) => [
			org.name, org.id, org.domains.join(', '),
			button('Details', () => show(() => orgView(org.id))),
		])),
	]
}

async function orgView(id) {
	const { org, connections } = await callTool('get_org', { org_id: id })
	return [
		el('h2', {}, org.name),
		el('p', {}, 'Domains: ' + org.domains.join(', ')),
		el('h2', {}, 'Connections'),
		connectionsTable(connections),
		el('div', { class: 'toolbar' }, button('Back to orgs', () => show(orgsView))),
	]
}

function connectionsTable(connections) {
	return table(['Name', 'ID', 'Org', 'Kind', 'Issuer', 'Tenant', 'Enabled', 'On sign-in page'], connections.map((c) => [
		c.name, c.id, c.org_id, c.kind, c.issuer, c.tenant_id ?? '', yesNo(c.enabled), yesNo(c.show_on_sign_in_page),
	]))
}

async function connectionsView() {
	const { connections } = await callTool('list_connections')
	return [el('h2', {}, 'Connections'), connectionsTable(connections)]
}

function userRows(appId, users) {
	return users.map((user) => [
		user.uid, user.email ?? '', user.display_name ?? '', user.disabled ? 'Disabled' : 'Active', showJSON(user.claims),
		button('Details', () => show(() => userView(appId, { uid: user.uid }))),
	])
}

const USER_HEADERS = ['UID', 'Email', 'Name', 'Status', 'Claims', '']

let selectedApp = null

async function usersView(pageToken = '') {
	const { apps } = await callTool('list_apps')
	selectedApp ??= apps[0]?.id
	const args = { app_id: selectedApp, limit: PAGE_SIZE }
	if (pageToken) args.page_token = pageToken
	const { users, next_page_token: next } = await callTool('list_users', args)

	const picker = el('select', {
		id: 'app-picker',
		onchange: (event) => {
			selectedApp = event.target.value
			show(() => usersView())
		},
	}, ...apps.map((app) => el('option', { value: app.id }, app.name)))
	picker.value = selectedApp

	const lookupInput = el('input', { id: 'user-lookup', type: 'text', required: 'required' })
	const lookup = el('form', {
		onsubmit: (event) => {
			event.preventDefault()
			const value = lookupInput.value.trim()
			show(() => userView(selectedApp, value.includes('@') ? { email: value } : { uid: value }))
		},
	},
	el('label', { for: 'user-lookup' }, 'Find by UID or email'),
	lookupInput,
	el('button', { type: 'submit' }, 'Find'))

	return [
		el('h2', {}, 'Users'),
		el('div', { class: 'toolbar' }, el('label', { for: 'app-picker' }, 'App'), picker),
		lookup,
		table(USER_HEADERS, userRows(selectedApp, users)),
		el('div', { class: 'toolbar' },
			pageToken ? button('First page', () => show(() => usersView())) : null,
			next ? button('Next page', () => show(() => usersView(next))) : null),
	]
}

async function userView(appId, lookup) {
	const { user } = await callTool('get_user', { app_id: appId, ...lookup })
	const { links } = await callTool('get_user_links', { app_id: appId, uid: user.uid })

	const facts = [
		['UID', user.uid],
		['Email', user.email ?? ''],
		['Email verified', yesNo(user.email_verified)],
		['Name', user.display_name ?? ''],
		['Status', user.disabled ? 'Disabled' : 'Active'],
		['Providers', user.provider_ids.join(', ')],
		['Created', user.created_at ?? ''],
		['Last sign-in', user.last_sign_in_at ?? ''],
		['Hidden claims', user.hidden_claims.join(', ')],
	]
	return [
		el('h2', {}, user.display_name || user.uid),
		el('dl', {}, ...facts.flatMap(([name, value]) => [el('dt', {}, name), el('dd', {}, value)])),
		el('h2', {}, 'Claims'),
		showJSON(user.claims),
		el('h2', {}, 'Linked identities'),
		links.length === 0
			? el('p', {}, 'None stored. This person may be recognized through their existing provider account, or not at all.')
			: table(['Connection', 'Subject', 'Linked'], links.map((link) => [link.connection_id, link.subject, link.created_at ?? ''])),
		el('div', { class: 'toolbar' }, button('Back to users', () => show(() => usersView()))),
	]
}

async function eventsView() {
	const { events } = await callTool('list_sign_in_events', { limit: 25 })
	return [
		el('h2', {}, 'Recent sign-ins'),
		el('div', { class: 'toolbar' }, button('Refresh', () => show(eventsView))),
		events.length === 0
			? el('p', {}, 'Nothing yet.')
			: table(['Time', 'Outcome', 'Reason', 'App', 'Org', 'Connection', 'Email', 'UID'], events.map((event) => [
				event.time, event.outcome === 'signed_in' ? 'Signed in' : 'Refused', event.reason ?? '', event.app_id ?? '',
				event.org_id ?? '', event.connection_id ?? '', event.email ?? '', event.uid ?? '',
			])),
	]
}

const SECTIONS = [
	['Orgs', orgsView],
	['Connections', connectionsView],
	['Users', () => usersView()],
	['Sign-ins', eventsView],
]

function showSection(label, view) {
	currentSection = label
	for (const item of nav.children) {
		if (item.textContent === currentSection) item.setAttribute('aria-current', 'page')
		else item.removeAttribute('aria-current')
	}
	return show(view)
}

function renderNav() {
	nav.replaceChildren(...SECTIONS.map(([label, view]) => button(label, () => showSection(label, view))))
	nav.hidden = false
}

// Putting it together.

async function onUserChanged(user) {
	viewVersion++
	if (!user) {
		client = null
		nav.hidden = true
		account.replaceChildren(button('Sign in', startSignIn))
		main.replaceChildren(el('p', {}, 'Sign in to inspect the broker.'))
		return
	}

	account.replaceChildren(el('span', {}, user.email ?? user.uid), button('Sign out', () => signOut(auth)))
	main.replaceChildren(el('p', {}, 'Checking your access...'))
	try {
		await connect()
	} catch (err) {
		if (handleRefusal()) return
		main.replaceChildren()
		showProblem('The server couldn\'t be reached. Please try again.')
		console.error(err)
		return
	}
	renderNav()
	await showSection(...SECTIONS[0])
}

try {
	await finishSignIn()
} catch (err) {
	showProblem('Sign-in failed. Please try again.')
	console.error(err)
}
onAuthStateChanged(auth, onUserChanged)
