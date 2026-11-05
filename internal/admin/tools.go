package admin

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	firebaseauth "firebase.google.com/go/v4/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"google.golang.org/api/iterator"

	"github.com/teal-mongoose/auth-mcp/internal/broker"
	"github.com/teal-mongoose/auth-mcp/internal/connector"
)

const (
	defaultLimit = 25
	maxLimit     = 100
	maxUIDLength = 128
)

// visibleClaims are the custom claims whose values tools may show. Any other claim shows only its
// name, because claims can hold anything: one existing script writes a password into them.
var visibleClaims = []string{"admin", "org", "practice", "clinic", "roles", "role"}

// userError is a problem with the request, whose message is safe to show the caller. Any other error
// is logged, and the caller only learns that something went wrong.
type userError string

func (e userError) Error() string { return string(e) }

// addTool registers a read-only tool, and logs every call: who, which tool, what target and the result.
// The log never holds tokens or tool output.
func addTool[In, Out any](s *Server, name, title, description string, target func(In) string, handler func(context.Context, In) (Out, error)) {
	tool := &mcp.Tool{
		Name:        name,
		Description: description,
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, IdempotentHint: true, Title: title},
	}
	mcp.AddTool(s.mcp, tool, func(ctx context.Context, req *mcp.CallToolRequest, in In) (*mcp.CallToolResult, Out, error) {
		caller := ""
		if req.Extra != nil && req.Extra.TokenInfo != nil {
			caller = req.Extra.TokenInfo.UserID
		}

		out, err := handler(ctx, in)

		log := s.config.Logger.With("caller", caller, "tool", name, "target", target(in))
		var problem userError
		switch {
		case err == nil:
			log.Info("admin tool call", "result", "ok")
			return nil, out, nil
		case errors.As(err, &problem):
			log.Info("admin tool call", "result", "refused", "reason", problem.Error())
			var empty Out
			return nil, empty, problem
		default:
			log.Error("admin tool call", "result", "failed", "error", err)
			var empty Out
			return nil, empty, errors.New("something went wrong; see the server's log")
		}
	})
}

func noTarget[In any](In) string { return "" }

func (s *Server) addTools() {
	addTool(s, "list_apps", "List apps", "Lists registered apps and their return URLs.", noTarget, s.listApps)
	addTool(s, "list_orgs", "List orgs", "Lists customers, Healthspaces itself, and their email domains.", noTarget, s.listOrgs)
	addTool(s, "get_org", "Get org", "Gets one org and its provider connections.",
		func(in getOrgInput) string { return in.OrgID }, s.getOrg)
	addTool(s, "list_connections", "List connections", "Lists provider connections and their status. Secrets are never included.", noTarget, s.listConnections)
	addTool(s, "get_connection", "Get connection", "Gets one provider connection. Secrets are never included.",
		func(in getConnectionInput) string { return in.ConnectionID }, s.getConnection)
	addTool(s, "get_user", "Get user", "Finds a user in one app's Firebase project, by uid or by email.",
		func(in getUserInput) string {
			if in.UID != "" {
				return in.AppID + "/" + in.UID
			}
			return in.AppID + "/(by email)"
		}, s.getUser)
	addTool(s, "list_users", "List users", "Pages through the users in one app's Firebase project.",
		func(in listUsersInput) string { return in.AppID }, s.listUsers)
	addTool(s, "get_user_links", "Get user links", "Lists the provider identities linked to a user in one app's Firebase project.",
		func(in getUserLinksInput) string { return in.AppID + "/" + in.UID }, s.getUserLinks)
	addTool(s, "list_sign_in_events", "List sign-in events", "Lists recent sign-ins and refusals, newest first, with the reason for each refusal.", noTarget, s.listSignInEvents)
}

type noInput struct{}

// App is a registered app, as tools show it.
type App struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	ProjectID    string   `json:"project_id"`
	RedirectURIs []string `json:"redirect_uris"`
}

type listAppsOutput struct {
	Apps []App `json:"apps"`
}

func (s *Server) listApps(ctx context.Context, _ noInput) (listAppsOutput, error) {
	apps, err := s.config.Store.Apps(ctx)
	if err != nil {
		return listAppsOutput{}, err
	}
	out := make([]App, 0, len(apps))
	for _, app := range apps {
		out = append(out, App{ID: app.ID, Name: app.Name, ProjectID: app.ProjectID, RedirectURIs: orEmpty(app.RedirectURIs)})
	}
	slices.SortFunc(out, func(a, b App) int { return strings.Compare(a.ID, b.ID) })
	return listAppsOutput{Apps: out}, nil
}

// Org is an org, as tools show it.
type Org struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Domains []string `json:"domains"`
}

func toOrg(org broker.Org) Org {
	return Org{ID: org.ID, Name: org.Name, Domains: orEmpty(org.Domains)}
}

type listOrgsOutput struct {
	Orgs []Org `json:"orgs"`
}

func (s *Server) listOrgs(ctx context.Context, _ noInput) (listOrgsOutput, error) {
	orgs, err := s.config.Store.Orgs(ctx)
	if err != nil {
		return listOrgsOutput{}, err
	}
	out := make([]Org, 0, len(orgs))
	for _, org := range orgs {
		out = append(out, toOrg(org))
	}
	slices.SortFunc(out, func(a, b Org) int { return strings.Compare(a.ID, b.ID) })
	return listOrgsOutput{Orgs: out}, nil
}

// Connection is a provider connection, as tools show it. Keep secrets out of this type.
type Connection struct {
	ID               string         `json:"id"`
	OrgID            string         `json:"org_id"`
	Name             string         `json:"name"`
	Kind             connector.Kind `json:"kind"`
	Issuer           string         `json:"issuer"`
	ClientID         string         `json:"client_id"`
	TenantID         string         `json:"tenant_id,omitempty"`
	Enabled          bool           `json:"enabled"`
	ShowOnSignInPage bool           `json:"show_on_sign_in_page"`
}

func toConnection(c broker.Connection) Connection {
	return Connection{
		ID: c.ID, OrgID: c.OrgID, Name: c.Name, Kind: c.Kind, Issuer: c.Issuer, ClientID: c.ClientID,
		TenantID: c.TenantID, Enabled: c.Enabled, ShowOnSignInPage: c.ShowOnSignInPage,
	}
}

func toConnections(connections []broker.Connection) []Connection {
	out := make([]Connection, 0, len(connections))
	for _, connection := range connections {
		out = append(out, toConnection(connection))
	}
	slices.SortFunc(out, func(a, b Connection) int { return strings.Compare(a.ID, b.ID) })
	return out
}

type getOrgInput struct {
	OrgID string `json:"org_id" jsonschema:"the org's id"`
}

type getOrgOutput struct {
	Org         Org          `json:"org"`
	Connections []Connection `json:"connections"`
}

func (s *Server) getOrg(ctx context.Context, in getOrgInput) (getOrgOutput, error) {
	org, _, err := s.config.Store.Org(ctx, in.OrgID)
	if errors.Is(err, broker.ErrNotFound) {
		return getOrgOutput{}, userError("no org with that id")
	}
	if err != nil {
		return getOrgOutput{}, err
	}
	connections, err := s.config.Store.ConnectionsForOrg(ctx, in.OrgID)
	if err != nil {
		return getOrgOutput{}, err
	}
	return getOrgOutput{Org: toOrg(org), Connections: toConnections(connections)}, nil
}

type listConnectionsOutput struct {
	Connections []Connection `json:"connections"`
}

func (s *Server) listConnections(ctx context.Context, _ noInput) (listConnectionsOutput, error) {
	connections, err := s.config.Store.Connections(ctx)
	if err != nil {
		return listConnectionsOutput{}, err
	}
	return listConnectionsOutput{Connections: toConnections(connections)}, nil
}

type getConnectionInput struct {
	ConnectionID string `json:"connection_id" jsonschema:"the connection's id"`
}

type getConnectionOutput struct {
	Connection Connection `json:"connection"`
}

func (s *Server) getConnection(ctx context.Context, in getConnectionInput) (getConnectionOutput, error) {
	connection, _, err := s.config.Store.Connection(ctx, in.ConnectionID)
	if errors.Is(err, broker.ErrNotFound) {
		return getConnectionOutput{}, userError("no connection with that id")
	}
	if err != nil {
		return getConnectionOutput{}, err
	}
	return getConnectionOutput{Connection: toConnection(connection)}, nil
}

// User is a Firebase account, as tools show it. Everything is copied field by field, so that password
// hashes and anything new in the SDK's record stay out unless they're added here.
type User struct {
	UID           string         `json:"uid"`
	Email         string         `json:"email,omitempty"`
	DisplayName   string         `json:"display_name,omitempty"`
	Disabled      bool           `json:"disabled"`
	EmailVerified bool           `json:"email_verified"`
	ProviderIDs   []string       `json:"provider_ids"`
	CreatedAt     string         `json:"created_at,omitempty"`
	LastSignInAt  string         `json:"last_sign_in_at,omitempty"`
	Claims        map[string]any `json:"claims"`
	// HiddenClaims names the claims that exist but whose values aren't shown.
	HiddenClaims []string `json:"hidden_claims"`
}

func toUser(record *firebaseauth.UserRecord) User {
	user := User{
		UID:           record.UID,
		Email:         record.Email,
		DisplayName:   record.DisplayName,
		Disabled:      record.Disabled,
		EmailVerified: record.EmailVerified,
		ProviderIDs:   []string{},
		Claims:        map[string]any{},
		HiddenClaims:  []string{},
	}
	for _, provider := range record.ProviderUserInfo {
		user.ProviderIDs = append(user.ProviderIDs, provider.ProviderID)
	}
	if record.UserMetadata != nil {
		user.CreatedAt = millisToTime(record.UserMetadata.CreationTimestamp)
		user.LastSignInAt = millisToTime(record.UserMetadata.LastLogInTimestamp)
	}
	for name, value := range record.CustomClaims {
		if slices.Contains(visibleClaims, name) {
			user.Claims[name] = value
		} else {
			user.HiddenClaims = append(user.HiddenClaims, name)
		}
	}
	slices.Sort(user.HiddenClaims)
	return user
}

func millisToTime(millis int64) string {
	if millis == 0 {
		return ""
	}
	return time.UnixMilli(millis).UTC().Format(time.RFC3339)
}

// appClient returns the Admin SDK client for an app's project.
func (s *Server) appClient(ctx context.Context, appID string) (broker.App, *firebaseauth.Client, error) {
	app, err := s.config.Store.App(ctx, appID)
	if errors.Is(err, broker.ErrNotFound) {
		return broker.App{}, nil, userError("no app with that id")
	}
	if err != nil {
		return broker.App{}, nil, err
	}
	client, ok := s.config.Auth[app.ProjectID]
	if !ok {
		return broker.App{}, nil, fmt.Errorf("no auth client for project %s", app.ProjectID)
	}
	return app, client, nil
}

type getUserInput struct {
	AppID string `json:"app_id" jsonschema:"the app whose Firebase project to search"`
	UID   string `json:"uid,omitempty" jsonschema:"the user's uid; give this or email, not both"`
	Email string `json:"email,omitempty" jsonschema:"the user's email address; give this or uid, not both"`
}

type getUserOutput struct {
	User User `json:"user"`
}

func (s *Server) getUser(ctx context.Context, in getUserInput) (getUserOutput, error) {
	if (in.UID == "") == (in.Email == "") {
		return getUserOutput{}, userError("give exactly one of uid or email")
	}
	if len(in.UID) > maxUIDLength {
		return getUserOutput{}, userError("that uid is too long")
	}
	if in.Email != "" {
		if _, ok := connector.EmailDomain(in.Email); !ok {
			return getUserOutput{}, userError("that isn't an email address")
		}
	}

	_, client, err := s.appClient(ctx, in.AppID)
	if err != nil {
		return getUserOutput{}, err
	}

	var record *firebaseauth.UserRecord
	if in.UID != "" {
		record, err = client.GetUser(ctx, in.UID)
	} else {
		record, err = client.GetUserByEmail(ctx, in.Email)
	}
	if firebaseauth.IsUserNotFound(err) {
		return getUserOutput{}, userError("no user found in that app's project")
	}
	if err != nil {
		return getUserOutput{}, err
	}
	return getUserOutput{User: toUser(record)}, nil
}

type listUsersInput struct {
	AppID     string `json:"app_id" jsonschema:"the app whose Firebase project to list"`
	Limit     int    `json:"limit,omitempty" jsonschema:"how many users to return, from 1 to 100; the default is 25"`
	PageToken string `json:"page_token,omitempty" jsonschema:"next_page_token from the previous page"`
}

type listUsersOutput struct {
	Users         []User `json:"users"`
	NextPageToken string `json:"next_page_token,omitempty"`
}

func checkLimit(limit int) (int, error) {
	if limit == 0 {
		return defaultLimit, nil
	}
	if limit < 1 || limit > maxLimit {
		return 0, userError(fmt.Sprintf("limit must be from 1 to %d", maxLimit))
	}
	return limit, nil
}

func (s *Server) listUsers(ctx context.Context, in listUsersInput) (listUsersOutput, error) {
	limit, err := checkLimit(in.Limit)
	if err != nil {
		return listUsersOutput{}, err
	}
	_, client, err := s.appClient(ctx, in.AppID)
	if err != nil {
		return listUsersOutput{}, err
	}

	var records []*firebaseauth.ExportedUserRecord
	next, err := iterator.NewPager(client.Users(ctx, ""), limit, in.PageToken).NextPage(&records)
	if err != nil {
		if in.PageToken != "" {
			return listUsersOutput{}, userError("that page_token isn't valid")
		}
		return listUsersOutput{}, err
	}

	users := make([]User, 0, len(records))
	for _, record := range records {
		users = append(users, toUser(record.UserRecord))
	}
	return listUsersOutput{Users: users, NextPageToken: next}, nil
}

type getUserLinksInput struct {
	AppID string `json:"app_id" jsonschema:"the app whose Firebase project the user is in"`
	UID   string `json:"uid" jsonschema:"the user's uid"`
}

// UserLink is a provider identity linked to a user.
type UserLink struct {
	ConnectionID string `json:"connection_id"`
	Subject      string `json:"subject"`
	CreatedAt    string `json:"created_at,omitempty"`
}

type getUserLinksOutput struct {
	Links []UserLink `json:"links"`
}

func (s *Server) getUserLinks(ctx context.Context, in getUserLinksInput) (getUserLinksOutput, error) {
	app, _, err := s.appClient(ctx, in.AppID)
	if err != nil {
		return getUserLinksOutput{}, err
	}
	links, err := s.config.Store.LinksForUser(ctx, app.ProjectID, in.UID)
	if err != nil {
		return getUserLinksOutput{}, err
	}
	out := make([]UserLink, 0, len(links))
	for _, link := range links {
		out = append(out, UserLink{ConnectionID: link.ConnectionID, Subject: link.Subject, CreatedAt: formatTime(link.CreatedAt)})
	}
	slices.SortFunc(out, func(a, b UserLink) int { return strings.Compare(a.ConnectionID, b.ConnectionID) })
	return getUserLinksOutput{Links: out}, nil
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

type listSignInEventsInput struct {
	Limit int `json:"limit,omitempty" jsonschema:"how many events to return, from 1 to 100; the default is 25"`
}

// SignInEvent is a sign-in or refusal, as tools show it.
type SignInEvent struct {
	Time         string `json:"time"`
	Outcome      string `json:"outcome"`
	Reason       string `json:"reason,omitempty"`
	AppID        string `json:"app_id,omitempty"`
	OrgID        string `json:"org_id,omitempty"`
	ConnectionID string `json:"connection_id,omitempty"`
	Subject      string `json:"subject,omitempty"`
	Email        string `json:"email,omitempty"`
	UID          string `json:"uid,omitempty"`
}

type listSignInEventsOutput struct {
	Events []SignInEvent `json:"events"`
}

func (s *Server) listSignInEvents(ctx context.Context, in listSignInEventsInput) (listSignInEventsOutput, error) {
	limit, err := checkLimit(in.Limit)
	if err != nil {
		return listSignInEventsOutput{}, err
	}
	events, err := s.config.Store.RecentEvents(ctx, limit)
	if err != nil {
		return listSignInEventsOutput{}, err
	}
	out := make([]SignInEvent, 0, len(events))
	for _, event := range events {
		out = append(out, SignInEvent{
			Time: formatTime(event.Time), Outcome: event.Outcome, Reason: event.Reason, AppID: event.AppID,
			OrgID: event.OrgID, ConnectionID: event.ConnectionID, Subject: event.Subject, Email: event.Email, UID: event.UID,
		})
	}
	return listSignInEventsOutput{Events: out}, nil
}

func orEmpty(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}
