package broker

import (
	"context"
	"errors"
	"time"

	"cloud.google.com/go/firestore"
	"google.golang.org/api/iterator"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/teal-mongoose/auth-mcp/internal/connector"
)

const (
	collectionOrgs        = "orgs"
	collectionApps        = "apps"
	collectionConnections = "connections"
	collectionLinks       = "links"
	collectionPending     = "pending_signins"
	collectionCodes       = "codes"
	collectionEvents      = "sign_in_events"
)

// ErrNotFound means the document doesn't exist, or has already been consumed.
var ErrNotFound = errors.New("not found")

// App is a registered application, and the Firebase project its logins belong to.
type App struct {
	ID           string   `firestore:"-"`
	Name         string   `firestore:"name"`
	ProjectID    string   `firestore:"project_id"`
	RedirectURIs []string `firestore:"redirect_uris"`
}

// Org is a customer, or Healthspaces itself. Email in its domains routes to its connections, and
// Google and Okta connections accept only these domains.
type Org struct {
	ID      string   `firestore:"-"`
	Name    string   `firestore:"name"`
	Domains []string `firestore:"domains"`
}

// Connection is one provider setup, belonging to one org. Its client secret is never stored here.
type Connection struct {
	ID       string         `firestore:"-"`
	OrgID    string         `firestore:"org_id"`
	Name     string         `firestore:"name"`
	Kind     connector.Kind `firestore:"kind"`
	Issuer   string         `firestore:"issuer"`
	ClientID string         `firestore:"client_id"`
	TenantID string         `firestore:"tenant_id"`
	Enabled  bool           `firestore:"enabled"`
	// ShowOnSignInPage lists it on the sign-in page, for staff. Customers are found by email domain
	// instead, so the page doesn't reveal who they are.
	ShowOnSignInPage bool `firestore:"show_on_sign_in_page"`
}

// Link ties a person at a connection to a Firebase uid in one project.
type Link struct {
	ConnectionID string    `firestore:"connection_id"`
	Subject      string    `firestore:"subject"`
	ProjectID    string    `firestore:"project_id"`
	UID          string    `firestore:"uid"`
	CreatedAt    time.Time `firestore:"created_at"`
}

// pendingSignIn is held between sending someone to a provider and them coming back. Its document id
// is a hash of the state, so reading the database doesn't reveal a usable state.
type pendingSignIn struct {
	AppID        string    `firestore:"app_id"`
	ConnectionID string    `firestore:"connection_id"`
	RedirectURI  string    `firestore:"redirect_uri"`
	AppState     string    `firestore:"app_state"`
	Challenge    string    `firestore:"code_challenge"`
	Nonce        string    `firestore:"nonce"`
	Verifier     string    `firestore:"verifier"`
	BindingHash  string    `firestore:"binding_hash"`
	ExpiresAt    time.Time `firestore:"expires_at"`
}

// authCode is the single-use code an app exchanges for a login. Its document id is a hash of the code.
type authCode struct {
	AppID       string    `firestore:"app_id"`
	ProjectID   string    `firestore:"project_id"`
	UID         string    `firestore:"uid"`
	OrgID       string    `firestore:"org_id"`
	RedirectURI string    `firestore:"redirect_uri"`
	Challenge   string    `firestore:"code_challenge"`
	ExpiresAt   time.Time `firestore:"expires_at"`
}

// Event records a sign-in or refusal for admins. It never holds a token or code.
type Event struct {
	Time         time.Time `firestore:"time"`
	Outcome      string    `firestore:"outcome"`
	Reason       string    `firestore:"reason"`
	AppID        string    `firestore:"app_id"`
	OrgID        string    `firestore:"org_id"`
	ConnectionID string    `firestore:"connection_id"`
	Subject      string    `firestore:"subject"`
	Email        string    `firestore:"email"`
	UID          string    `firestore:"uid"`
}

// Event outcomes.
const (
	OutcomeSignedIn = "signed_in"
	OutcomeRefused  = "refused"
)

// Store holds the broker's data in Firestore.
type Store struct {
	fs *firestore.Client
}

// NewStore returns a Store using fs.
func NewStore(fs *firestore.Client) *Store {
	return &Store{fs: fs}
}

func getDoc[T any](ctx context.Context, s *Store, collection, id string) (T, *firestore.DocumentSnapshot, error) {
	var out T
	if id == "" {
		return out, nil, ErrNotFound
	}
	snap, err := s.fs.Collection(collection).Doc(id).Get(ctx)
	if status.Code(err) == codes.NotFound {
		return out, nil, ErrNotFound
	}
	if err != nil {
		return out, nil, err
	}
	if err := snap.DataTo(&out); err != nil {
		return out, nil, err
	}
	return out, snap, nil
}

// consume reads and deletes a document in one transaction, so that of any number of concurrent
// callers, exactly one gets it.
func consume[T any](ctx context.Context, s *Store, collection, id string) (T, error) {
	var out T
	ref := s.fs.Collection(collection).Doc(id)
	err := s.fs.RunTransaction(ctx, func(_ context.Context, tx *firestore.Transaction) error {
		snap, err := tx.Get(ref)
		if status.Code(err) == codes.NotFound {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if err := snap.DataTo(&out); err != nil {
			return err
		}
		return tx.Delete(ref)
	})
	if errors.Is(err, ErrNotFound) {
		var empty T
		return empty, ErrNotFound
	}
	return out, err
}

// Org returns an org, and when it last changed.
func (s *Store) Org(ctx context.Context, id string) (Org, time.Time, error) {
	org, snap, err := getDoc[Org](ctx, s, collectionOrgs, id)
	org.ID = id
	if err != nil {
		return org, time.Time{}, err
	}
	return org, snap.UpdateTime, nil
}

// OrgsForDomain returns the orgs claiming an email domain. More than one is a configuration problem,
// which callers must refuse rather than guess at.
func (s *Store) OrgsForDomain(ctx context.Context, domain string) ([]Org, error) {
	snaps, err := s.fs.Collection(collectionOrgs).Where("domains", "array-contains", domain).Documents(ctx).GetAll()
	if err != nil {
		return nil, err
	}
	orgs := make([]Org, 0, len(snaps))
	for _, snap := range snaps {
		var org Org
		if err := snap.DataTo(&org); err != nil {
			return nil, err
		}
		org.ID = snap.Ref.ID
		orgs = append(orgs, org)
	}
	return orgs, nil
}

// PutOrg saves an org.
func (s *Store) PutOrg(ctx context.Context, org Org) error {
	_, err := s.fs.Collection(collectionOrgs).Doc(org.ID).Set(ctx, org)
	return err
}

// App returns a registered app.
func (s *Store) App(ctx context.Context, id string) (App, error) {
	app, _, err := getDoc[App](ctx, s, collectionApps, id)
	app.ID = id
	return app, err
}

// PutApp saves an app.
func (s *Store) PutApp(ctx context.Context, app App) error {
	_, err := s.fs.Collection(collectionApps).Doc(app.ID).Set(ctx, app)
	return err
}

// Connection returns a connection, and when it last changed.
func (s *Store) Connection(ctx context.Context, id string) (Connection, time.Time, error) {
	connection, snap, err := getDoc[Connection](ctx, s, collectionConnections, id)
	connection.ID = id
	if err != nil {
		return connection, time.Time{}, err
	}
	return connection, snap.UpdateTime, nil
}

// Connections returns every connection.
func (s *Store) Connections(ctx context.Context) ([]Connection, error) {
	var connections []Connection
	iter := s.fs.Collection(collectionConnections).Documents(ctx)
	defer iter.Stop()
	for {
		snap, err := iter.Next()
		if errors.Is(err, iterator.Done) {
			return connections, nil
		}
		if err != nil {
			return nil, err
		}
		var connection Connection
		if err := snap.DataTo(&connection); err != nil {
			return nil, err
		}
		connection.ID = snap.Ref.ID
		connections = append(connections, connection)
	}
}

// ConnectionsForOrg returns an org's connections.
func (s *Store) ConnectionsForOrg(ctx context.Context, orgID string) ([]Connection, error) {
	snaps, err := s.fs.Collection(collectionConnections).Where("org_id", "==", orgID).Documents(ctx).GetAll()
	if err != nil {
		return nil, err
	}
	connections := make([]Connection, 0, len(snaps))
	for _, snap := range snaps {
		var connection Connection
		if err := snap.DataTo(&connection); err != nil {
			return nil, err
		}
		connection.ID = snap.Ref.ID
		connections = append(connections, connection)
	}
	return connections, nil
}

// PutConnection saves a connection.
func (s *Store) PutConnection(ctx context.Context, connection Connection) error {
	_, err := s.fs.Collection(collectionConnections).Doc(connection.ID).Set(ctx, connection)
	return err
}

func linkID(connectionID, subject, projectID string) string {
	return hash(connectionID + "\x00" + subject + "\x00" + projectID)
}

// LinkedUID returns the uid linked to this person in this project.
func (s *Store) LinkedUID(ctx context.Context, connectionID, subject, projectID string) (string, error) {
	link, _, err := getDoc[Link](ctx, s, collectionLinks, linkID(connectionID, subject, projectID))
	return link.UID, err
}

// PutLink saves a link.
func (s *Store) PutLink(ctx context.Context, link Link) error {
	_, err := s.fs.Collection(collectionLinks).Doc(linkID(link.ConnectionID, link.Subject, link.ProjectID)).Set(ctx, link)
	return err
}

// ClearLinks deletes every link. It's for reseeding.
func (s *Store) ClearLinks(ctx context.Context) error {
	iter := s.fs.Collection(collectionLinks).Documents(ctx)
	defer iter.Stop()
	for {
		snap, err := iter.Next()
		if errors.Is(err, iterator.Done) {
			return nil
		}
		if err != nil {
			return err
		}
		if _, err := snap.Ref.Delete(ctx); err != nil {
			return err
		}
	}
}

func (s *Store) putPending(ctx context.Context, state string, pending pendingSignIn) error {
	_, err := s.fs.Collection(collectionPending).Doc(hash(state)).Set(ctx, pending)
	return err
}

func (s *Store) consumePending(ctx context.Context, state string) (pendingSignIn, error) {
	return consume[pendingSignIn](ctx, s, collectionPending, hash(state))
}

func (s *Store) putCode(ctx context.Context, code string, doc authCode) error {
	_, err := s.fs.Collection(collectionCodes).Doc(hash(code)).Set(ctx, doc)
	return err
}

func (s *Store) consumeCode(ctx context.Context, code string) (authCode, error) {
	return consume[authCode](ctx, s, collectionCodes, hash(code))
}

func (s *Store) addEvent(ctx context.Context, event Event) error {
	_, _, err := s.fs.Collection(collectionEvents).Add(ctx, event)
	return err
}

// RecentEvents returns the latest events, newest first.
func (s *Store) RecentEvents(ctx context.Context, limit int) ([]Event, error) {
	var events []Event
	iter := s.fs.Collection(collectionEvents).OrderBy("time", firestore.Desc).Limit(limit).Documents(ctx)
	defer iter.Stop()
	for {
		snap, err := iter.Next()
		if errors.Is(err, iterator.Done) {
			return events, nil
		}
		if err != nil {
			return nil, err
		}
		var event Event
		if err := snap.DataTo(&event); err != nil {
			return nil, err
		}
		events = append(events, event)
	}
}
