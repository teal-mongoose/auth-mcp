package ratelimit

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time           { return c.t }
func (c *clock) advance(d time.Duration)  { c.t = c.t.Add(d) }
func newClock() *clock                    { return &clock{t: time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)} }
func tenPerMinute(burst int) Rule         { return Rule{Name: "test", Rate: PerMinute(10), Burst: burst} }
func allowed(l *Limiter, key string) bool { return l.Allow(key).OK }
func countAllowed(l *Limiter, key string, n int) int {
	ok := 0
	for range n {
		if allowed(l, key) {
			ok++
		}
	}
	return ok
}

func TestBurstThenRefuseThenRefill(t *testing.T) {
	c := newClock()
	l := New(tenPerMinute(3), 0, c.now)

	if got := countAllowed(l, "a", 5); got != 3 {
		t.Fatalf("allowed %d of 5 at once, want the burst of 3", got)
	}
	d := l.Allow("a")
	if d.OK || d.RetryAfter <= 0 || d.RetryAfter > 6*time.Second {
		t.Fatalf("over the limit: %+v, want a refusal with a wait of up to 6s", d)
	}

	c.advance(6 * time.Second)
	if !allowed(l, "a") {
		t.Fatal("one request should be allowed after 6s at 10 a minute")
	}
	if allowed(l, "a") {
		t.Fatal("only one should have refilled")
	}
}

func TestClientsHaveTheirOwnBuckets(t *testing.T) {
	l := New(tenPerMinute(2), 0, newClock().now)
	countAllowed(l, "a", 5)
	if !allowed(l, "b") {
		t.Fatal("another client was limited by the first one's requests")
	}
}

func TestSharedRuleCountsEveryone(t *testing.T) {
	l := New(Rule{Name: "all", Rate: PerMinute(10), Burst: 2, Shared: true}, 0, newClock().now)
	allowed(l, "a")
	allowed(l, "b")
	if allowed(l, "c") {
		t.Fatal("a shared rule let a third client through a burst of 2")
	}
}

func TestAFullTableMakesRoomRatherThanLockingOut(t *testing.T) {
	l := New(tenPerMinute(1), 2, newClock().now)
	allowed(l, "a")
	allowed(l, "b")
	// The table is full. New clients must still get their own buckets, or filling the table with junk
	// would lock out everyone new.
	for _, key := range []string{"c", "d", "e"} {
		if !allowed(l, key) {
			t.Fatalf("new client %s was refused because the table was full", key)
		}
	}
	if len(l.clients) > 2 {
		t.Fatalf("the table grew to %d, past its limit of 2", len(l.clients))
	}
}

func TestLogsHaveAnOverallBudget(t *testing.T) {
	l := New(tenPerMinute(1), 0, newClock().now)
	logged := 0
	for i := range 100 {
		key := string(rune('A' + i))
		allowed(l, key)
		if l.Allow(key).Log {
			logged++
		}
	}
	if logged != logBudget.burst {
		t.Fatalf("logged %d refusals from 100 clients at once, want the budget of %d", logged, logBudget.burst)
	}
}

func TestARefusalGivesBackWhatOtherLimitersTook(t *testing.T) {
	c := newClock()
	perClient := New(tenPerMinute(3), 0, c.now)
	shared := New(Rule{Name: "all", Rate: PerMinute(10), Burst: 1, Shared: true}, 0, c.now)
	h := Middleware(http.NotFoundHandler(), Config{
		ClientKey: RemoteAddrKey,
		Limiters:  func(*http.Request) []*Limiter { return []*Limiter{perClient, shared} },
	})
	// Someone else empties the shared bucket.
	allowed(shared, "")
	// Our client retries while it's empty. Its own allowance mustn't be spent on refused requests.
	for range 5 {
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/x", nil))
	}
	if got := countAllowed(perClient, RemoteAddrKey(httptest.NewRequest(http.MethodGet, "/x", nil)), 3); got != 3 {
		t.Fatalf("the client had %d of its 3 left after refused retries", got)
	}
}

func TestIdleClientsAreForgotten(t *testing.T) {
	c := newClock()
	l := New(tenPerMinute(1), 1, c.now)
	allowed(l, "a")
	c.advance(idleAfter + time.Second)
	allowed(l, "b")
	if _, ok := l.clients["a"]; ok {
		t.Fatal("an idle client wasn't swept")
	}
	if _, ok := l.clients["b"]; !ok {
		t.Fatal("after the sweep, a new client should have its own bucket")
	}
}

func TestRefusalsAreLoggedOncePerMinute(t *testing.T) {
	c := newClock()
	l := New(tenPerMinute(1), 0, c.now)
	allowed(l, "a")
	if d := l.Allow("a"); !d.Log {
		t.Fatal("the first refusal should be logged")
	}
	if d := l.Allow("a"); d.Log {
		t.Fatal("a second refusal within a minute was logged")
	}
	c.advance(logEvery)
	allowed(l, "a")
	if d := l.Allow("a"); d.OK || !d.Log {
		t.Fatalf("a refusal a minute later: %+v, want it logged again", d)
	}
}

func TestMiddlewareRefusesWith429(t *testing.T) {
	var logs bytes.Buffer
	l := New(tenPerMinute(1), 0, newClock().now)
	reached := 0
	h := Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached++ }), Config{
		ClientKey: RemoteAddrKey,
		Limiters:  func(*http.Request) []*Limiter { return []*Limiter{l} },
		Logger:    slog.New(slog.NewTextHandler(&logs, nil)),
	})

	for i := range 2 {
		res := httptest.NewRecorder()
		h.ServeHTTP(res, httptest.NewRequest(http.MethodGet, "/x", nil))
		if i == 0 && res.Code != http.StatusOK {
			t.Fatalf("first request: %d", res.Code)
		}
		if i == 1 {
			if res.Code != http.StatusTooManyRequests {
				t.Fatalf("second request: %d, want 429", res.Code)
			}
			if res.Header().Get("Retry-After") != "6" || res.Header().Get("Cache-Control") != "no-store" ||
				res.Header().Get("X-Content-Type-Options") != "nosniff" {
				t.Fatalf("headers: %v", res.Header())
			}
		}
	}
	if reached != 1 {
		t.Fatalf("the handler ran %d times, want 1", reached)
	}
	if !strings.Contains(logs.String(), "rate limited") || !strings.Contains(logs.String(), "rule=test") {
		t.Fatalf("logs = %q", logs.String())
	}
}

func TestMiddlewareRefusedRequestsDontUseTheSharedAllowance(t *testing.T) {
	client := New(tenPerMinute(1), 0, newClock().now)
	shared := New(Rule{Name: "all", Rate: PerMinute(10), Burst: 5, Shared: true}, 0, newClock().now)
	h := Middleware(http.NotFoundHandler(), Config{
		ClientKey: RemoteAddrKey,
		Limiters:  func(*http.Request) []*Limiter { return []*Limiter{client, shared} },
	})
	for range 10 {
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/x", nil))
	}
	// One client's refused requests mustn't use up everyone's shared allowance.
	if got := countAllowed(shared, "", 10); got != 4 {
		t.Fatalf("shared bucket had %d left, want 4", got)
	}
}

func TestRefusalsAreReadableByTheCallingPage(t *testing.T) {
	l := New(tenPerMinute(1), 0, newClock().now)
	h := Middleware(http.NotFoundHandler(), Config{
		ClientKey: RemoteAddrKey,
		Limiters:  func(*http.Request) []*Limiter { return []*Limiter{l} },
	})
	var res *httptest.ResponseRecorder
	for range 2 {
		r := httptest.NewRequest(http.MethodPost, "/token", nil)
		r.Header.Set("Origin", "http://localhost:8711")
		res = httptest.NewRecorder()
		h.ServeHTTP(res, r)
	}
	if res.Code != http.StatusTooManyRequests {
		t.Fatalf("got %d", res.Code)
	}
	if res.Header().Get("Access-Control-Allow-Origin") != "http://localhost:8711" ||
		res.Header().Get("Access-Control-Expose-Headers") != "Retry-After" ||
		res.Header().Get("Access-Control-Allow-Credentials") != "" {
		t.Fatalf("headers: %v", res.Header())
	}
}

func TestNoLimitersPassesThrough(t *testing.T) {
	h := Middleware(http.NotFoundHandler(), Config{
		ClientKey: func(*http.Request) string { t.Fatal("ClientKey called with no limiters"); return "" },
		Limiters:  func(*http.Request) []*Limiter { return nil },
	})
	res := httptest.NewRecorder()
	h.ServeHTTP(res, httptest.NewRequest(http.MethodGet, "/x", nil))
	if res.Code != http.StatusNotFound {
		t.Fatalf("got %d", res.Code)
	}
}

func TestRightmostForwardedKey(t *testing.T) {
	cases := []struct {
		name    string
		headers []string
		want    string
	}{
		{"none", nil, "192.0.2.1"},
		{"one entry", []string{"203.0.113.7"}, "203.0.113.7"},
		{"client-supplied entries are ignored", []string{"198.51.100.1, 10.0.0.1 , 203.0.113.7"}, "203.0.113.7"},
		{"several headers: the last header's last entry", []string{"198.51.100.1", "203.0.113.7"}, "203.0.113.7"},
		{"garbage", []string{"203.0.113.7, not-an-ip"}, "unparseable"},
		{"empty last entry falls back", []string{"203.0.113.7, "}, "192.0.2.1"},
		{"IPv6 grouped by /48", []string{"2001:db8:1:2:aaaa::1"}, "2001:db8:1::/48"},
		{"IPv4-mapped IPv6", []string{"::ffff:203.0.113.7"}, "203.0.113.7"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.RemoteAddr = "192.0.2.1:1234"
			for _, h := range tc.headers {
				r.Header.Add("X-Forwarded-For", h)
			}
			if got := RightmostForwardedKey(r); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestIPv6SiteSharesABucket(t *testing.T) {
	l := New(tenPerMinute(1), 0, newClock().now)
	if !allowed(l, normalize("2001:db8:1:2::1")) {
		t.Fatal("first")
	}
	// Another /64 in the same /48, as one home or office can use.
	if allowed(l, normalize("2001:db8:1:ff:ffff::9")) {
		t.Fatal("another subnet in the same /48 got a fresh bucket")
	}
	if !allowed(l, normalize("2001:db8:2::1")) {
		t.Fatal("another /48 should have its own bucket")
	}
}
