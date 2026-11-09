// Package ratelimit limits how often clients can call the server. Limits are kept in memory, per server
// instance, so with several instances a client gets up to that many times the limit. That's enough to
// stop one client hammering the sign-in flow, guessing email domains, or running up Firestore costs.
package ratelimit

import (
	"log/slog"
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

const (
	// idleAfter is how long a client goes unseen before it's forgotten. By then its bucket has refilled
	// for any rule here, so forgetting it changes nothing.
	idleAfter  = 10 * time.Minute
	sweepEvery = time.Minute
	// logEvery limits refusal logs to one per client and rule in this time.
	logEvery = time.Minute
	// DefaultMaxClients bounds memory. Past it, an arbitrary client is forgotten to make room, so a new
	// client still gets its own bucket. A forgotten client just starts again with a full bucket.
	DefaultMaxClients = 50_000
)

// logBudget limits each limiter's refusal logs across all clients, so many clients can't flood the logs.
var logBudget = struct {
	rate  rate.Limit
	burst int
}{rate: 2, burst: 10}

// Rule is a token bucket: Burst requests at once, refilling at Rate per second.
type Rule struct {
	Name  string
	Rate  rate.Limit
	Burst int
	// Shared makes one bucket for all clients, as a backstop on the instance's total.
	Shared bool
}

// PerMinute is a Rate of n requests a minute.
func PerMinute(n int) rate.Limit {
	return rate.Limit(float64(n) / 60)
}

// Limiter applies one Rule to every client.
type Limiter struct {
	rule       Rule
	maxClients int
	now        func() time.Time

	mu      sync.Mutex
	clients map[string]*client
	sweepAt time.Time
	logs    *rate.Limiter
}

type client struct {
	bucket   *rate.Limiter
	lastSeen time.Time
	loggedAt time.Time
}

// New returns a Limiter. maxClients defaults to DefaultMaxClients, and now to time.Now.
func New(rule Rule, maxClients int, now func() time.Time) *Limiter {
	if maxClients <= 0 {
		maxClients = DefaultMaxClients
	}
	if now == nil {
		now = time.Now
	}
	return &Limiter{
		rule:       rule,
		maxClients: maxClients,
		now:        now,
		clients:    map[string]*client{},
		logs:       rate.NewLimiter(logBudget.rate, logBudget.burst),
	}
}

// Decision is the result of Allow.
type Decision struct {
	OK bool
	// RetryAfter is how long until a request would be allowed, when OK is false.
	RetryAfter time.Duration
	// Log says this refusal is worth logging: the first for this client and rule in a while, and within
	// the limiter's overall log budget.
	Log bool

	undo func()
}

// Allow takes one request from key's bucket, if there's one left.
func (l *Limiter) Allow(key string) Decision {
	if l.rule.Shared {
		key = ""
	}
	now := l.now()

	l.mu.Lock()
	defer l.mu.Unlock()

	if !now.Before(l.sweepAt) {
		for k, c := range l.clients {
			if now.Sub(c.lastSeen) > idleAfter {
				delete(l.clients, k)
			}
		}
		l.sweepAt = now.Add(sweepEvery)
	}

	c, ok := l.clients[key]
	if !ok {
		if len(l.clients) >= l.maxClients {
			for k := range l.clients {
				delete(l.clients, k)
				break
			}
		}
		c = &client{bucket: rate.NewLimiter(l.rule.Rate, l.rule.Burst)}
		l.clients[key] = c
	}
	c.lastSeen = now

	reservation := c.bucket.ReserveN(now, 1)
	if delay := reservation.DelayFrom(now); reservation.OK() && delay == 0 {
		return Decision{OK: true, undo: func() { reservation.CancelAt(l.now()) }}
	}
	// A reservation is only not OK if the bucket can never hold one request, which no rule here does.
	wait := time.Hour
	if reservation.OK() {
		wait = reservation.DelayFrom(now)
	}
	reservation.CancelAt(now)

	decision := Decision{RetryAfter: wait}
	if now.Sub(c.loggedAt) >= logEvery && l.logs.AllowN(now, 1) {
		c.loggedAt = now
		decision.Log = true
	}
	return decision
}

// Config says how Middleware limits requests.
type Config struct {
	// ClientKey identifies the client a request comes from.
	ClientKey func(*http.Request) string
	// Limiters returns the limiters that apply to a request. All must allow it. If one refuses, the
	// requests taken from the others are given back, so a refused request costs nothing.
	Limiters func(*http.Request) []*Limiter
	// Logger defaults to slog.Default.
	Logger *slog.Logger
}

// Middleware refuses requests over their limits with 429 Too Many Requests.
func Middleware(next http.Handler, cfg Config) http.Handler {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		limiters := cfg.Limiters(r)
		if len(limiters) > 0 {
			key := cfg.ClientKey(r)
			taken := make([]Decision, 0, len(limiters))
			for _, l := range limiters {
				d := l.Allow(key)
				if d.OK {
					taken = append(taken, d)
					continue
				}
				for _, t := range taken {
					t.undo()
				}
				if d.Log {
					logger.Warn("rate limited", "rule", l.rule.Name, "client", key, "path", r.URL.Path)
				}
				refuse(w, r, d.RetryAfter)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func refuse(w http.ResponseWriter, r *http.Request, retryAfter time.Duration) {
	seconds := 3600
	if retryAfter < time.Hour {
		seconds = max(int(math.Ceil(retryAfter.Seconds())), 1)
	}
	h := w.Header()
	h.Set("Retry-After", strconv.Itoa(seconds))
	h.Set("Cache-Control", "no-store")
	h.Set("Content-Type", "text/plain; charset=utf-8")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
	// Let a calling page read the refusal, rather than see an opaque network error. The body is the same
	// fixed text for everyone, and no credentials are allowed, so any origin may read it.
	if origin := r.Header.Get("Origin"); origin != "" {
		h.Set("Access-Control-Allow-Origin", origin)
		h.Set("Access-Control-Expose-Headers", "Retry-After")
		h.Add("Vary", "Origin")
	}
	w.WriteHeader(http.StatusTooManyRequests)
	_, _ = w.Write([]byte("Too many requests. Wait a moment, then try again.\n"))
}

// RemoteAddrKey identifies clients by the address that connected, for a server with no proxy in front.
func RemoteAddrKey(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return normalize(host)
}

// RightmostForwardedKey identifies clients by the last X-Forwarded-For entry, which is the address the
// proxy in front of the server saw, as on Cloud Run. Entries to its left come from the client and can be
// anything, so they're ignored. It assumes exactly one proxy: with a load balancer in front as well, the
// last entry would be the load balancer, and every client would share one bucket.
func RightmostForwardedKey(r *http.Request) string {
	values := r.Header.Values("X-Forwarded-For")
	if len(values) == 0 {
		return RemoteAddrKey(r)
	}
	entries := strings.Split(values[len(values)-1], ",")
	last := strings.TrimSpace(entries[len(entries)-1])
	if last == "" {
		return RemoteAddrKey(r)
	}
	return normalize(last)
}

// normalize groups IPv6 addresses by their /48, the most a single site is usually given, so that one
// person can't get fresh buckets by cycling through their own addresses or subnets. It's the IPv6 version
// of everyone behind one office's IPv4 address sharing a limit. Anything unparseable shares one key.
func normalize(host string) string {
	ip := net.ParseIP(host)
	if ip == nil {
		return "unparseable"
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.Mask(net.CIDRMask(48, 128)).String() + "/48"
}
