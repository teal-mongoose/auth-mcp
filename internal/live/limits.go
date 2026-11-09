package live

import (
	"net/http"
	"strings"
	"time"

	"github.com/teal-mongoose/auth-mcp/internal/ratelimit"
)

// Rate limits, per client and server instance. A client is an IPv4 address or an IPv6 /48. A sign-in is
// one /authorize, one /callback and one /token, so these allow about 30 sign-ins a minute from one
// address, such as an office behind one NAT, after a burst of 20. Typing an email to find your org is
// limited harder, because it's how someone would test domains to learn who the customers are.
var (
	limitEmailRouting = ratelimit.Rule{Name: "email routing", Rate: ratelimit.PerMinute(20), Burst: 10}
	limitSignIn       = ratelimit.Rule{Name: "sign-in", Rate: ratelimit.PerMinute(60), Burst: 20}
	limitToken        = ratelimit.Rule{Name: "token", Rate: ratelimit.PerMinute(60), Burst: 20}
	limitAdmin        = ratelimit.Rule{Name: "admin", Rate: ratelimit.PerMinute(120), Burst: 40}
	// Starting a sign-in and coming back from the provider both write to Firestore. This caps an
	// instance's total from everyone together, to bound cost. It's set far above real use, so that it
	// takes many separate networks to reach, and can't be used by a few clients to block everyone's
	// sign-in.
	limitAllSignInWrites = ratelimit.Rule{Name: "sign-in writes, all clients", Rate: 100, Burst: 500, Shared: true}
)

// withRateLimits limits the broker's and admin server's endpoints. Behind a proxy, as on Cloud Run,
// clients are told apart by the address the proxy saw; on this machine, by the connecting address.
func withRateLimits(next http.Handler, behindProxy bool) http.Handler {
	return rateLimited(next, behindProxy, time.Now)
}

func rateLimited(next http.Handler, behindProxy bool, now func() time.Time) http.Handler {
	emailRouting := ratelimit.New(limitEmailRouting, 0, now)
	signIn := ratelimit.New(limitSignIn, 0, now)
	token := ratelimit.New(limitToken, 0, now)
	adminCalls := ratelimit.New(limitAdmin, 0, now)
	allWrites := ratelimit.New(limitAllSignInWrites, 0, now)

	key := ratelimit.RemoteAddrKey
	if behindProxy {
		key = ratelimit.RightmostForwardedKey
	}
	return ratelimit.Middleware(next, ratelimit.Config{
		ClientKey: key,
		Limiters: func(r *http.Request) []*ratelimit.Limiter {
			// CORS preflights do no work, and refusing them would hide the real response from the page.
			if r.Method == http.MethodOptions {
				return nil
			}
			path := r.URL.Path
			switch {
			case path == "/authorize" && r.Method == http.MethodPost:
				return []*ratelimit.Limiter{emailRouting, allWrites}
			case path == "/authorize", strings.HasPrefix(path, "/callback/"):
				return []*ratelimit.Limiter{signIn, allWrites}
			case path == "/token":
				return []*ratelimit.Limiter{token}
			case path == "/mcp":
				return []*ratelimit.Limiter{adminCalls}
			}
			return nil
		},
	})
}
