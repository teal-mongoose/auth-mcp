package live

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func send(h http.Handler, method, path, forwardedFor string) int {
	r := httptest.NewRequest(method, path, nil)
	r.RemoteAddr = "169.254.1.1:5000"
	if forwardedFor != "" {
		r.Header.Set("X-Forwarded-For", forwardedFor)
	}
	res := httptest.NewRecorder()
	h.ServeHTTP(res, r)
	return res.Code
}

func countOK(h http.Handler, method, path, forwardedFor string, n int) int {
	ok := 0
	for range n {
		if send(h, method, path, forwardedFor) == http.StatusOK {
			ok++
		}
	}
	return ok
}

// limitedAt rate-limits okHandler with a stopped clock, so nothing refills during a test.
func limitedAt(behindProxy bool) http.Handler {
	stopped := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	return rateLimited(okHandler(), behindProxy, func() time.Time { return stopped })
}

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
}

func TestEachEndpointHasItsBurst(t *testing.T) {
	cases := []struct {
		method, path string
		burst        int
	}{
		{http.MethodPost, "/authorize", limitEmailRouting.Burst},
		{http.MethodGet, "/authorize", limitSignIn.Burst},
		{http.MethodGet, "/callback/staff-google", limitSignIn.Burst},
		{http.MethodPost, "/token", limitToken.Burst},
		{http.MethodPost, "/mcp", limitAdmin.Burst},
	}
	for _, tc := range cases {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			h := limitedAt(true)
			if got := countOK(h, tc.method, tc.path, "203.0.113.7", tc.burst+5); got != tc.burst {
				t.Fatalf("allowed %d at once, want %d", got, tc.burst)
			}
		})
	}
}

func TestOtherPathsAreNotLimited(t *testing.T) {
	h := limitedAt(true)
	if got := countOK(h, http.MethodGet, "/healthz", "203.0.113.7", 200); got != 200 {
		t.Fatalf("allowed %d of 200", got)
	}
}

func TestSpoofedForwardedForDoesNotEscapeTheLimit(t *testing.T) {
	h := limitedAt(true)
	ok := 0
	for i := range limitEmailRouting.Burst + 5 {
		// Only the last entry, added by Cloud Run, counts. The client controls the rest.
		spoofed := fmt.Sprintf("198.51.100.%d, 203.0.113.7", i)
		if send(h, http.MethodPost, "/authorize", spoofed) == http.StatusOK {
			ok++
		}
	}
	if ok != limitEmailRouting.Burst {
		t.Fatalf("allowed %d with spoofed entries, want %d", ok, limitEmailRouting.Burst)
	}
	if send(h, http.MethodPost, "/authorize", "203.0.113.8") != http.StatusOK {
		t.Fatal("another real address should have its own limit")
	}
}

func TestOnThisMachineTheConnectingAddressCounts(t *testing.T) {
	h := limitedAt(false)
	ok := 0
	for i := range limitEmailRouting.Burst + 5 {
		// Without a proxy, X-Forwarded-For is entirely the client's, so it's ignored.
		if send(h, http.MethodPost, "/authorize", fmt.Sprintf("203.0.113.%d", i)) == http.StatusOK {
			ok++
		}
	}
	if ok != limitEmailRouting.Burst {
		t.Fatalf("allowed %d, want %d", ok, limitEmailRouting.Burst)
	}
}

func TestSignInWritesAreCappedAcrossClients(t *testing.T) {
	h := limitedAt(true)
	ok := 0
	for i := range limitAllSignInWrites.Burst + 20 {
		// A different address each time, so only the shared limit applies. Callbacks count too.
		addr := fmt.Sprintf("203.0.%d.%d", i/250, i%250)
		path := "/authorize"
		if i%2 == 1 {
			path = "/callback/staff-google"
		}
		if send(h, http.MethodGet, path, addr) == http.StatusOK {
			ok++
		}
	}
	if ok != limitAllSignInWrites.Burst {
		t.Fatalf("allowed %d sign-in writes from many addresses at once, want %d", ok, limitAllSignInWrites.Burst)
	}
}

func TestAFewClientsCantBlockEveryonesSignIn(t *testing.T) {
	h := limitedAt(true)
	// Twenty attackers, each using their whole allowance.
	for i := range 20 {
		countOK(h, http.MethodGet, "/authorize", fmt.Sprintf("198.51.100.%d", i), limitSignIn.Burst+10)
	}
	if send(h, http.MethodGet, "/authorize", "203.0.113.7") != http.StatusOK {
		t.Fatal("a new client was refused after a few others used their allowance")
	}
}

func TestCyclingIPv6SubnetsDoesNotEscapeTheLimit(t *testing.T) {
	h := limitedAt(true)
	ok := 0
	for i := range limitEmailRouting.Burst + 5 {
		// A different /64 each time, all in one /48.
		if send(h, http.MethodPost, "/authorize", fmt.Sprintf("2001:db8:1:%x::1", i)) == http.StatusOK {
			ok++
		}
	}
	if ok != limitEmailRouting.Burst {
		t.Fatalf("allowed %d from one /48, want %d", ok, limitEmailRouting.Burst)
	}
}

func TestPreflightsAndHeadAreHandled(t *testing.T) {
	h := limitedAt(true)
	if got := countOK(h, http.MethodOptions, "/mcp", "203.0.113.7", limitAdmin.Burst+20); got != limitAdmin.Burst+20 {
		t.Fatalf("allowed %d preflights, want all of them", got)
	}
	if got := countOK(h, http.MethodHead, "/authorize", "203.0.113.8", limitSignIn.Burst+5); got != limitSignIn.Burst {
		t.Fatalf("HEAD /authorize: allowed %d, want the sign-in burst of %d", got, limitSignIn.Burst)
	}
}
