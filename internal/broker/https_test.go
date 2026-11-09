package broker

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestBindingCookieOverHTTPS(t *testing.T) {
	b := New(Config{BaseURL: "https://auth.example"})
	cookie := b.bindingCookie("state", "value", 600)

	if !strings.HasPrefix(cookie.Name, "__Host-") {
		t.Errorf("name = %q, want the __Host- prefix", cookie.Name)
	}
	// The prefix only works with all three of these.
	if !cookie.Secure || cookie.Path != "/" || cookie.Domain != "" {
		t.Errorf("cookie = %+v", cookie)
	}
	if !cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode {
		t.Errorf("cookie = %+v", cookie)
	}
	if cookie.Name != b.bindingCookieName("state") {
		t.Errorf("the callback would look for %q, not %q", b.bindingCookieName("state"), cookie.Name)
	}
}

func TestBindingCookieOnThisMachine(t *testing.T) {
	b := New(Config{BaseURL: "http://localhost:8701"})
	cookie := b.bindingCookie("state", "value", 600)
	if strings.HasPrefix(cookie.Name, "__Host-") || cookie.Secure || cookie.Path != "/callback" {
		t.Errorf("cookie = %+v", cookie)
	}
}

func TestHSTSOnlyOverHTTPS(t *testing.T) {
	for baseURL, want := range map[string]bool{"https://auth.example": true, "http://localhost:8701": false} {
		res := httptest.NewRecorder()
		New(Config{BaseURL: baseURL}).Handler().ServeHTTP(res, httptest.NewRequest(http.MethodGet, "/nothing-here", nil))
		got := res.Header().Get("Strict-Transport-Security") != ""
		if got != want {
			t.Errorf("%s: HSTS = %v, want %v", baseURL, got, want)
		}
	}
}
