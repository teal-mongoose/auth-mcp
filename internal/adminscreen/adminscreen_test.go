package adminscreen

import (
	"encoding/json"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

func serve(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(Handler(Config{
		AppID:           "test-admin",
		Name:            "Test Admin </script><script>alert(1)</script>",
		ProjectID:       "demo-auth-mcp",
		AuthEmulatorURL: "http://127.0.0.1:9399",
		BrokerURL:       "http://127.0.0.1:8701",
		RedirectURI:     "http://127.0.0.1:8713/",
	}))
	t.Cleanup(server.Close)
	return server
}

func get(t *testing.T, target string) (*http.Response, string) {
	t.Helper()
	res, err := http.Get(target)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	return res, string(body)
}

func TestPageCarriesItsConfig(t *testing.T) {
	server := serve(t)
	res, body := get(t, server.URL+"/")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", res.StatusCode)
	}

	match := regexp.MustCompile(`(?s)id="config">(.*?)</script>`).FindStringSubmatch(body)
	if match == nil {
		t.Fatalf("no config in the page: %s", body)
	}
	var config Config
	if err := json.Unmarshal([]byte(match[1]), &config); err != nil {
		t.Fatalf("config isn't JSON: %v: %s", err, match[1])
	}
	if config.AppID != "test-admin" || config.BrokerURL != "http://127.0.0.1:8701" || config.ProjectID != "demo-auth-mcp" {
		t.Errorf("config = %+v", config)
	}
}

func TestConfigCannotBreakOutOfThePage(t *testing.T) {
	server := serve(t)
	_, body := get(t, server.URL+"/")
	if strings.Contains(body, "<script>alert(1)") {
		t.Errorf("the page contains unescaped HTML from its config: %s", body)
	}
	if !strings.Contains(html.UnescapeString(body), "Test Admin") {
		t.Errorf("the name is missing: %s", body)
	}
}

func TestContentSecurityPolicy(t *testing.T) {
	server := serve(t)
	res, _ := get(t, server.URL+"/")
	policy := res.Header.Get("Content-Security-Policy")

	for _, want := range []string{
		"default-src 'none'",
		"script-src 'self' https://www.gstatic.com https://esm.sh",
		"connect-src http://127.0.0.1:8701 http://127.0.0.1:9399",
		"frame-ancestors 'none'",
	} {
		if !strings.Contains(policy, want) {
			t.Errorf("policy %q is missing %q", policy, want)
		}
	}
	if strings.Contains(policy, "unsafe-inline") || strings.Contains(policy, "unsafe-eval") {
		t.Errorf("policy %q allows inline code", policy)
	}
}

func TestAssetsAreServedAndOthersAreNot(t *testing.T) {
	server := serve(t)

	for path, wantType := range map[string]string{"/app.js": "javascript", "/app.css": "text/css"} {
		res, body := get(t, server.URL+path)
		if res.StatusCode != http.StatusOK || body == "" {
			t.Errorf("%s = %d, %d bytes", path, res.StatusCode, len(body))
		}
		if got := res.Header.Get("Content-Type"); !strings.Contains(got, wantType) {
			t.Errorf("%s Content-Type = %q", path, got)
		}
	}

	for _, path := range []string{"/index.html", "/static/app.js", "/nope", "/../adminscreen.go"} {
		res, _ := get(t, server.URL+path)
		if res.StatusCode != http.StatusNotFound {
			t.Errorf("%s = %d, want 404", path, res.StatusCode)
		}
	}
}

// TestHiddenAlwaysHides guards a bug that left the section buttons on screen after someone lost access.
func TestHiddenAlwaysHides(t *testing.T) {
	server := serve(t)
	_, styles := get(t, server.URL+"/app.css")
	if !regexp.MustCompile(`\[hidden\]\s*\{\s*display:\s*none\s*!important`).MatchString(styles) {
		t.Error("app.css can override the hidden attribute")
	}
}

// TestScreenNeverBuildsHTMLFromStrings guards the rule that keeps names and claims from running as code.
func TestScreenNeverBuildsHTMLFromStrings(t *testing.T) {
	server := serve(t)
	_, script := get(t, server.URL+"/app.js")
	for _, unsafe := range []string{"innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function"} {
		if strings.Contains(script, unsafe) {
			t.Errorf("app.js uses %s", unsafe)
		}
	}
}
