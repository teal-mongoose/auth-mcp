package admin

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func post(t *testing.T, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json, text/event-stream")
	res := httptest.NewRecorder()
	New(Config{}).Handler().ServeHTTP(res, r)
	return res
}

func TestBatchesAreRefusedBeforeAnythingElse(t *testing.T) {
	for _, body := range []string{
		`[{"jsonrpc":"2.0","id":1,"method":"tools/list"},{"jsonrpc":"2.0","id":2,"method":"tools/list"}]`,
		"  \n\t\r[]",
	} {
		if res := post(t, body); res.Code != http.StatusBadRequest || !strings.Contains(res.Body.String(), "batches") {
			t.Fatalf("%q: %d %q, want a 400 refusing batches", body, res.Code, res.Body.String())
		}
	}
}

func TestSingleRequestsPassThroughIntact(t *testing.T) {
	body := `  {"jsonrpc":"2.0","id":1,"method":"tools/list"}`
	var got string
	h := refuseBatches(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		got = string(b)
	}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body)))
	if got != body {
		t.Fatalf("the next handler read %q, want %q", got, body)
	}
}

func TestOversizedBodiesAreRefused(t *testing.T) {
	big := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"pad":"` + strings.Repeat("x", maxRequestBytes) + `"}}`
	if res := post(t, big); res.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("got %d, want 413", res.Code)
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("connection reset") }

func TestUnreadableBodiesAreABadRequest(t *testing.T) {
	res := httptest.NewRecorder()
	refuseBatches(http.NotFoundHandler()).ServeHTTP(res, httptest.NewRequest(http.MethodPost, "/mcp", failingReader{}))
	if res.Code != http.StatusBadRequest {
		t.Fatalf("got %d, want 400", res.Code)
	}
}
