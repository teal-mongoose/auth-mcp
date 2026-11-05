// Package adminscreen is a small page for inspecting the broker through its admin MCP server. It's a
// test tool, used only by the dev stack, and the server doesn't serve it.
package adminscreen

import (
	"embed"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"
)

//go:embed static
var static embed.FS

var page = template.Must(template.ParseFS(static, "static/index.html"))

// Config says which app the page is, and where it connects.
type Config struct {
	AppID           string
	Name            string
	ProjectID       string
	AuthEmulatorURL string
	BrokerURL       string
	RedirectURI     string
}

// Handler serves the page and its assets.
func Handler(cfg Config) http.Handler {
	assets, err := fs.Sub(static, "static")
	if err != nil {
		panic(err)
	}
	files := http.FileServerFS(assets)

	policy := strings.Join([]string{
		"default-src 'none'",
		"script-src 'self' https://www.gstatic.com https://esm.sh",
		"style-src 'self'",
		"connect-src " + cfg.BrokerURL + " " + cfg.AuthEmulatorURL,
		"base-uri 'none'",
		"form-action 'none'",
		"frame-ancestors 'none'",
	}, "; ")

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", policy)
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Cache-Control", "no-store")

		switch r.URL.Path {
		case "/":
			h.Set("Content-Type", "text/html; charset=utf-8")
			if err := page.ExecuteTemplate(w, "index.html", cfg); err != nil {
				slog.Error("rendering admin screen", "error", err)
			}
		case "/app.js", "/app.css":
			files.ServeHTTP(w, r)
		default:
			http.NotFound(w, r)
		}
	})
}
