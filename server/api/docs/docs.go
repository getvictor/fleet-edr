// Package docs serves the self-hosted OpenAPI documentation: an embedded
// Redoc renderer at GET /api/docs and the underlying spec at GET
// /api/openapi.yaml. Both routes are unauthenticated on purpose — the spec
// content is already public on the GitHub release page and procurement
// teams expect to be able to browse a customer-site's API surface without
// credentials.
//
// The Redoc JS bundle and the spec are compiled into the server binary so
// an air-gapped or privacy-conscious customer doesn't make external
// network calls just to load the docs page. The upstream Redoc bundle
// references cdn.redoc.ly/redoc/logo-mini.svg for the top-nav branding
// mark; we patch that single URL in the embedded bundle to point at
// /api/docs/logo-mini.svg (served from embed/ too) so there are zero
// external requests on load.
//
// The canonical spec lives at docs/api/openapi.yaml in the repo root; the
// copy in embed/openapi.yaml is refreshed via go generate (see the
// directive below) and a `task sync:openapi-embed` helper is a follow-up.
// If you edit the canonical copy, run `go generate ./server/api/docs/...`
// before building.
package docs

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"net/http"
)

//go:generate sh -c "cp ../../../docs/api/openapi.yaml embed/openapi.yaml"

//go:embed embed/openapi.yaml embed/redoc.standalone.js embed/logo-mini.svg
var assets embed.FS

// bundleHash is a short content-hash cache-buster appended to the bundle
// and logo URLs in the served HTML. Computed once at init so subsequent
// requests don't rehash. When we update Redoc (new bundle bytes), the
// hash changes, the browser refetches — no stale-cache window.
var bundleHash = func() string {
	b, err := assets.ReadFile("embed/redoc.standalone.js")
	if err != nil {
		// Should never happen — the embed directive fails at compile
		// time if the file is missing. Keep the zero-path working so
		// tests that skip the bundle don't panic.
		return "v0"
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])[:12]
}()

// indexHTML renders the Redoc bootstrap page. Kept inline (not an
// embedded file) because it's tiny and we want to stamp the bundleHash
// cache-buster into the script src at request time. Everything is
// served from the same origin — zero external scripts, fonts, or
// images, so the page loads cleanly offline and gives no cross-origin
// privacy concerns.
func indexHTML() string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Fleet EDR API</title>
<style>
body { margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
</style>
</head>
<body>
<redoc spec-url="/api/openapi.yaml"></redoc>
<script src="/api/docs/redoc.standalone.js?v=%s"></script>
</body>
</html>
`, bundleHash)
}

// RegisterRoutes wires /api/docs + /api/docs/redoc.standalone.js + /api/openapi.yaml
// onto the given mux. Callers mount these on the public (pre-auth) mux —
// the spec is already public on GitHub releases and gating the hosted
// renderer would only add friction for evaluators.
func RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/docs", serveIndex)
	mux.HandleFunc("GET /api/docs/redoc.standalone.js", serveAsset("embed/redoc.standalone.js", "application/javascript; charset=utf-8", true))
	mux.HandleFunc("GET /api/docs/logo-mini.svg", serveAsset("embed/logo-mini.svg", "image/svg+xml", true))
	mux.HandleFunc("GET /api/openapi.yaml", serveAsset("embed/openapi.yaml", "application/yaml; charset=utf-8", false))
}

func serveIndex(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// No caching on the index — cheap to regenerate and means a bundle-URL
	// bump rolls out immediately. The heavy asset (redoc.standalone.js)
	// gets the cache header.
	w.Header().Set("Cache-Control", "no-store")
	if _, err := fmt.Fprint(w, indexHTML()); err != nil {
		// Can't usefully surface the error — the client already has
		// partial bytes. Log path via the caller's middleware chain.
		_ = err
	}
}

func serveAsset(path, contentType string, cacheable bool) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		b, err := assets.ReadFile(path)
		if err != nil {
			http.Error(w, "docs asset not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", contentType)
		if cacheable {
			// The bundle is bytes-identical across releases at the same
			// Redoc version, and changes only when we bump the pin. 1h
			// max-age keeps the browser's cached copy fresh without
			// making the first-paint cost a round-trip every session.
			w.Header().Set("Cache-Control", "public, max-age=3600")
		}
		if _, err := w.Write(b); err != nil {
			_ = err
		}
	}
}
