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
//
// Cache invalidation strategy across the three assets:
//   - redoc.standalone.js is hash-busted via ?v=<bundleHash> in the served
//     HTML. New bundle bytes → new hash → new URL → full refetch. The
//     response is cached with a 1h max-age so repeat visits are fast.
//   - openapi.yaml and logo-mini.svg are served with Cache-Control:
//     no-cache plus an ETag. Browsers revalidate with If-None-Match on
//     every navigation and get a 304 (no body) when unchanged. The
//     tradeoff: one extra round-trip per page load vs. URL chaining
//     through the bundle (which would require regenerating bundleHash
//     whenever the logo/spec change).
package docs

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"net/http"
	"time"
)

//go:generate sh -c "cp ../../../docs/api/openapi.yaml embed/openapi.yaml"

//go:embed embed/openapi.yaml embed/redoc.standalone.js embed/logo-mini.svg
var assets embed.FS

// Preloaded asset bytes. Reading from embed.FS on every request allocates
// a fresh []byte per call (the embed package has no shared backing buffer
// for consumers), so we pay that cost once at init.
var (
	bundleBytes = mustReadAsset("embed/redoc.standalone.js")
	specBytes   = mustReadAsset("embed/openapi.yaml")
	logoBytes   = mustReadAsset("embed/logo-mini.svg")
)

// bundleHash is the 12-char content-hash cache-buster appended to the
// embedded Redoc bundle URL in the served HTML. Computed once at init. A
// new Redoc version (new bundle bytes) flips the hash and the browser
// refetches the script immediately — no stale-cache window. The logo and
// spec use a separate ETag-based revalidation strategy; see the package
// doc comment for the rationale.
var bundleHash = contentHash12(bundleBytes)

// Precomputed ETag values — full 64-char hex of sha256(content). Returned
// in the ETag header and compared against If-None-Match on subsequent
// requests to serve 304s without writing a body.
var (
	specETag = `"` + contentHashFull(specBytes) + `"`
	logoETag = `"` + contentHashFull(logoBytes) + `"`
)

// Shared zero-time for http.ServeContent; we don't maintain a per-asset
// modtime and ServeContent only uses it for Last-Modified when non-zero.
var epoch = time.Time{}

// Header names used more than once across handlers. Extracted so the
// raw strings live in one place (Sonar go:S1192 / Go-idiomatic).
const (
	headerContentType   = "Content-Type"
	headerCacheControl  = "Cache-Control"
	headerNoSniff       = "X-Content-Type-Options"
	cacheControlNoCache = "no-cache"
)

func mustReadAsset(path string) []byte {
	b, err := assets.ReadFile(path)
	if err != nil {
		// Should never fire — the //go:embed directive fails at compile
		// time when a referenced file is missing. Panicking here
		// surfaces a developer bug rather than a runtime 500.
		panic(fmt.Sprintf("docs: embedded asset %q missing: %v", path, err))
	}
	return b
}

func contentHash12(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])[:12]
}

func contentHashFull(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

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

// RegisterRoutes wires /api/docs + /api/docs/redoc.standalone.js +
// /api/docs/logo-mini.svg + /api/openapi.yaml onto the given mux. Callers
// mount these on the public (pre-auth) mux — the spec is already public
// on GitHub releases and gating the hosted renderer would only add
// friction for evaluators.
func RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/docs", serveIndex)
	mux.HandleFunc("GET /api/docs/redoc.standalone.js", serveBundle)
	mux.HandleFunc("GET /api/docs/logo-mini.svg", serveLogo)
	mux.HandleFunc("GET /api/openapi.yaml", serveSpec)
}

// setSecurityHeaders applies the always-on hardening: nosniff on every
// asset handler prevents a browser from interpreting, say, a spec file
// shipped with the wrong Content-Type as an executable script.
func setSecurityHeaders(w http.ResponseWriter) {
	w.Header().Set(headerNoSniff, "nosniff")
}

func serveIndex(w http.ResponseWriter, _ *http.Request) {
	setSecurityHeaders(w)
	w.Header().Set(headerContentType, "text/html; charset=utf-8")
	// No caching on the index — cheap to regenerate and means a new
	// bundleHash rolls out on the next request. The heavy JS bundle
	// gets long caching via its hash-busted URL.
	w.Header().Set(headerCacheControl, "no-store")
	if _, err := fmt.Fprint(w, indexHTML()); err != nil {
		_ = err // client already has partial bytes; can't usefully surface
	}
}

func serveBundle(w http.ResponseWriter, r *http.Request) {
	setSecurityHeaders(w)
	w.Header().Set(headerContentType, "application/javascript; charset=utf-8")
	// Bundle URL carries its own ?v=<hash> cache-buster, so a long max-age
	// is safe — the browser can serve the cached copy without revalidating
	// until we bump Redoc, at which point the URL itself changes.
	w.Header().Set(headerCacheControl, "public, max-age=3600")
	http.ServeContent(w, r, "redoc.standalone.js", epoch, bytes.NewReader(bundleBytes))
}

func serveLogo(w http.ResponseWriter, r *http.Request) {
	setSecurityHeaders(w)
	w.Header().Set(headerContentType, "image/svg+xml")
	// Logo URL is embedded inside the bundle as a bare path (no cache-
	// buster), so use ETag + revalidation instead of a long max-age.
	// Customers updating the brand mark don't wait for TTLs to expire.
	w.Header().Set(headerCacheControl, cacheControlNoCache)
	w.Header().Set("ETag", logoETag)
	http.ServeContent(w, r, "logo-mini.svg", epoch, bytes.NewReader(logoBytes))
}

func serveSpec(w http.ResponseWriter, r *http.Request) {
	setSecurityHeaders(w)
	w.Header().Set(headerContentType, "application/yaml; charset=utf-8")
	// Spec URL in the HTML is also a bare path; revalidate-every-load is
	// the simplest way to guarantee no stale spec after a server upgrade.
	// 304 responses carry no body, so the cost is one round-trip.
	w.Header().Set(headerCacheControl, cacheControlNoCache)
	w.Header().Set("ETag", specETag)
	http.ServeContent(w, r, "openapi.yaml", epoch, bytes.NewReader(specBytes))
}
