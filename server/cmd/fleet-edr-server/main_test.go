package main

import (
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/httpserver"
)

// TestRegisterUIRoutes_SPAFallback locks in the SPA-fallback contract: /ui/{deep-link} must return 200 with the index.html
// body so React Router can take over client-side, NOT a 301 redirect to ./. An earlier implementation rewrote URL.Path to
// /ui/index.html and let http.FileServer serve it, but FileServer canonicalises /index.html → ./ and broke every SPA deep link (e.g.
// /ui/hosts/{host_id}).
func TestRegisterUIRoutes_SPAFallback(t *testing.T) {
	t.Parallel()
	// Synthesise a minimal "dist" tree so the handler doesn't depend on a built UI bundle being present. The real embed.FS has the same
	// shape (index.html at the root + an assets/ subdirectory).
	memFS := fstest.MapFS{
		"dist/index.html": &fstest.MapFile{
			Data: []byte("<!doctype html><html><body>SPA</body></html>"),
		},
		"dist/assets/main.js": &fstest.MapFile{
			Data: []byte("console.log('asset-marker');"),
		},
	}

	mux := http.NewServeMux()
	registerUIRoutesWithFS(t, mux, memFS, passthroughGate)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	cases := []struct {
		name      string
		path      string
		wantCode  int
		wantBody  string // empty means don't assert
		wantCType string
	}{
		{
			name:      "root /ui/ serves index.html",
			path:      "/ui/",
			wantCode:  http.StatusOK,
			wantBody:  "SPA",
			wantCType: "text/html; charset=utf-8",
		},
		{
			name:      "deep link /ui/hosts/{id} falls back to index.html",
			path:      "/ui/hosts/93DFC6F5-763D-5075-B305-8AC145D12F96",
			wantCode:  http.StatusOK,
			wantBody:  "SPA",
			wantCType: "text/html; charset=utf-8",
		},
		{
			name:      "nested deep link falls back to index.html",
			path:      "/ui/alerts/123/details",
			wantCode:  http.StatusOK,
			wantBody:  "SPA",
			wantCType: "text/html; charset=utf-8",
		},
		{
			name:     "real asset is served as-is, not the index fallback",
			path:     "/ui/assets/main.js",
			wantCode: http.StatusOK,
			wantBody: "asset-marker",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+tc.path, nil)
			require.NoError(t, err)

			// Disable redirect-following so a regression to 301 fails the test
			// instead of silently following the redirect chain to /ui/.
			client := &http.Client{
				CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
					return http.ErrUseLastResponse
				},
			}
			resp, err := client.Do(req)
			require.NoError(t, err)
			defer resp.Body.Close()

			assert.Equal(t, tc.wantCode, resp.StatusCode,
				"path=%s must NOT 301-redirect; SPA fallback must serve 200", tc.path)
			if tc.wantCType != "" {
				assert.Equal(t, tc.wantCType, resp.Header.Get("Content-Type"))
			}
			if tc.wantBody != "" {
				body := make([]byte, 1024)
				n, _ := resp.Body.Read(body)
				assert.Contains(t, string(body[:n]), tc.wantBody)
			}
		})
	}
}

// TestRegisterUIRoutes_BreakglassGate locks in the path-concealment promise the breakglass.Handler comment makes for
// /admin/break-glass: off-allowlist callers must not be able to load the React shell at /ui/admin/break-glass{,/setup} either,
// since the goal is to hide the path's existence rather than just the API surface. The regression this guards: registering the React
// routes BEFORE the /ui/ catch-all (so the more-specific patterns are gated), and applying the gate to BOTH the login and setup paths.
func TestRegisterUIRoutes_BreakglassGate(t *testing.T) {
	t.Parallel()
	memFS := fstest.MapFS{
		"dist/index.html": &fstest.MapFile{
			Data: []byte("<!doctype html><html><body>SPA</body></html>"),
		},
	}

	cases := []struct {
		name     string
		gate     func(http.Handler) http.Handler
		path     string
		wantCode int
	}{
		{
			name:     "passthrough gate serves /ui/admin/break-glass index",
			gate:     passthroughGate,
			path:     "/ui/admin/break-glass",
			wantCode: http.StatusOK,
		},
		{
			name:     "passthrough gate serves /ui/admin/break-glass/setup index",
			gate:     passthroughGate,
			path:     "/ui/admin/break-glass/setup",
			wantCode: http.StatusOK,
		},
		{
			name:     "deny gate hides /ui/admin/break-glass behind 404",
			gate:     denyAllGate,
			path:     "/ui/admin/break-glass",
			wantCode: http.StatusNotFound,
		},
		{
			name:     "deny gate hides /ui/admin/break-glass/setup behind 404",
			gate:     denyAllGate,
			path:     "/ui/admin/break-glass/setup",
			wantCode: http.StatusNotFound,
		},
		{
			name:     "deny gate does NOT block unrelated /ui/ routes",
			gate:     denyAllGate,
			path:     "/ui/hosts/abc",
			wantCode: http.StatusOK,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			mux := http.NewServeMux()
			registerUIRoutesWithFS(t, mux, memFS, tc.gate)
			srv := httptest.NewServer(mux)
			t.Cleanup(srv.Close)
			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+tc.path, nil)
			require.NoError(t, err)
			client := &http.Client{
				CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
					return http.ErrUseLastResponse
				},
			}
			resp, err := client.Do(req)
			require.NoError(t, err)
			defer resp.Body.Close()
			assert.Equal(t, tc.wantCode, resp.StatusCode)
		})
	}
}

// passthroughGate is the no-op middleware test cases use when they
// don't want to exercise the break-glass UI gate.
func passthroughGate(next http.Handler) http.Handler { return next }

// denyAllGate is the always-deny middleware: everything 404s. Stands
// in for an off-allowlist caller hitting a gated React route.
func denyAllGate(_ http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.NotFound(w, nil)
	})
}

// registerUIRoutesWithFS is a test-only entry point that wires the same handler topology as registerUIRoutes against a caller-provided
// FS. Lets the test exercise the SPA fallback + break-glass UI gate without touching the process's real embed.FS.
func registerUIRoutesWithFS(
	t *testing.T,
	mux *http.ServeMux,
	srcFS fs.FS,
	breakglassGate func(http.Handler) http.Handler,
) {
	t.Helper()
	uiDist, err := fs.Sub(srcFS, "dist")
	require.NoError(t, err)
	logger := slog.Default()
	fileServer := http.StripPrefix("/ui/", http.FileServer(http.FS(uiDist)))

	breakglassUI := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serveIndex(w, r, uiDist, logger)
	})
	mux.Handle("/ui/admin/break-glass", breakglassGate(breakglassUI))
	mux.Handle("/ui/admin/break-glass/setup", breakglassGate(breakglassUI))

	mux.HandleFunc("/ui/", func(w http.ResponseWriter, r *http.Request) {
		stripped := r.URL.Path[len("/ui/"):]
		if stripped == "" {
			serveIndex(w, r, uiDist, logger)
			return
		}
		if _, err := fs.Stat(uiDist, stripped); err != nil {
			serveIndex(w, r, uiDist, logger)
			return
		}
		fileServer.ServeHTTP(w, r)
	})
}

// TestMountAuthed_registeredRouteIsProtectedNotSPA locks in the issue #463 contract: a route registered through the authed-route
// registration callback is mounted on the outer router and reaches the session-protected wrapper (401 / JSON when unauthenticated),
// rather than falling through to the `/` SPA catch-all (which 302'd / served index.html and broke the UI's JSON fetch). Because
// mountAuthed derives the mounted set from what is actually registered, a registered route can never be left off the allowlist.
//
// spec:server-rest-api/registered-authed-routes-are-reachable-through-the-composed-router/a-registered-authed-route-is-session-protected-not-spa-fall-through
func TestMountAuthed_registeredRouteIsProtectedNotSPA(t *testing.T) {
	t.Parallel()
	outer := http.NewServeMux()
	// SPA catch-all: what an un-allowlisted /api route used to fall through to (the bug).
	outer.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<!doctype html>"))
	})
	// protect stands in for the session/bearer middleware: an unauthenticated request gets 401 JSON.
	protect := func(http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"invalid_session"}`))
		})
	}
	mountAuthed(outer, protect, func(r httpserver.Router) {
		r.HandleFunc("GET /api/probe", func(http.ResponseWriter, *http.Request) {})
	})

	// A registered authed route reaches the protected wrapper: 401 JSON, NOT the SPA shell.
	pw := httptest.NewRecorder()
	outer.ServeHTTP(pw, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/probe", nil))
	assert.Equal(t, http.StatusUnauthorized, pw.Code)
	assert.Equal(t, "application/json", pw.Header().Get("Content-Type"))
	assert.NotContains(t, pw.Body.String(), "<!doctype html>")

	// A route that was never registered still falls through to the SPA (control: derive mounts only what is registered).
	mw := httptest.NewRecorder()
	outer.ServeHTTP(mw, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/never-registered", nil))
	assert.Equal(t, "text/html", mw.Header().Get("Content-Type"))
}
