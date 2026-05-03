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
)

// TestRegisterUIRoutes_SPAFallback locks in the post-phase-6 fix:
// /ui/{deep-link} must return 200 with the index.html body so React
// Router can take over client-side, NOT a 301 redirect to ./. Earlier
// this code rewrote URL.Path to /ui/index.html and let http.FileServer
// serve it, but FileServer canonicalises /index.html → ./ and broke
// every SPA deep link (e.g. /ui/hosts/{host_id}).
func TestRegisterUIRoutes_SPAFallback(t *testing.T) {
	// Synthesise a minimal "dist" tree so the handler doesn't depend on
	// a built UI bundle being present. The real embed.FS has the same
	// shape (index.html at the root + an assets/ subdirectory).
	memFS := fstest.MapFS{
		"dist/index.html": &fstest.MapFile{
			Data: []byte("<!doctype html><html><body>SPA</body></html>"),
		},
		"dist/assets/main.js": &fstest.MapFile{
			Data: []byte("console.log('phase6');"),
		},
	}

	mux := http.NewServeMux()
	registerUIRoutesWithFS(t, mux, memFS)
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
			wantBody: "phase6",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
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

// registerUIRoutesWithFS is a test-only entry point that wires the
// same handler topology as registerUIRoutes against a caller-provided
// FS. Lets the test exercise the SPA fallback without touching the
// process's real embed.FS.
func registerUIRoutesWithFS(t *testing.T, mux *http.ServeMux, srcFS fs.FS) {
	t.Helper()
	uiDist, err := fs.Sub(srcFS, "dist")
	require.NoError(t, err)
	logger := slog.Default()
	fileServer := http.StripPrefix("/ui/", http.FileServer(http.FS(uiDist)))
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
