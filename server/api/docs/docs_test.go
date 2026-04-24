package docs

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRegisterRoutes_IndexServesHTMLReferencingAssets(t *testing.T) {
	mux := http.NewServeMux()
	RegisterRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/api/docs", nil)
	require.NoError(t, err)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.True(t, strings.HasPrefix(resp.Header.Get("Content-Type"), "text/html"))

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	s := string(body)
	// The HTML must point at the two same-origin assets so there's no
	// external network request. Flags a regression where someone swaps
	// them for CDN URLs.
	assert.Contains(t, s, `spec-url="/api/openapi.yaml"`,
		"index must load the embedded spec")
	assert.Regexp(t, `src="/api/docs/redoc\.standalone\.js\?v=[a-f0-9]{12}"`, s,
		"index must load the embedded Redoc bundle with a content-hash cache-buster")
	assert.NotContains(t, s, "cdn.redoc.ly",
		"index must not reference any external CDN")
}

// TestRedocBundle_NoExternalURLs is the regression test for a previously-
// shipped external network call. The upstream Redoc standalone bundle
// references cdn.redoc.ly/redoc/logo-mini.svg for its top-nav brand mark;
// we patch that URL to /api/docs/logo-mini.svg at vendor time so the page
// makes zero external requests. If someone re-downloads a fresh Redoc
// bundle and forgets to re-patch, this test fires.
func TestRedocBundle_NoExternalURLs(t *testing.T) {
	b, err := assets.ReadFile("embed/redoc.standalone.js")
	require.NoError(t, err)
	assert.NotContains(t, string(b), "cdn.redoc.ly",
		"Redoc bundle still references cdn.redoc.ly — re-apply the same-origin URL patch (see docs.go doc comment)")
}

func TestRegisterRoutes_SpecAndBundleServedFromEmbed(t *testing.T) {
	mux := http.NewServeMux()
	RegisterRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	cases := []struct {
		path           string
		wantMimePrefix string
		wantHeadBytes  string // a substring the beginning of the file should contain
		wantETag       bool   // spec + logo revalidate via ETag; bundle uses URL-bust
	}{
		{"/api/openapi.yaml", "application/yaml", "openapi: 3.1.0", true},
		{"/api/docs/redoc.standalone.js", "application/javascript", "For license information", false},
		{"/api/docs/logo-mini.svg", "image/svg+xml", "<svg", true},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+tc.path, nil)
			require.NoError(t, err)
			resp, err := http.DefaultClient.Do(req)
			require.NoError(t, err)
			defer resp.Body.Close()
			require.Equal(t, http.StatusOK, resp.StatusCode)
			assert.True(t, strings.HasPrefix(resp.Header.Get("Content-Type"), tc.wantMimePrefix),
				"got Content-Type %q", resp.Header.Get("Content-Type"))
			assert.Equal(t, "nosniff", resp.Header.Get("X-Content-Type-Options"),
				"every asset handler must set X-Content-Type-Options: nosniff")
			if tc.wantETag {
				assert.NotEmpty(t, resp.Header.Get("ETag"),
					"spec and logo must carry ETag for revalidation")
				assert.Equal(t, "no-cache", resp.Header.Get("Cache-Control"),
					"revalidating assets use Cache-Control: no-cache")
			}
			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			assert.Contains(t, string(body[:min(len(body), 400)]), tc.wantHeadBytes)
		})
	}
}

// TestETagRevalidation_Returns304 confirms that a conditional GET with a
// matching If-None-Match skips the body — the key win of the ETag
// strategy for the spec and logo. Saves bandwidth on repeat loads while
// still guaranteeing a correct spec after a server upgrade.
func TestETagRevalidation_Returns304(t *testing.T) {
	mux := http.NewServeMux()
	RegisterRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	paths := []string{"/api/openapi.yaml", "/api/docs/logo-mini.svg"}
	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			first, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+path, nil)
			require.NoError(t, err)
			firstResp, err := http.DefaultClient.Do(first)
			require.NoError(t, err)
			_, _ = io.Copy(io.Discard, firstResp.Body)
			firstResp.Body.Close()
			etag := firstResp.Header.Get("ETag")
			require.NotEmpty(t, etag)

			second, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+path, nil)
			require.NoError(t, err)
			second.Header.Set("If-None-Match", etag)
			secondResp, err := http.DefaultClient.Do(second)
			require.NoError(t, err)
			defer secondResp.Body.Close()
			assert.Equal(t, http.StatusNotModified, secondResp.StatusCode,
				"matching If-None-Match must produce 304 Not Modified")
		})
	}
}
