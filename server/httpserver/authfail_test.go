package httpserver_test

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/httpserver"
)

// Both writers must produce a byte-identical JSON failure body so that scripted clients (the agent, smoke tests, cURL helpers) can
// match a single response shape regardless of which middleware fired.
func TestWriteAuthFailure_BodyShape(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		write  func(w http.ResponseWriter, r *http.Request)
		status int
		body   string
	}{
		{
			name: "bearer 401",
			write: func(w http.ResponseWriter, r *http.Request) {
				httpserver.WriteAuthFailure(r.Context(), w, slog.Default(),
					http.StatusUnauthorized, "missing_bearer")
			},
			status: http.StatusUnauthorized,
			body:   `{"error":"missing_bearer"}` + "\n",
		},
		{
			name: "cookie 401",
			write: func(w http.ResponseWriter, r *http.Request) {
				httpserver.WriteCookieAuthFailure(r.Context(), w, slog.Default(),
					http.StatusUnauthorized, "missing_session")
			},
			status: http.StatusUnauthorized,
			body:   `{"error":"missing_session"}` + "\n",
		},
		{
			name: "cookie 403 csrf",
			write: func(w http.ResponseWriter, r *http.Request) {
				httpserver.WriteCookieAuthFailure(r.Context(), w, slog.Default(),
					http.StatusForbidden, "csrf_mismatch")
			},
			status: http.StatusForbidden,
			body:   `{"error":"csrf_mismatch"}` + "\n",
		},
		{
			name: "bearer 503 verifier_unavailable",
			write: func(w http.ResponseWriter, r *http.Request) {
				httpserver.WriteAuthFailure(r.Context(), w, slog.Default(),
					http.StatusServiceUnavailable, "verifier_unavailable")
			},
			status: http.StatusServiceUnavailable,
			body:   `{"error":"verifier_unavailable"}` + "\n",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rec := httptest.NewRecorder()
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
			tc.write(rec, req)

			assert.Equal(t, tc.status, rec.Code)
			body, err := io.ReadAll(rec.Body)
			require.NoError(t, err)
			assert.Equal(t, tc.body, string(body))
			assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
			assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))

			// Body parses as the shared shape regardless of which writer fired.
			var parsed httpserver.AuthErrBody
			require.NoError(t, json.Unmarshal([]byte(tc.body), &parsed))
		})
	}
}

// WriteAuthFailure (Bearer-token endpoints) MUST set `WWW-Authenticate: Bearer error="invalid_token"` on 401 per RFC 6750 so the
// agent's existing client logic continues to recognise an authentication failure distinct from a service outage.
func TestWriteAuthFailure_Bearer401_SetsChallenge(t *testing.T) {
	t.Parallel()
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	httpserver.WriteAuthFailure(req.Context(), rec, slog.Default(),
		http.StatusUnauthorized, "invalid_token")

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Equal(t, `Bearer error="invalid_token"`, rec.Header().Get("WWW-Authenticate"),
		"Bearer 401 must carry the RFC 6750 challenge")
}

// On 5xx the Bearer writer must NOT advertise a challenge, since the failure isn't a credential problem and we don't want clients to
// retry with fresh tokens against an unhealthy server.
func TestWriteAuthFailure_BearerNon401_OmitsChallenge(t *testing.T) {
	t.Parallel()
	for _, status := range []int{http.StatusForbidden, http.StatusServiceUnavailable, http.StatusInternalServerError} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			t.Parallel()
			rec := httptest.NewRecorder()
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
			httpserver.WriteAuthFailure(req.Context(), rec, slog.Default(),
				status, "verifier_unavailable")

			assert.Equal(t, status, rec.Code)
			assert.Empty(t, rec.Header().Get("WWW-Authenticate"),
				"non-401 must not advertise a Bearer challenge")
		})
	}
}

// Regression for #80: cookie-session endpoints must not advertise a Bearer challenge on 401. The browser receives a 401 with a JSON
// body and follows the application's redirect-to-login UX; sending Bearer triggers spurious HTTP-Basic dialogs in some clients and
// confuses scripted callers that prefer Bearer-shaped responses for retries.
func TestWriteCookieAuthFailure_NoChallenge(t *testing.T) {
	t.Parallel()
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusServiceUnavailable, http.StatusInternalServerError} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			t.Parallel()
			rec := httptest.NewRecorder()
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
			httpserver.WriteCookieAuthFailure(req.Context(), rec, slog.Default(),
				status, "missing_session")

			assert.Equal(t, status, rec.Code)
			assert.Empty(t, rec.Header().Get("WWW-Authenticate"),
				"cookie-auth failures must not advertise a Bearer challenge regardless of status")
		})
	}
}

// Both writers must tolerate a nil logger so handlers that fail before the logger is wired (e.g. boot path) can still produce a clean
// response. The signature accepts *slog.Logger so passing nil is the natural way to express "no logger".
func TestWriteAuthFailure_NilLoggerOK(t *testing.T) {
	t.Parallel()
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	assert.NotPanics(t, func() {
		httpserver.WriteAuthFailure(req.Context(), rec, nil, http.StatusUnauthorized, "boot_failure")
	})
	rec2 := httptest.NewRecorder()
	assert.NotPanics(t, func() {
		httpserver.WriteCookieAuthFailure(req.Context(), rec2, nil, http.StatusUnauthorized, "boot_failure")
	})
}
