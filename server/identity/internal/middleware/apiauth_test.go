package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/identity/api"
)

type stubAuth struct {
	actor *api.Actor
	ok    bool
}

func (s stubAuth) Authenticate(string, time.Time) (*api.Actor, bool) { return s.actor, s.ok }

// markerMW records whether it ran, standing in for the session and CSRF middlewares.
func markerMW(ran *bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			*ran = true
			next.ServeHTTP(w, r)
		})
	}
}

func TestAPIAuth_bearerPinsActorSkippingSession(t *testing.T) {
	t.Parallel()
	var sessionRan, csrfRan bool
	var gotActor *api.Actor
	final := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a, _ := api.ActorFromContext(r.Context())
		gotActor = a
		w.WriteHeader(http.StatusOK)
	})
	want := &api.Actor{AuthMethod: "service_account", SessionFresh: true}
	mw := APIAuth(stubAuth{actor: want, ok: true}, markerMW(&sessionRan), markerMW(&csrfRan), nil)

	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/hosts", nil)
	r.Header.Set("Authorization", "Bearer some-token")
	w := httptest.NewRecorder()
	mw(final).ServeHTTP(w, r)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Same(t, want, gotActor, "bearer path pins the resolved actor")
	assert.False(t, sessionRan, "bearer path must not run the session middleware")
	assert.False(t, csrfRan, "bearer path is CSRF-exempt")
}

// spec:server-identity-authentication/the-api-accepts-a-bearer-access-token-as-a-second-transport/neither-credential-present-is-unauthorized
func TestAPIAuth_invalidBearerIs401(t *testing.T) {
	t.Parallel()
	var sessionRan bool
	mw := APIAuth(stubAuth{ok: false}, markerMW(&sessionRan), markerMW(new(bool)), nil)
	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/hosts", nil)
	r.Header.Set("Authorization", "Bearer bad")
	w := httptest.NewRecorder()
	mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(w, r)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.False(t, sessionRan, "an invalid bearer token is a clear 401, never a fall-through to the cookie path")
}

// spec:server-identity-authentication/the-api-accepts-a-bearer-access-token-as-a-second-transport/cookie-transport-is-unchanged-for-the-browser
func TestAPIAuth_noBearerDelegatesToSession(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name       string
		authHeader string
	}{
		{"no header", ""},
		{"non-bearer scheme", "Basic Zm9vOmJhcg=="},
		{"empty bearer", "Bearer "},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var sessionRan, csrfRan, finalRan bool
			mw := APIAuth(stubAuth{ok: false}, markerMW(&sessionRan), markerMW(&csrfRan), nil)
			r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/hosts", nil)
			if tc.authHeader != "" {
				r.Header.Set("Authorization", tc.authHeader)
			}
			w := httptest.NewRecorder()
			mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { finalRan = true })).ServeHTTP(w, r)
			assert.True(t, sessionRan, "no usable bearer: session middleware runs")
			assert.True(t, csrfRan, "no usable bearer: CSRF middleware runs")
			assert.True(t, finalRan)
		})
	}
}
