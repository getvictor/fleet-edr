package middleware_test

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/identity/api"
	"github.com/fleetdm/edr/server/identity/internal/middleware"
	"github.com/fleetdm/edr/server/identity/internal/rbac"
	"github.com/fleetdm/edr/server/identity/internal/service"
	"github.com/fleetdm/edr/server/identity/internal/sessions"
	"github.com/fleetdm/edr/server/identity/internal/users"
	"github.com/fleetdm/edr/server/identity/testkit"
	"github.com/fleetdm/edr/server/testdb"
)

// newService returns a ready-to-use api.Service backed by a fresh test DB. A stub users row (id=1, 7, 42 — anything tests reference)
// is inserted first so the FK sessions.user_id -> users(id) constraint doesn't reject session inserts that the tests below mint via
// the sessions store directly.
func newService(t *testing.T) (api.Service, *sessions.Store) {
	t.Helper()
	s := testdb.Open(t)
	require.NoError(t, testkit.ApplySchema(t.Context(), s))
	for _, uid := range []int64{1, 7, 42} {
		_, err := s.ExecContext(t.Context(),
			`INSERT INTO users (id, email, password_hash, password_salt) VALUES (?, ?, ?, ?)`,
			uid, "stub-"+fmtInt(uid)+"@test", []byte("stub-hash"), []byte("stub-salt"))
		if err != nil {
			t.Fatalf("seed stub user %d: %v", uid, err)
		}
	}
	us := users.New(s)
	ss := sessions.New(s, sessions.Options{})
	rb := rbac.New(s)
	return service.New(us, ss, rb, slog.Default()), ss
}

func fmtInt(i int64) string {
	if i == 0 {
		return "0"
	}
	var out []byte
	for i > 0 {
		out = append([]byte{byte('0' + i%10)}, out...)
		i /= 10
	}
	return string(out)
}

// sealedBody is a tiny handler that writes "ok" once the middleware lets it through.
var sealedBody = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
	_, _ = io.WriteString(w, "ok")
})

func TestSession_MissingCookieReturns401(t *testing.T) {
	t.Parallel()
	svc, _ := newService(t)
	mw := middleware.Session(svc, slog.Default())
	srv := httptest.NewServer(mw(sealedBody))
	t.Cleanup(srv.Close)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/", nil)
	require.NoError(t, err)
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	// Regression for #80: a cookie-auth 401 must not advertise a Bearer challenge. The Session middleware's failure mode is "open the
	// login page", not "retry with a Bearer token", so clients that surface WWW-Authenticate to the user (browsers' HTTP-Basic dialog,
	// curl --anyauth) shouldn't see one.
	assert.Empty(t, resp.Header.Get("WWW-Authenticate"))
}

func TestSession_UnknownCookieReturns401(t *testing.T) {
	t.Parallel()
	svc, _ := newService(t)
	mw := middleware.Session(svc, slog.Default())
	srv := httptest.NewServer(mw(sealedBody))
	t.Cleanup(srv.Close)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/", nil)
	require.NoError(t, err)
	// 32 zero bytes, base64url -- never matches a real session.
	req.AddCookie(&http.Cookie{Name: api.SessionCookieName, Value: api.EncodeToken(make([]byte, sessions.IDLen))})
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestSession_MalformedCookieReturns401(t *testing.T) {
	t.Parallel()
	svc, _ := newService(t)
	mw := middleware.Session(svc, slog.Default())
	srv := httptest.NewServer(mw(sealedBody))
	t.Cleanup(srv.Close)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/", nil)
	require.NoError(t, err)
	req.AddCookie(&http.Cookie{Name: api.SessionCookieName, Value: "not-base64-@#$%"})
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestSession_ValidCookieLetsHandlerRun(t *testing.T) {
	t.Parallel()
	svc, ss := newService(t)
	sess, err := ss.Create(t.Context(), 42, sessions.CreateOptions{})
	require.NoError(t, err)

	mw := middleware.Session(svc, slog.Default())
	var sawUserID int64
	var sawSession *api.Session
	srv := httptest.NewServer(mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		uid, _ := api.UserIDFromContext(r.Context())
		sawUserID = uid
		s, _ := api.SessionFromContext(r.Context())
		sawSession = s
		w.WriteHeader(http.StatusOK)
	})))
	t.Cleanup(srv.Close)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/", nil)
	require.NoError(t, err)
	req.AddCookie(&http.Cookie{Name: api.SessionCookieName, Value: api.EncodeToken(sess.ID)})
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, int64(42), sawUserID)
	require.NotNil(t, sawSession)
	assert.Equal(t, sess.CSRFToken, sawSession.CSRFToken)
}

// A GET never needs a CSRF header even if one of the authenticated admin
// surfaces ever ends up behind the CSRF middleware.
func TestCSRF_SafeMethodPassesThrough(t *testing.T) {
	t.Parallel()
	mw := middleware.CSRF(slog.Default())
	srv := httptest.NewServer(mw(sealedBody))
	t.Cleanup(srv.Close)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/", nil)
	require.NoError(t, err)
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

// CSRF outside Session (no session on ctx for an unsafe method) is a programming error; we surface it as 500 not 401 so the ops team
// pages on server misconfiguration rather than assuming a bad token.
func TestCSRF_MisconfiguredReturns500(t *testing.T) {
	t.Parallel()
	mw := middleware.CSRF(slog.Default())
	srv := httptest.NewServer(mw(sealedBody))
	t.Cleanup(srv.Close)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL+"/", nil)
	require.NoError(t, err)
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
}

// CSRF stack: happy path + the two failure modes with a real Session pinned.
func TestCSRF_Stack(t *testing.T) {
	t.Parallel()
	svc, ss := newService(t)
	sess, err := ss.Create(t.Context(), 7, sessions.CreateOptions{})
	require.NoError(t, err)

	csrf := api.EncodeToken(sess.CSRFToken)

	// Session(CSRF(h)) so Session runs first (outer middleware on the way in),
	// pins ctx, then CSRF reads it.
	mw := middleware.Session(svc, slog.Default())(middleware.CSRF(slog.Default())(sealedBody))
	srv := httptest.NewServer(mw)
	t.Cleanup(srv.Close)

	makeReq := func(t *testing.T, method string) *http.Request {
		t.Helper()
		req, err := http.NewRequestWithContext(t.Context(), method, srv.URL+"/", nil)
		require.NoError(t, err)
		req.AddCookie(&http.Cookie{Name: api.SessionCookieName, Value: api.EncodeToken(sess.ID)})
		return req
	}

	t.Run("unsafe method missing header => 403", func(t *testing.T) {
		t.Parallel()
		resp, err := srv.Client().Do(makeReq(t, http.MethodPost))
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	})

	t.Run("unsafe method wrong header => 403", func(t *testing.T) {
		t.Parallel()
		req := makeReq(t, http.MethodPost)
		req.Header.Set(api.CSRFHeaderName, api.EncodeToken(make([]byte, sessions.IDLen)))
		resp, err := srv.Client().Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	})

	t.Run("unsafe method correct header => 200", func(t *testing.T) {
		t.Parallel()
		req := makeReq(t, http.MethodPost)
		req.Header.Set(api.CSRFHeaderName, csrf)
		resp, err := srv.Client().Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})
}

func TestSession_PanicsOnNilService(t *testing.T) {
	t.Parallel()
	assert.Panics(t, func() { _ = middleware.Session(nil, slog.Default()) })
}
