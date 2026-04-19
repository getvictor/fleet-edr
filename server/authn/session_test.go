package authn

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/sessions"
	"github.com/fleetdm/edr/server/store"
)

// newSessionsStore returns a ready-to-use sessions.Store backed by a fresh test DB.
// A stub users row (id=42, and anything else tests reference) is inserted first so the
// Phase 3 FK sessions.user_id → users(id) constraint doesn't reject the insert.
func newSessionsStore(t *testing.T) *sessions.Store {
	t.Helper()
	s := store.OpenTestStore(t)
	for _, uid := range []int64{1, 7, 42} {
		_, err := s.DB().ExecContext(t.Context(),
			`INSERT INTO users (id, email, password_hash, password_salt) VALUES (?, ?, ?, ?)`,
			uid, "authn-stub@test", []byte("stub-hash"), []byte("stub-salt"))
		if err != nil {
			// Email is UNIQUE so the 2nd+ inserts with the same email fail. Use unique.
			_, err2 := s.DB().ExecContext(t.Context(),
				`INSERT INTO users (id, email, password_hash, password_salt) VALUES (?, ?, ?, ?)`,
				uid, "authn-stub-"+fmtInt(uid)+"@test", []byte("stub-hash"), []byte("stub-salt"))
			if err2 != nil {
				t.Fatalf("seed stub user %d: %v / %v", uid, err, err2)
			}
		}
	}
	return sessions.New(s.DB(), sessions.Options{})
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
// Tests use it to distinguish "middleware let me through" (body == "ok") from
// "middleware short-circuited with an error" (status != 200 and body is JSON).
var sealedBody = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
	_, _ = io.WriteString(w, "ok")
})

func TestSession_MissingCookieReturns401(t *testing.T) {
	st := newSessionsStore(t)
	mw := Session(st, slog.Default())
	srv := httptest.NewServer(mw(sealedBody))
	t.Cleanup(srv.Close)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/", nil)
	require.NoError(t, err)
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestSession_UnknownCookieReturns401(t *testing.T) {
	st := newSessionsStore(t)
	mw := Session(st, slog.Default())
	srv := httptest.NewServer(mw(sealedBody))
	t.Cleanup(srv.Close)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/", nil)
	require.NoError(t, err)
	// 32 zero bytes, base64url — never matches a real session.
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: EncodeSessionID(make([]byte, sessions.IDLen))})
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestSession_MalformedCookieReturns401(t *testing.T) {
	st := newSessionsStore(t)
	mw := Session(st, slog.Default())
	srv := httptest.NewServer(mw(sealedBody))
	t.Cleanup(srv.Close)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/", nil)
	require.NoError(t, err)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "not-base64-@#$%"})
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestSession_ValidCookieLetsHandlerRun(t *testing.T) {
	st := newSessionsStore(t)
	sess, err := st.Create(t.Context(), 42)
	require.NoError(t, err)

	mw := Session(st, slog.Default())
	var sawUserID int64
	var sawSession *sessions.Session
	srv := httptest.NewServer(mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		uid, _ := UserIDFromContext(r.Context())
		sawUserID = uid
		s, _ := SessionFromContext(r.Context())
		sawSession = s
		w.WriteHeader(http.StatusOK)
	})))
	t.Cleanup(srv.Close)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/", nil)
	require.NoError(t, err)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: EncodeSessionID(sess.ID)})
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, int64(42), sawUserID)
	require.NotNil(t, sawSession)
	assert.Equal(t, sess.CSRFToken, sawSession.CSRFToken)
}

// TestCSRF_SafeMethodPassesThrough — a GET never needs a CSRF header even if one of
// the authenticated admin surfaces ever ends up behind the CSRF middleware.
func TestCSRF_SafeMethodPassesThrough(t *testing.T) {
	mw := CSRF(slog.Default())
	srv := httptest.NewServer(mw(sealedBody))
	t.Cleanup(srv.Close)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/", nil)
	require.NoError(t, err)
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

// TestCSRF_MisconfiguredReturns500 — CSRF outside Session (no session on ctx for an
// unsafe method) is a programming error; we surface it as 500 not 401 so the ops team
// pages on server misconfiguration rather than assuming a bad token.
func TestCSRF_MisconfiguredReturns500(t *testing.T) {
	mw := CSRF(slog.Default())
	srv := httptest.NewServer(mw(sealedBody))
	t.Cleanup(srv.Close)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL+"/", nil)
	require.NoError(t, err)
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
}

// TestCSRF_Stack happy path + the two failure modes with a real Session pinned.
func TestCSRF_Stack(t *testing.T) {
	st := newSessionsStore(t)
	sess, err := st.Create(t.Context(), 7)
	require.NoError(t, err)

	csrf := EncodeSessionID(sess.CSRFToken)

	// Middleware order: outer CSRF, inner Session. At request time, Session runs first
	// (wraps the request on the way in), CSRF checks afterwards — but they share ctx
	// only because CSRF invokes `next` which is Session(sealedBody). So we actually
	// want Session(CSRF(sealedBody)) — Session runs first, CSRF sees ctx it populated.
	mw := Session(st, slog.Default())(CSRF(slog.Default())(sealedBody))
	srv := httptest.NewServer(mw)
	t.Cleanup(srv.Close)

	makeReq := func(t *testing.T, method string) *http.Request {
		t.Helper()
		req, err := http.NewRequestWithContext(t.Context(), method, srv.URL+"/", nil)
		require.NoError(t, err)
		req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: EncodeSessionID(sess.ID)})
		return req
	}

	t.Run("unsafe method missing header → 403", func(t *testing.T) {
		resp, err := srv.Client().Do(makeReq(t, http.MethodPost))
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	})

	t.Run("unsafe method wrong header → 403", func(t *testing.T) {
		req := makeReq(t, http.MethodPost)
		req.Header.Set(CSRFHeaderName, EncodeSessionID(make([]byte, sessions.IDLen)))
		resp, err := srv.Client().Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	})

	t.Run("unsafe method correct header → 200", func(t *testing.T) {
		req := makeReq(t, http.MethodPost)
		req.Header.Set(CSRFHeaderName, csrf)
		resp, err := srv.Client().Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})
}

func TestSession_PanicsOnNilStore(t *testing.T) {
	assert.Panics(t, func() { _ = Session(nil, slog.Default()) })
}
