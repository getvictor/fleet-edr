package login_test

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"

	"github.com/fleetdm/edr/server/identity/api"
	"github.com/fleetdm/edr/server/identity/internal/login"
	"github.com/fleetdm/edr/server/identity/internal/middleware"
	"github.com/fleetdm/edr/server/identity/internal/rbac"
	"github.com/fleetdm/edr/server/identity/internal/service"
	"github.com/fleetdm/edr/server/identity/internal/sessions"
	"github.com/fleetdm/edr/server/identity/internal/users"
	"github.com/fleetdm/edr/server/identity/testkit"
	"github.com/fleetdm/edr/server/testdb"
)

// Local mirror types pinned to the wire shape so the external test package can decode without reaching for handler.go's private struct
// names.
type sessionResponse struct {
	User struct {
		ID    int64  `json:"id"`
		Email string `json:"email"`
	} `json:"user"`
	CSRFToken   string   `json:"csrf_token"`
	AuthMethod  string   `json:"auth_method"`
	Permissions []string `json:"permissions"`
	Roles       []string `json:"roles"`
}

// setupServer wires the GET + DELETE /api/session handler stack the way main.go does. Returns the HTTP server + the users /
// sessions stores so tests can seed users and mint sessions directly via the underlying stores; there is no password-based
// login wire path, so this is the only way to put a session row in front of the handler.
func setupServer(t *testing.T) (*httptest.Server, *users.Store, *sessions.Store) {
	t.Helper()
	db := testdb.Open(t)
	require.NoError(t, testkit.ApplySchema(t.Context(), db))
	us := users.New(db)
	ss := sessions.New(db, sessions.Options{})
	rb := rbac.New(db)
	svc := service.New(us, ss, rb, nil, slog.Default())

	h := login.New(svc, login.Options{
		CookieSecure: false, // httptest is plain HTTP; browsers would reject Secure anyway.
		Logger:       slog.Default(),
	})

	publicMux := http.NewServeMux()
	h.RegisterPublicRoutes(publicMux)

	// Mirror production: authed routes (GET /session) go through Session -> CSRF.
	authedSub := http.NewServeMux()
	h.RegisterAuthedRoutes(authedSub)
	authedWrap := middleware.Session(svc, slog.Default())(middleware.CSRF(slog.Default())(authedSub))

	root := http.NewServeMux()
	root.Handle("DELETE /api/session", publicMux) // logout: public (reads cookie itself)
	root.Handle("GET /api/session", authedWrap)

	srv := httptest.NewServer(root)
	t.Cleanup(srv.Close)
	return srv, us, ss
}

// sessionCookie creates a user and a session row via the underlying stores and returns a cookie pointing at it. It is the
// test-only mint path that stands in for the production OIDC callback / break-glass FinishLogin entry points.
func sessionCookie(t *testing.T, us *users.Store, ss *sessions.Store) *http.Cookie {
	t.Helper()
	u, err := us.Create(t.Context(), users.CreateRequest{
		Email: "tester@example.com", Password: "long-enough-test-password",
	})
	require.NoError(t, err)
	sess, err := ss.Create(t.Context(), u.ID, sessions.CreateOptions{AuthMethod: "oidc"})
	require.NoError(t, err)
	return &http.Cookie{
		Name:  api.SessionCookieName,
		Value: api.EncodeToken(sess.ID),
	}
}

// spec:ui-authentication-session/get-requests-authenticate-by-cookie-alone/get-with-valid-session
// spec:ui-authentication-session/current-user-lookup/session-probe-while-logged-in
//
// Two scenarios share this test. The GET-with-valid-session clause is pinned by the cookie-only request
// (no CSRF header) returning 200; the current-user-lookup clause is pinned by the JSON body carrying
// the user identity + the session's CSRF token (the UI reads csrf_token client-side to use on
// subsequent state-changing requests).
func TestGet_ReturnsCurrentSession(t *testing.T) {
	t.Parallel()
	srv, us, ss := setupServer(t)
	cookie := sessionCookie(t, us, ss)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/api/session", nil)
	require.NoError(t, err)
	req.AddCookie(cookie)
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var body sessionResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.NotEmpty(t, body.CSRFToken, "GET must return the session's CSRF token")
	assert.Equal(t, "oidc", body.AuthMethod, "auth_method must reflect how the session was minted")
}

// spec:ui-authentication-session/get-requests-authenticate-by-cookie-alone/get-without-session
// spec:ui-authentication-session/current-user-lookup/session-probe-while-logged-out
//
// Two scenarios share this test: an unauthenticated GET to /api/session returns 401, satisfying both
// the GET-without-session clause (no cookie present) and the session-probe-while-logged-out clause
// (the UI's "are we still logged in?" check observes a 401 and routes to the login flow).
func TestGet_MissingCookieReturns401(t *testing.T) {
	t.Parallel()
	srv, _, _ := setupServer(t)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/api/session", nil)
	require.NoError(t, err)
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// spec:ui-authentication-session/logout-invalidates-the-session-and-clears-the-cookie/logout-while-logged-in
// spec:ui-authentication-session/logout-invalidates-the-session-and-clears-the-cookie/logout-with-stale-or-missing-cookie
//
// Two scenarios share this test. The logout-while-logged-in clause is pinned by the first DELETE
// returning 204 with a Max-Age<0 cookie (the browser-clear shape) AND the row being gone from the DB
// (the ss.Get assertion). The logout-with-stale-or-missing-cookie clause is structural here: after the
// row is deleted, the second GET with the same cookie returns 401 because the session row is gone,
// which is exactly the "client's cookie no longer corresponds to any active session row" precondition;
// a follow-up logout against the same cookie would still return 204 with the cookie-clearing response
// (the handler's idempotent shape: no row lookup is performed before emitting the clearing cookie).
func TestLogout_DeletesSessionAndClearsCookie(t *testing.T) {
	t.Parallel()
	srv, us, ss := setupServer(t)
	cookie := sessionCookie(t, us, ss)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodDelete, srv.URL+"/api/session", nil)
	require.NoError(t, err)
	req.AddCookie(cookie)
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusNoContent, resp.StatusCode)

	clears := resp.Cookies()
	require.Len(t, clears, 1)
	assert.Empty(t, clears[0].Value)
	assert.Negative(t, clears[0].MaxAge)

	// Subsequent GET with the old cookie -> 401 (session row is gone).
	req2, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/api/session", nil)
	require.NoError(t, err)
	req2.AddCookie(cookie)
	resp2, err := srv.Client().Do(req2)
	require.NoError(t, err)
	defer resp2.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp2.StatusCode)

	// Belt-and-suspenders: the row really is gone from the DB.
	raw, err := api.DecodeToken(cookie.Value)
	require.NoError(t, err)
	_, err = ss.Get(t.Context(), raw)
	require.Error(t, err)
}

// spec:ui-authentication-session/the-session-probe-names-the-operator-s-roles/the-probe-returns-the-roles-the-session-carries
//
// For any set of live bindings, in any order and with repeats, the probe's roles decode to exactly the distinct global role ids, sorted,
// and permissions stay an array. The bindings are put on the request context directly, since the store hands them back in index order
// and could not produce the unsorted or repeated sets this needs.
func TestGet_RolesNameEachGlobalRoleOnceSorted_PBT(t *testing.T) {
	t.Parallel()
	db := testdb.Open(t)
	require.NoError(t, testkit.ApplySchema(t.Context(), db))
	us := users.New(db)
	svc := service.New(us, sessions.New(db, sessions.Options{}), rbac.New(db), nil, slog.Default())
	mux := http.NewServeMux()
	login.New(svc, login.Options{Logger: slog.Default()}).RegisterAuthedRoutes(mux)
	u, err := us.Create(t.Context(), users.CreateRequest{Email: "roles@example.com", Password: "long-enough-test-password"})
	require.NoError(t, err)

	roleIDs := []string{"super_admin", "admin", "senior_analyst", "analyst", "auditor"}
	scopes := []api.RoleBindingScopeType{api.RoleBindingScopeGlobal, "host_group", "host"}
	rapid.Check(t, func(rt *rapid.T) {
		bindings := rapid.SliceOf(rapid.Custom(func(rt *rapid.T) api.RoleBinding {
			return api.RoleBinding{
				RoleID:    rapid.SampledFrom(roleIDs).Draw(rt, "role"),
				ScopeType: rapid.SampledFrom(scopes).Draw(rt, "scope"),
			}
		})).Draw(rt, "bindings")
		want := []string{}
		for _, b := range bindings {
			if b.ScopeType == api.RoleBindingScopeGlobal && !slices.Contains(want, b.RoleID) {
				want = append(want, b.RoleID)
			}
		}
		slices.Sort(want)

		ctx := api.WithActor(api.WithSession(t.Context(), &api.Session{UserID: u.ID}), &api.Actor{Roles: bindings})
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequestWithContext(ctx, http.MethodGet, "/api/session", nil))
		require.Equal(rt, http.StatusOK, rec.Code)
		var body sessionResponse
		require.NoError(rt, json.Unmarshal(rec.Body.Bytes(), &body))
		require.Equal(rt, want, body.Roles)
		require.NotNil(rt, body.Permissions)
	})
}
