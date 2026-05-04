package login_test

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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

// Local mirror types pinned to the wire shape so the external test
// package can decode without reaching for handler.go's private struct
// names.
type sessionResponse struct {
	User struct {
		ID    int64  `json:"id"`
		Email string `json:"email"`
	} `json:"user"`
	CSRFToken string `json:"csrf_token"`
}

type errBody struct {
	Error string `json:"error"`
}

// setupServer wires a full session handler + middleware stack backed by real
// stores, exactly like main.go does. Returns the HTTP server + the userStore
// + the sessions store so tests can seed an initial user / verify deletion.
func setupServer(t *testing.T, ratePerMinute int) (*httptest.Server, *users.Store, *sessions.Store) {
	t.Helper()
	db := testdb.Open(t)
	require.NoError(t, testkit.ApplySchema(t.Context(), db))
	us := users.New(db)
	ss := sessions.New(db, sessions.Options{})
	rb := rbac.New(db)
	svc := service.New(us, ss, rb, slog.Default())

	h := login.New(svc, login.Options{
		RatePerMinute: ratePerMinute,
		CookieSecure:  false, // httptest is plain HTTP; browsers would reject Secure anyway.
		Logger:        slog.Default(),
	})

	publicMux := http.NewServeMux()
	h.RegisterPublicRoutes(publicMux)

	// Mirror production: authed routes (GET /session) go through Session -> CSRF.
	authedSub := http.NewServeMux()
	h.RegisterAuthedRoutes(authedSub)
	authedWrap := middleware.Session(svc, slog.Default())(middleware.CSRF(slog.Default())(authedSub))

	root := http.NewServeMux()
	root.Handle("POST /api/session", publicMux)   // login: public
	root.Handle("DELETE /api/session", publicMux) // logout: public (reads cookie itself)
	root.Handle("GET /api/session", authedWrap)

	srv := httptest.NewServer(root)
	t.Cleanup(srv.Close)
	return srv, us, ss
}

func postJSON(t *testing.T, srv *httptest.Server, path string, body any) *http.Response {
	t.Helper()
	buf := new(bytes.Buffer)
	require.NoError(t, json.NewEncoder(buf).Encode(body))
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL+path, buf)
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	return resp
}

func TestLogin_HappyPath(t *testing.T) {
	srv, us, _ := setupServer(t, 30)
	_, err := us.Create(t.Context(), users.CreateRequest{Email: "admin@example.com", Password: "rightpassword"})
	require.NoError(t, err)

	resp := postJSON(t, srv, "/api/session", map[string]string{
		"email": "admin@example.com", "password": "rightpassword",
	})
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	cookies := resp.Cookies()
	require.Len(t, cookies, 1)
	c := cookies[0]
	assert.Equal(t, api.SessionCookieName, c.Name)
	assert.True(t, c.HttpOnly)
	assert.Equal(t, http.SameSiteLaxMode, c.SameSite)
	assert.NotEmpty(t, c.Value)

	var body sessionResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "admin@example.com", body.User.Email)
	assert.Positive(t, body.User.ID)
	assert.NotEmpty(t, body.CSRFToken)
}

func TestLogin_WrongPasswordReturnsGeneric401(t *testing.T) {
	srv, us, _ := setupServer(t, 30)
	_, err := us.Create(t.Context(), users.CreateRequest{Email: "admin@example.com", Password: "rightpassword"})
	require.NoError(t, err)

	resp := postJSON(t, srv, "/api/session", map[string]string{
		"email": "admin@example.com", "password": "wrong",
	})
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	var body errBody
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "invalid_credentials", body.Error, "must not leak whether email exists")
}

func TestLogin_UnknownEmailReturnsGeneric401(t *testing.T) {
	srv, _, _ := setupServer(t, 30)
	resp := postJSON(t, srv, "/api/session", map[string]string{
		"email": "nobody@example.com", "password": "anything",
	})
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	var body errBody
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "invalid_credentials", body.Error,
		"unknown-email 401 must be indistinguishable from wrong-password 401")
}

func TestLogin_RateLimit(t *testing.T) {
	srv, us, _ := setupServer(t, 2) // 2/min so burst of 2, then 429
	_, err := us.Create(t.Context(), users.CreateRequest{Email: "admin@example.com", Password: "pw"})
	require.NoError(t, err)

	for range 2 {
		resp := postJSON(t, srv, "/api/session", map[string]string{
			"email": "admin@example.com", "password": "wrong",
		})
		resp.Body.Close()
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	}

	resp := postJSON(t, srv, "/api/session", map[string]string{
		"email": "admin@example.com", "password": "wrong",
	})
	defer resp.Body.Close()
	assert.Equal(t, http.StatusTooManyRequests, resp.StatusCode)
	assert.Equal(t, "60", resp.Header.Get("Retry-After"))
}

func TestLogin_MalformedBody(t *testing.T) {
	srv, _, _ := setupServer(t, 30)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL+"/api/session",
		bytes.NewBufferString("{"))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// sessionCookie logs in and returns the resulting session cookie + CSRF token.
func sessionCookie(t *testing.T, srv *httptest.Server, us *users.Store) (*http.Cookie, string) {
	t.Helper()
	_, err := us.Create(t.Context(), users.CreateRequest{Email: "admin@example.com", Password: "pw"})
	require.NoError(t, err)

	resp := postJSON(t, srv, "/api/session", map[string]string{
		"email": "admin@example.com", "password": "pw",
	})
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var body sessionResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	cookies := resp.Cookies()
	require.Len(t, cookies, 1)
	return cookies[0], body.CSRFToken
}

func TestGet_ReturnsCurrentSession(t *testing.T) {
	srv, us, _ := setupServer(t, 30)
	cookie, csrf := sessionCookie(t, srv, us)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/api/session", nil)
	require.NoError(t, err)
	req.AddCookie(cookie)
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var body sessionResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, csrf, body.CSRFToken, "GET must return the same CSRF token as login issued")
}

func TestGet_MissingCookieReturns401(t *testing.T) {
	srv, _, _ := setupServer(t, 30)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/api/session", nil)
	require.NoError(t, err)
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestLogout_DeletesSessionAndClearsCookie(t *testing.T) {
	srv, us, ss := setupServer(t, 30)
	cookie, _ := sessionCookie(t, srv, us)

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
