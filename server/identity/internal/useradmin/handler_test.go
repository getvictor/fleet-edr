package useradmin

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/identity/api"
	"github.com/fleetdm/edr/server/identity/internal/users"
)

// These unit tests drive the handler with in-memory fakes to exercise the error and edge branches that the DB-backed integration
// tests in server/identity/internal/tests do not reach (store failures -> 500, malformed bodies, the multi-role effective-role pick).

type fakeAuthZ struct{ allow bool }

func (f fakeAuthZ) Allow(_ context.Context, _ api.Action, _ api.Resource) (api.Decision, error) {
	if f.allow {
		return api.Decision{Allow: true, Reason: api.ReasonGranted}, nil
	}
	return api.Decision{Allow: false, Reason: api.ReasonNoMatchingRule}, nil
}

type fakeUsers struct {
	list    []users.AdminUser
	listErr error
	get     *users.AdminUser
	getErr  error
}

func (f *fakeUsers) List(context.Context) ([]users.AdminUser, error) { return f.list, f.listErr }
func (f *fakeUsers) GetAdmin(context.Context, int64) (*users.AdminUser, error) {
	return f.get, f.getErr
}

type fakeRoles struct {
	all       map[int64][]string
	allErr    error
	live      []string
	liveErr   error
	setErr    error
	statusErr error
}

func (f *fakeRoles) AllLiveBindings(context.Context) (map[int64][]string, error) {
	return f.all, f.allErr
}
func (f *fakeRoles) LiveGlobalRoles(context.Context, int64) ([]string, error) {
	return f.live, f.liveErr
}
func (f *fakeRoles) SetUserRole(context.Context, int64, string) ([]string, error) {
	return f.live, f.setErr
}
func (f *fakeRoles) SetUserStatus(context.Context, int64, string) error {
	return f.statusErr
}

func serve(h *Handler, method, path, body string, actor *api.Actor) *httptest.ResponseRecorder {
	mux := http.NewServeMux()
	h.RegisterAuthedRoutes(mux)
	r := httptest.NewRequestWithContext(context.Background(), method, path, strings.NewReader(body))
	if actor != nil {
		r = r.WithContext(api.WithActor(r.Context(), actor))
	}
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	return w
}

func superActor() *api.Actor {
	return &api.Actor{UserID: 999, Roles: []api.RoleBinding{{RoleID: roleSuperAdmin}}}
}

func TestHandler_listErrorsReturn500(t *testing.T) {
	t.Parallel()
	t.Run("user store error", func(t *testing.T) {
		t.Parallel()
		h := NewHandler(&fakeUsers{listErr: errors.New("boom")}, &fakeRoles{}, fakeAuthZ{allow: true}, nil, nil)
		w := serve(h, http.MethodGet, "/api/settings/users", "", superActor())
		assert.Equal(t, http.StatusInternalServerError, w.Code)
		assert.Contains(t, w.Body.String(), "internal")
	})
	t.Run("bindings store error", func(t *testing.T) {
		t.Parallel()
		h := NewHandler(&fakeUsers{list: []users.AdminUser{{ID: 1, Email: "a@x"}}},
			&fakeRoles{allErr: errors.New("boom")}, fakeAuthZ{allow: true}, nil, nil)
		w := serve(h, http.MethodGet, "/api/settings/users", "", superActor())
		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

func TestHandler_listPicksHighestEffectiveRole(t *testing.T) {
	t.Parallel()
	h := NewHandler(
		&fakeUsers{list: []users.AdminUser{
			{ID: 1, Email: "multi@x", Status: "active"},
			{ID: 2, Email: "norole@x", Status: "active"}, // no binding -> roles must serialize as [] and role as ""
		}},
		&fakeRoles{all: map[int64][]string{1: {"analyst", "admin"}}}, // legacy multi-binding on user 1 only
		fakeAuthZ{allow: true}, nil, nil)
	w := serve(h, http.MethodGet, "/api/settings/users", "", superActor())
	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
	body := w.Body.String()
	assert.Contains(t, body, `"role":"admin"`) // admin outranks analyst
	assert.Contains(t, body, `"role":""`)      // no-binding user
	assert.Contains(t, body, `"roles":[]`)     // serialized as array, never null
	assert.NotContains(t, body, `"roles":null`)
}

func TestHandler_forbiddenWhenChokepointDenies(t *testing.T) {
	t.Parallel()
	h := NewHandler(&fakeUsers{}, &fakeRoles{}, fakeAuthZ{allow: false}, nil, nil)
	w := serve(h, http.MethodGet, "/api/settings/users", "", superActor())
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestHandler_setRoleInvalidJSON(t *testing.T) {
	t.Parallel()
	h := NewHandler(&fakeUsers{}, &fakeRoles{}, fakeAuthZ{allow: true}, nil, nil)
	w := serve(h, http.MethodPut, "/api/settings/users/5/role", "{not json", superActor())
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "invalid_json")
}

func TestHandler_setRoleStoreErrorReturns500(t *testing.T) {
	t.Parallel()
	h := NewHandler(
		&fakeUsers{get: &users.AdminUser{ID: 5, Email: "t@x", Status: "active"}},
		&fakeRoles{live: []string{"analyst"}, setErr: errors.New("boom")},
		fakeAuthZ{allow: true}, nil, nil)
	w := serve(h, http.MethodPut, "/api/settings/users/5/role", `{"role":"senior_analyst"}`, superActor())
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestHandler_setRoleNotFound(t *testing.T) {
	t.Parallel()
	h := NewHandler(&fakeUsers{getErr: users.ErrNotFound}, &fakeRoles{},
		fakeAuthZ{allow: true}, nil, nil)
	w := serve(h, http.MethodPut, "/api/settings/users/5/role", `{"role":"analyst"}`, superActor())
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestHandler_setStatusStoreErrorReturns500(t *testing.T) {
	t.Parallel()
	h := NewHandler(
		&fakeUsers{get: &users.AdminUser{ID: 5, Email: "t@x", Status: "active"}},
		&fakeRoles{live: []string{"analyst"}, statusErr: errors.New("boom")},
		fakeAuthZ{allow: true}, nil, nil)
	w := serve(h, http.MethodPut, "/api/settings/users/5/status", `{"status":"disabled"}`, superActor())
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestHandler_lastAdminMapsTo409(t *testing.T) {
	t.Parallel()
	t.Run("set role", func(t *testing.T) {
		t.Parallel()
		h := NewHandler(
			&fakeUsers{get: &users.AdminUser{ID: 5, Email: "admin@x", Status: "active"}},
			&fakeRoles{live: []string{"admin"}, setErr: api.ErrLastAdmin},
			fakeAuthZ{allow: true}, nil, nil)
		w := serve(h, http.MethodPut, "/api/settings/users/5/role", `{"role":"analyst"}`, superActor())
		assert.Equal(t, http.StatusConflict, w.Code)
		assert.Contains(t, w.Body.String(), "last_admin")
	})
	t.Run("set status", func(t *testing.T) {
		t.Parallel()
		h := NewHandler(
			&fakeUsers{get: &users.AdminUser{ID: 5, Email: "admin@x", Status: "active"}},
			&fakeRoles{live: []string{"admin"}, statusErr: api.ErrLastAdmin},
			fakeAuthZ{allow: true}, nil, nil)
		w := serve(h, http.MethodPut, "/api/settings/users/5/status", `{"status":"disabled"}`, superActor())
		assert.Equal(t, http.StatusConflict, w.Code)
		assert.Contains(t, w.Body.String(), "last_admin")
	})
}
