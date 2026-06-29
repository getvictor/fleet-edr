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
	// provision* drive ProvisionUser; provisionID is the new id returned on success.
	provisionID    int64
	provisionErr   error
	provisionEmail string
	provisionRole  string
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
func (f *fakeRoles) ProvisionUser(_ context.Context, email, roleID string) (int64, error) {
	f.provisionEmail, f.provisionRole = email, roleID
	return f.provisionID, f.provisionErr
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
	return &api.Actor{Principal: api.UserPrincipal(999, ""), Roles: []api.RoleBinding{{RoleID: roleSuperAdmin}}}
}

func adminActor() *api.Actor {
	return &api.Actor{Principal: api.UserPrincipal(1, ""), Roles: []api.RoleBinding{{RoleID: roleAdmin}}}
}

type fakeAudit struct{ events []api.AuditEvent }

func (f *fakeAudit) Record(_ context.Context, e api.AuditEvent) error {
	f.events = append(f.events, e)
	return nil
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

func TestHandler_createPreProvisionsUser(t *testing.T) {
	t.Parallel()
	roles := &fakeRoles{provisionID: 42}
	audit := &fakeAudit{}
	h := NewHandler(&fakeUsers{}, roles, fakeAuthZ{allow: true}, audit, nil)
	w := serve(h, http.MethodPost, "/api/settings/users", `{"email":" Alice@Example.COM ","role":"senior_analyst"}`, superActor())

	require.Equal(t, http.StatusCreated, w.Code)
	// Email is normalised (lowercase + trimmed) and the role passes through to the store.
	assert.Equal(t, "alice@example.com", roles.provisionEmail)
	assert.Equal(t, "senior_analyst", roles.provisionRole)
	body := w.Body.String()
	assert.Contains(t, body, `"id":42`)
	assert.Contains(t, body, `"status":"provisioned"`)
	assert.Contains(t, body, `"role":"senior_analyst"`)
	assert.Contains(t, body, `"roles":["senior_analyst"]`)
	// Exactly one user.provisioned audit row carrying the assigned role and the new user as target.
	require.Len(t, audit.events, 1)
	assert.Equal(t, api.AuditUserProvisioned, audit.events[0].Action)
	assert.Equal(t, "user", audit.events[0].TargetType)
	assert.Equal(t, "42", audit.events[0].TargetID)
	assert.Equal(t, "senior_analyst", audit.events[0].Payload["role"])
}

func TestHandler_createSuperAdminAllowedForSuperActor(t *testing.T) {
	t.Parallel()
	roles := &fakeRoles{provisionID: 7}
	h := NewHandler(&fakeUsers{}, roles, fakeAuthZ{allow: true}, &fakeAudit{}, nil)
	w := serve(h, http.MethodPost, "/api/settings/users", `{"email":"root@example.io","role":"super_admin"}`, superActor())
	require.Equal(t, http.StatusCreated, w.Code)
	assert.Equal(t, "super_admin", roles.provisionRole)
}

func TestHandler_createValidationAndGuards(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name       string
		body       string
		actor      *api.Actor
		allow      bool
		provErr    error
		wantStatus int
		wantBody   string
	}{
		{"invite denied", `{"email":"a@x.io","role":"analyst"}`, superActor(), false, nil, http.StatusForbidden, ""},
		{"malformed json", `{nope`, superActor(), true, nil, http.StatusBadRequest, "invalid_json"},
		{"empty email", `{"email":"   ","role":"analyst"}`, superActor(), true, nil, http.StatusBadRequest, "invalid_email"},
		{"email without at", `{"email":"nope","role":"analyst"}`, superActor(), true, nil, http.StatusBadRequest, "invalid_email"},
		{"unknown role", `{"email":"a@x.io","role":"wizard"}`, superActor(), true, nil, http.StatusBadRequest, "invalid_role"},
		{"super_admin by admin actor", `{"email":"a@x.io","role":"super_admin"}`, adminActor(), true, nil, http.StatusForbidden, "super_admin_forbidden"},
		{"duplicate email", `{"email":"a@x.io","role":"analyst"}`, superActor(), true, api.ErrEmailExists, http.StatusConflict, "email_exists"},
		{"store error", `{"email":"a@x.io","role":"analyst"}`, superActor(), true, errors.New("boom"), http.StatusInternalServerError, "internal"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := NewHandler(&fakeUsers{}, &fakeRoles{provisionErr: tc.provErr}, fakeAuthZ{allow: tc.allow}, &fakeAudit{}, nil)
			w := serve(h, http.MethodPost, "/api/settings/users", tc.body, tc.actor)
			assert.Equal(t, tc.wantStatus, w.Code)
			if tc.wantBody != "" {
				assert.Contains(t, w.Body.String(), tc.wantBody)
			}
		})
	}
}
