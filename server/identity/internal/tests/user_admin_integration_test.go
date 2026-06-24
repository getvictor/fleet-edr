package tests

import (
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/identity/api"
	"github.com/fleetdm/edr/server/identity/internal/rbac"
)

// newUserAdminEnv builds an identity with schema applied and returns the DB plus the authed mux carrying the user-management routes.
// Reuses newServiceAccountIdentity (a full identity wiring); the SA signing key it sets is harmless here.
func newUserAdminEnv(t *testing.T) (*sqlx.DB, http.Handler) {
	t.Helper()
	id, db := newServiceAccountIdentity(t)
	mux := http.NewServeMux()
	id.RegisterAuthedRoutes(mux)
	return db, mux
}

// actorWithRole builds a synthetic authenticated actor with a single global role binding, as the session middleware would pin.
func actorWithRole(uid int64, role string) *api.Actor {
	return &api.Actor{
		UserID: uid, AuthMethod: "oidc", SessionFresh: true,
		Roles: []api.RoleBinding{{
			UserID: uid, RoleID: role, ScopeType: api.RoleBindingScopeGlobal, ScopeID: api.RoleBindingScopeWildcard,
		}},
	}
}

func bindGlobalRole(t *testing.T, db *sqlx.DB, uid int64, role string) {
	t.Helper()
	_, err := db.ExecContext(t.Context(),
		"INSERT INTO role_bindings (user_id, role_id, scope_type, scope_id) VALUES (?, ?, 'global', '*')", uid, role)
	require.NoError(t, err)
}

func seedUserWithRole(t *testing.T, db *sqlx.DB, email, role string) int64 {
	t.Helper()
	uid := seedUser(t, db, email)
	bindGlobalRole(t, db, uid, role)
	return uid
}

func userReq(t *testing.T, mux http.Handler, actor *api.Actor, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	r := httptest.NewRequestWithContext(t.Context(), method, path, rdr)
	if actor != nil {
		r = r.WithContext(api.WithActor(r.Context(), actor))
	}
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	return w
}

func globalRoleIDs(t *testing.T, db *sqlx.DB, uid int64) []string {
	t.Helper()
	roles := []string{}
	require.NoError(t, db.SelectContext(t.Context(), &roles,
		"SELECT role_id FROM role_bindings WHERE user_id = ? AND scope_type = 'global' ORDER BY role_id", uid))
	return roles
}

func userStatus(t *testing.T, db *sqlx.DB, uid int64) string {
	t.Helper()
	var s string
	require.NoError(t, db.GetContext(t.Context(), &s, "SELECT status FROM users WHERE id = ?", uid))
	return s
}

func auditRows(t *testing.T, db *sqlx.DB, action, targetID string) int {
	t.Helper()
	var n int
	require.NoError(t, db.GetContext(t.Context(), &n,
		"SELECT COUNT(*) FROM audit_events WHERE action = ? AND target_id = ?", action, targetID))
	return n
}

func auditPayload(t *testing.T, db *sqlx.DB, action, targetID string) string {
	t.Helper()
	var p sql.NullString
	require.NoError(t, db.GetContext(t.Context(), &p,
		"SELECT payload FROM audit_events WHERE action = ? AND target_id = ? ORDER BY id DESC LIMIT 1", action, targetID))
	return p.String
}

func TestUserAdmin_listSetRoleAndDisable(t *testing.T) {
	t.Parallel()

	t.Run("spec:server-identity-authorization/operators-manage-users-and-their-roles-through-an-audited-api/listing-users-returns-each-user-with-role-and-status", func(t *testing.T) {
		t.Parallel()
		db, mux := newUserAdminEnv(t)
		adminID := seedUserWithRole(t, db, "admin@ua.local", "admin")
		seedUserWithRole(t, db, "ana@ua.local", "analyst")

		w := userReq(t, mux, actorWithRole(adminID, "admin"), http.MethodGet, "/api/settings/users", "")
		require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
		var resp struct {
			Users []struct {
				ID     int64  `json:"id"`
				Email  string `json:"email"`
				Role   string `json:"role"`
				Status string `json:"status"`
			} `json:"users"`
		}
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		byEmail := map[string]string{}
		for _, u := range resp.Users {
			byEmail[u.Email] = u.Role
			assert.Equal(t, "active", u.Status)
		}
		assert.Equal(t, "admin", byEmail["admin@ua.local"])
		assert.Equal(t, "analyst", byEmail["ana@ua.local"])
	})

	t.Run("spec:server-identity-authorization/user-management-is-gated-by-a-dedicated-admin-action/admin-holds-the-user-management-action", func(t *testing.T) {
		t.Parallel()
		db, mux := newUserAdminEnv(t)
		adminID := seedUserWithRole(t, db, "admin2@ua.local", "admin")
		target := seedUserWithRole(t, db, "promote@ua.local", "analyst")

		// An admin actor (not super_admin) successfully sets a role: the chokepoint grants user.manage to admin.
		w := userReq(t, mux, actorWithRole(adminID, "admin"), http.MethodPut,
			"/api/settings/users/"+strconv.FormatInt(target, 10)+"/role", `{"role":"senior_analyst"}`)
		require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
	})

	t.Run("spec:server-identity-authorization/operators-manage-users-and-their-roles-through-an-audited-api/setting-a-role-replaces-the-global-binding-and-is-audited", func(t *testing.T) {
		t.Parallel()
		db, mux := newUserAdminEnv(t)
		adminID := seedUserWithRole(t, db, "admin3@ua.local", "admin")
		target := seedUserWithRole(t, db, "ana2@ua.local", "analyst")
		tid := strconv.FormatInt(target, 10)

		w := userReq(t, mux, actorWithRole(adminID, "super_admin"), http.MethodPut,
			"/api/settings/users/"+tid+"/role", `{"role":"senior_analyst"}`)
		require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())

		// Exactly one global binding remains, for the new role.
		assert.Equal(t, []string{"senior_analyst"}, globalRoleIDs(t, db, target))
		// One audit row records the change with from + to.
		assert.Equal(t, 1, auditRows(t, db, "authz.role_binding.update", tid))
		payload := auditPayload(t, db, "authz.role_binding.update", tid)
		assert.Contains(t, payload, "analyst")
		assert.Contains(t, payload, "senior_analyst")
	})

	t.Run("spec:server-identity-authorization/operators-manage-users-and-their-roles-through-an-audited-api/disabling-a-user-is-audited-and-blocks-access", func(t *testing.T) {
		t.Parallel()
		db, mux := newUserAdminEnv(t)
		adminID := seedUserWithRole(t, db, "admin4@ua.local", "admin")
		target := seedUserWithRole(t, db, "victim@ua.local", "analyst")
		tid := strconv.FormatInt(target, 10)

		w := userReq(t, mux, actorWithRole(adminID, "super_admin"), http.MethodPut,
			"/api/settings/users/"+tid+"/status", `{"status":"disabled"}`)
		require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
		assert.Equal(t, "disabled", userStatus(t, db, target))
		assert.Equal(t, 1, auditRows(t, db, "user.disabled", tid))
	})
}

// TestUserAdmin_edgeCases shares one env (db + mux) across its subtests, so the subtests run serially; the parent is parallel only
// with respect to other top-level tests, which is safe because newUserAdminEnv gives it an isolated database.
func TestUserAdmin_edgeCases(t *testing.T) { //nolint:tparallel // subtests share one env (db + mux) and run serially by design; see the doc comment above
	t.Parallel()
	db, mux := newUserAdminEnv(t)
	operator := seedUser(t, db, "edge-op@ua.local")
	actor := actorWithRole(operator, "super_admin")

	t.Run("invalid role is rejected", func(t *testing.T) {
		target := seedUserWithRole(t, db, "edge1@ua.local", "analyst")
		w := userReq(t, mux, actor, http.MethodPut,
			"/api/settings/users/"+strconv.FormatInt(target, 10)+"/role", `{"role":"wizard"}`)
		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), "invalid_role")
	})

	t.Run("invalid status is rejected", func(t *testing.T) {
		target := seedUserWithRole(t, db, "edge2@ua.local", "analyst")
		w := userReq(t, mux, actor, http.MethodPut,
			"/api/settings/users/"+strconv.FormatInt(target, 10)+"/status", `{"status":"frozen"}`)
		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), "invalid_status")
	})

	t.Run("unknown user is not found", func(t *testing.T) {
		w := userReq(t, mux, actor, http.MethodPut, "/api/settings/users/999999/role", `{"role":"analyst"}`)
		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("non-numeric id is rejected", func(t *testing.T) {
		w := userReq(t, mux, actor, http.MethodPut, "/api/settings/users/abc/role", `{"role":"analyst"}`)
		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), "invalid_id")
	})

	t.Run("setting the role the user already holds is a no-op without an audit row", func(t *testing.T) {
		target := seedUserWithRole(t, db, "edge3@ua.local", "auditor")
		tid := strconv.FormatInt(target, 10)
		w := userReq(t, mux, actor, http.MethodPut, "/api/settings/users/"+tid+"/role", `{"role":"auditor"}`)
		require.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, 0, auditRows(t, db, "authz.role_binding.update", tid))
		assert.Equal(t, 0, auditRows(t, db, "authz.role_binding.create", tid))
	})

	t.Run("first grant to a user with no binding audits a create", func(t *testing.T) {
		target := seedUser(t, db, "edge4@ua.local") // no role binding
		tid := strconv.FormatInt(target, 10)
		w := userReq(t, mux, actor, http.MethodPut, "/api/settings/users/"+tid+"/role", `{"role":"analyst"}`)
		require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
		assert.Equal(t, []string{"analyst"}, globalRoleIDs(t, db, target))
		assert.Equal(t, 1, auditRows(t, db, "authz.role_binding.create", tid))
	})

	t.Run("disabling then enabling audits both transitions", func(t *testing.T) {
		target := seedUserWithRole(t, db, "edge5@ua.local", "analyst")
		tid := strconv.FormatInt(target, 10)
		dw := userReq(t, mux, actor, http.MethodPut, "/api/settings/users/"+tid+"/status", `{"status":"disabled"}`)
		require.Equal(t, http.StatusOK, dw.Code)
		ew := userReq(t, mux, actor, http.MethodPut, "/api/settings/users/"+tid+"/status", `{"status":"active"}`)
		require.Equal(t, http.StatusOK, ew.Code)
		assert.Equal(t, "active", userStatus(t, db, target))
		assert.Equal(t, 1, auditRows(t, db, "user.disabled", tid))
		assert.Equal(t, 1, auditRows(t, db, "user.enabled", tid))
	})
}

// TestUserAdmin_disabledUserBlocked proves the disable mutation actually blocks access: LoadActor (run on every authed request by the
// session middleware) rejects a disabled user with ErrUserDisabled, and re-enabling restores access. This is the enforcement half of
// the "disabling blocks access" scenario, complementing the status+audit assertions above.
// spec:server-identity-authorization/operators-manage-users-and-their-roles-through-an-audited-api/disabling-a-user-is-audited-and-blocks-access
func TestUserAdmin_disabledUserBlocked(t *testing.T) {
	t.Parallel()
	id, db := newServiceAccountIdentity(t)
	mux := http.NewServeMux()
	id.RegisterAuthedRoutes(mux)
	operator := seedUser(t, db, "op-disable@ua.local")
	target := seedUserWithRole(t, db, "blockme@ua.local", "analyst")
	tid := strconv.FormatInt(target, 10)
	actor := actorWithRole(operator, "super_admin")

	// Before disable, the actor loads.
	_, err := id.Service().LoadActor(t.Context(), target, "oidc", false)
	require.NoError(t, err)

	require.Equal(t, http.StatusOK,
		userReq(t, mux, actor, http.MethodPut, "/api/settings/users/"+tid+"/status", `{"status":"disabled"}`).Code)
	// After disable, every authed request for this user is rejected at actor-load time.
	_, err = id.Service().LoadActor(t.Context(), target, "oidc", false)
	require.ErrorIs(t, err, api.ErrUserDisabled)

	require.Equal(t, http.StatusOK,
		userReq(t, mux, actor, http.MethodPut, "/api/settings/users/"+tid+"/status", `{"status":"active"}`).Code)
	// Re-enabling restores access.
	_, err = id.Service().LoadActor(t.Context(), target, "oidc", false)
	require.NoError(t, err)
}

// TestUserAdmin_concurrentDisableKeepsOneAdmin fires two disables of the last two admins at the same time against the real store and
// MySQL. The atomic guard (sentinel row lock + READ COMMITTED re-count) must let exactly one through and reject the other, leaving at
// least one active admin. Without the lock both would pass their independent count and the deployment would be left admin-less.
// spec:server-identity-authorization/user-management-guardrails-prevent-lockout-and-privilege-escalation/concurrent-demotions-cannot-both-remove-the-last-admin
func TestUserAdmin_concurrentDisableKeepsOneAdmin(t *testing.T) {
	t.Parallel()
	_, db := newServiceAccountIdentity(t)
	store := rbac.New(db)
	a := seedUserWithRole(t, db, "admin-a@ua.local", "admin")
	b := seedUserWithRole(t, db, "admin-b@ua.local", "admin")

	var wg sync.WaitGroup
	errs := make([]error, 2)
	wg.Add(2)
	go func() { defer wg.Done(); errs[0] = store.SetUserStatus(t.Context(), a, "disabled") }()
	go func() { defer wg.Done(); errs[1] = store.SetUserStatus(t.Context(), b, "disabled") }()
	wg.Wait()

	var rejected, succeeded int
	for _, e := range errs {
		switch {
		case errors.Is(e, api.ErrLastAdmin):
			rejected++
		case e == nil:
			succeeded++
		default:
			t.Fatalf("unexpected error: %v", e)
		}
	}
	assert.Equal(t, 1, succeeded, "exactly one disable should succeed")
	assert.Equal(t, 1, rejected, "exactly one disable should be rejected as last_admin")

	var active int
	require.NoError(t, db.GetContext(t.Context(), &active, `
		SELECT COUNT(DISTINCT rb.user_id) FROM role_bindings rb JOIN users u ON u.id = rb.user_id
		WHERE rb.role_id IN ('admin','super_admin') AND rb.scope_type='global'
		  AND (rb.expires_at IS NULL OR rb.expires_at > NOW(6)) AND u.status='active'`))
	assert.GreaterOrEqual(t, active, 1, "at least one active admin must remain")
}

func TestUserAdmin_unauthorizedDenied(t *testing.T) {
	t.Parallel()
	// spec:server-identity-authorization/user-management-is-gated-by-a-dedicated-admin-action/a-role-without-the-grant-is-denied
	db, mux := newUserAdminEnv(t)
	analystID := seedUserWithRole(t, db, "ana3@ua.local", "analyst")
	target := seedUserWithRole(t, db, "t@ua.local", "analyst")

	// List requires user.read; an analyst lacks it.
	lw := userReq(t, mux, actorWithRole(analystID, "analyst"), http.MethodGet, "/api/settings/users", "")
	assert.Equal(t, http.StatusForbidden, lw.Code)

	// Mutations require user.manage; an analyst lacks it.
	rw := userReq(t, mux, actorWithRole(analystID, "analyst"), http.MethodPut,
		"/api/settings/users/"+strconv.FormatInt(target, 10)+"/role", `{"role":"auditor"}`)
	assert.Equal(t, http.StatusForbidden, rw.Code)
}

func TestUserAdmin_guardrails(t *testing.T) {
	t.Parallel()

	t.Run("spec:server-identity-authorization/user-management-guardrails-prevent-lockout-and-privilege-escalation/the-last-admin-cannot-be-demoted-or-disabled", func(t *testing.T) {
		t.Parallel()
		db, mux := newUserAdminEnv(t)
		// The target is the only admin-tier user in the DB. The acting operator is a synthetic super_admin not bound in the DB.
		operator := seedUser(t, db, "op@ua.local")
		lastAdmin := seedUserWithRole(t, db, "only-admin@ua.local", "admin")
		aid := strconv.FormatInt(lastAdmin, 10)
		actor := actorWithRole(operator, "super_admin")

		demote := userReq(t, mux, actor, http.MethodPut, "/api/settings/users/"+aid+"/role", `{"role":"analyst"}`)
		assert.Equal(t, http.StatusConflict, demote.Code)
		assert.Contains(t, demote.Body.String(), "last_admin")
		assert.Equal(t, []string{"admin"}, globalRoleIDs(t, db, lastAdmin), "demote left the binding unchanged")

		disable := userReq(t, mux, actor, http.MethodPut, "/api/settings/users/"+aid+"/status", `{"status":"disabled"}`)
		assert.Equal(t, http.StatusConflict, disable.Code)
		assert.Contains(t, disable.Body.String(), "last_admin")
		assert.Equal(t, "active", userStatus(t, db, lastAdmin), "disable left the status unchanged")
	})

	t.Run("spec:server-identity-authorization/user-management-guardrails-prevent-lockout-and-privilege-escalation/an-operator-cannot-change-their-own-role", func(t *testing.T) {
		t.Parallel()
		db, mux := newUserAdminEnv(t)
		// A second admin exists so the last-admin guard is not what trips; the self guard must.
		seedUserWithRole(t, db, "other-admin@ua.local", "admin")
		self := seedUserWithRole(t, db, "self@ua.local", "admin")
		sid := strconv.FormatInt(self, 10)
		actor := actorWithRole(self, "super_admin")

		role := userReq(t, mux, actor, http.MethodPut, "/api/settings/users/"+sid+"/role", `{"role":"analyst"}`)
		assert.Equal(t, http.StatusConflict, role.Code)
		assert.Contains(t, role.Body.String(), "cannot_modify_self")

		status := userReq(t, mux, actor, http.MethodPut, "/api/settings/users/"+sid+"/status", `{"status":"disabled"}`)
		assert.Equal(t, http.StatusConflict, status.Code)
		assert.Contains(t, status.Body.String(), "cannot_modify_self")
	})

	t.Run("spec:server-identity-authorization/user-management-guardrails-prevent-lockout-and-privilege-escalation/break-glass-users-cannot-be-modified", func(t *testing.T) {
		t.Parallel()
		db, mux := newUserAdminEnv(t)
		operator := seedUserWithRole(t, db, "op2@ua.local", "admin")
		bg := seedUserWithRole(t, db, "breakglass@ua.local", "admin")
		_, err := db.ExecContext(t.Context(), "UPDATE users SET is_breakglass = 1 WHERE id = ?", bg)
		require.NoError(t, err)
		bid := strconv.FormatInt(bg, 10)
		actor := actorWithRole(operator, "super_admin")

		w := userReq(t, mux, actor, http.MethodPut, "/api/settings/users/"+bid+"/role", `{"role":"analyst"}`)
		assert.Equal(t, http.StatusConflict, w.Code)
		assert.Contains(t, w.Body.String(), "breakglass_immutable")
		assert.Equal(t, []string{"admin"}, globalRoleIDs(t, db, bg))
	})

	t.Run("spec:server-identity-authorization/user-management-guardrails-prevent-lockout-and-privilege-escalation/only-a-super-admin-may-grant-the-super-admin-role", func(t *testing.T) {
		t.Parallel()
		db, mux := newUserAdminEnv(t)
		adminID := seedUserWithRole(t, db, "plainadmin@ua.local", "admin")
		target := seedUserWithRole(t, db, "candidate@ua.local", "analyst")
		tid := strconv.FormatInt(target, 10)
		// An admin actor (not super_admin) cannot grant super_admin.
		grant := userReq(t, mux, actorWithRole(adminID, "admin"), http.MethodPut,
			"/api/settings/users/"+tid+"/role", `{"role":"super_admin"}`)
		assert.Equal(t, http.StatusForbidden, grant.Code)
		assert.Contains(t, grant.Body.String(), "super_admin_forbidden")
		assert.Equal(t, []string{"analyst"}, globalRoleIDs(t, db, target))

		// An admin actor cannot modify a user who currently holds super_admin either.
		super := seedUserWithRole(t, db, "theboss@ua.local", "super_admin")
		modBoss := userReq(t, mux, actorWithRole(adminID, "admin"), http.MethodPut,
			"/api/settings/users/"+strconv.FormatInt(super, 10)+"/role", `{"role":"analyst"}`)
		assert.Equal(t, http.StatusForbidden, modBoss.Code)
		assert.Contains(t, modBoss.Body.String(), "super_admin_forbidden")
	})
}
