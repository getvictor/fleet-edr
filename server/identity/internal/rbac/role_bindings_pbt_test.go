//go:build integration

package rbac_test

import (
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"

	"github.com/fleetdm/edr/server/identity/api"
	"github.com/fleetdm/edr/server/identity/internal/rbac"
)

// TestListLiveBindings_ExpiryBoundary_PBT generates random expires_at
// timestamps and asserts the SQL filter "expires_at IS NULL OR
// expires_at > NOW(6)" stays correct across the boundary. The
// existing example-based TestListLiveBindings_ExpiredBindingsFiltered
// pins three named cases (past, future, NULL); this PBT explores the
// space between them so a regression that swaps `>` for `>=` (or
// drops the NULL clause) trips on the next run.
//
// Property: a binding with expires_at=t is returned iff t is NULL OR
// t is strictly after the wall-clock NOW(6) at SELECT time.
//
// Generation strategy: rapid draws an offset in (-2h, +2h) skipping a
// 250ms band around zero. The skip avoids a known race (the
// timestamp's nominal offset puts it past NOW(6) at INSERT time, but
// the SELECT runs on a slightly-later NOW(6) and the row no longer
// matches). 250ms is large enough to absorb test runner / DB roundtrip
// jitter without trivializing the boundary check.
func TestListLiveBindings_ExpiryBoundary_PBT(t *testing.T) {
	db := openSchema(t)
	store := rbac.New(db)

	rapid.Check(t, func(rt *rapid.T) {
		offsetMillis := rapid.OneOf(
			rapid.IntRange(-2*60*60*1000, -250),
			rapid.IntRange(250, 2*60*60*1000),
		).Draw(rt, "offset_millis")
		nullExpiry := rapid.Bool().Draw(rt, "null_expiry")
		email := uniqueEmail(rt)

		uid := insertUser(t, db, email)
		var expires *time.Time
		if !nullExpiry {
			at := time.Now().Add(time.Duration(offsetMillis) * time.Millisecond)
			expires = &at
		}
		insertBinding(t, db, bindingFixture{
			UserID:    uid,
			RoleID:    "analyst",
			TenantID:  api.DefaultTenantID,
			ScopeType: "tenant",
			ScopeID:   "*",
			ExpiresAt: expires,
		})

		got, err := store.ListLiveBindings(t.Context(), uid)
		require.NoError(rt, err)

		// Property: returned iff null OR strictly future.
		shouldReturn := nullExpiry || offsetMillis > 0
		if shouldReturn {
			require.Lenf(rt, got, 1,
				"binding with offset_millis=%d null=%v should be live", offsetMillis, nullExpiry)
		} else {
			require.Emptyf(rt, got,
				"binding with offset_millis=%d null=%v should be expired", offsetMillis, nullExpiry)
		}
	})
}

// TestListLiveBindings_RoleSelectivity_PBT confirms that for any
// random combination of (live + expired) bindings on the same user,
// only the live ones come back, in any order. The example test pins
// a specific 3-binding fixture; this PBT covers the wider space of
// "n live + m expired" combinations.
func TestListLiveBindings_RoleSelectivity_PBT(t *testing.T) {
	db := openSchema(t)
	store := rbac.New(db)
	roles := []string{"super_admin", "admin", "senior_analyst", "analyst", "auditor"}

	rapid.Check(t, func(rt *rapid.T) {
		liveRoles := rapid.SliceOfDistinct(rapid.SampledFrom(roles), func(s string) string { return s }).
			Draw(rt, "live_roles")
		expiredRoles := rapid.SliceOfDistinct(rapid.SampledFrom(roles), func(s string) string { return s }).
			Draw(rt, "expired_roles")
		// Ensure no overlap between sets so we can assert exact membership.
		expiredRoles = slices.DeleteFunc(expiredRoles, func(r string) bool { return slices.Contains(liveRoles, r) })

		email := uniqueEmail(rt)
		uid := insertUser(t, db, email)
		for _, role := range liveRoles {
			future := time.Now().Add(1 * time.Hour)
			insertBinding(t, db, bindingFixture{
				UserID: uid, RoleID: role, TenantID: api.DefaultTenantID,
				ScopeType: "tenant", ScopeID: "*", ExpiresAt: &future,
			})
		}
		for _, role := range expiredRoles {
			past := time.Now().Add(-1 * time.Hour)
			insertBinding(t, db, bindingFixture{
				UserID: uid, RoleID: role, TenantID: api.DefaultTenantID,
				ScopeType: "tenant", ScopeID: "*", ExpiresAt: &past,
			})
		}

		got, err := store.ListLiveBindings(t.Context(), uid)
		require.NoError(rt, err)
		gotRoles := make([]string, 0, len(got))
		for _, b := range got {
			gotRoles = append(gotRoles, b.RoleID)
		}
		require.ElementsMatchf(rt, liveRoles, gotRoles,
			"live=%v expired=%v got=%v", liveRoles, expiredRoles, gotRoles)
	})
}

// uniqueEmail returns a per-property-iteration email so each PBT
// iteration's user is isolated. The role_bindings unique key is
// (user_id, role_id, tenant_id, scope_type, scope_id) so reusing a
// user across iterations would risk duplicate-key errors when the
// same role appears in two iterations' liveRoles draws.
func uniqueEmail(rt *rapid.T) string {
	return rapid.StringMatching(`pbt-[a-z0-9]{8}@test`).Draw(rt, "email")
}
