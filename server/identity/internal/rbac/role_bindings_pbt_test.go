//go:build integration

package rbac_test

import (
	"fmt"
	"github.com/jmoiron/sqlx"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"

	"github.com/fleetdm/edr/server/identity/internal/rbac"
)

// pbtEmailCounter feeds uniqueEmail. rapid.StringMatching's 36^8 keyspace looks vast but
// collides under heavier iteration counts (the test became flaky when the package was opted
// into t.Parallel() in issue #172). An atomic counter guarantees uniqueness regardless of
// how many iterations rapid decides to run.
var pbtEmailCounter atomic.Uint64

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
// Generation strategy: rapid draws an offset in (-2h, +2h) skipping a 250ms band around zero, so the boundary is approached from
// both sides without a drawn offset of exactly zero.
//
// The band used to be described as absorbing test-runner and round-trip jitter, and it does not: it only makes the flake rarer. A
// drawn offset is measured before three MySQL round trips, so on a loaded runner the row can genuinely expire before the SELECT
// runs, the query correctly returns nothing, and the live assertion fails. That happened twice on unrelated PRs (issue #802, drawn
// offset 250, then again at 275), and it does not reproduce locally because round trips here are sub-millisecond.
//
// Widening the band would only lengthen the odds, and computing the expiry from the database's own clock would not help either:
// the row still expires between the INSERT and the SELECT whichever clock set it. What removes the race is to stop asserting
// against the nominal offset and assert against the window the query actually ran in, which is what the three cases below do.
// Every drawn offset stays meaningful and no margin is assumed.
//
// Both the window and the expiry it is compared against are read from the DATABASE, because the predicate under test compares
// against NOW(6) and stores the expiry as TIMESTAMP(6). Bounds from the client would only agree while the two clocks do, and a
// client-side expiry carries nanoseconds the column does not, either of which can pick the wrong branch by a hair and put the
// flake back. Reading both back removes the assumption rather than bounding it.

// storedExpiry reads back the expiry as the column holds it, so an assertion about the boundary compares the same value the
// predicate does rather than the client's higher-precision copy of it.
func storedExpiry(t *testing.T, db *sqlx.DB, userID int64) time.Time {
	t.Helper()
	var at time.Time
	require.NoError(t, db.GetContext(t.Context(), &at,
		`SELECT expires_at FROM role_bindings WHERE user_id = ?`, userID))
	return at
}

// dbNow reads the clock the predicate under test actually compares against. A test asserting on expiry has to use it rather than
// time.Now(), or it is asserting that two clocks agree, which is not the property and is not guaranteed.
func dbNow(t *testing.T, db *sqlx.DB) time.Time {
	t.Helper()
	var now time.Time
	require.NoError(t, db.GetContext(t.Context(), &now, `SELECT NOW(6)`))
	return now
}

func TestListLiveBindings_ExpiryBoundary_PBT(t *testing.T) {
	t.Parallel()
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
			ScopeType: "global",
			ScopeID:   "*",
			ExpiresAt: expires,
		})
		if expires != nil {
			// Read back what was actually persisted. TIMESTAMP(6) holds microseconds and the client value carries nanoseconds,
			// so comparing the bounds against the client's copy can differ from what the predicate sees by up to a microsecond,
			// which is the whole width of the boundary this test is about.
			stored := storedExpiry(t, db, uid)
			expires = &stored
		}

		// Bracket the query, so the assertion can be made against the interval it ran in rather than against a nominal offset
		// computed several round trips earlier.
		//
		// Bracketed with the DATABASE's clock, not Go's, which review caught: the predicate under test compares against
		// NOW(6), so bounds read from the client only line up with it while the two clocks agree. A probe measured the skew
		// on this host at 681us, small enough to hide the problem and not to remove it, and a CI runner and its MySQL
		// container have no reason to be that close. Reading NOW(6) puts the bounds and the predicate on one clock, so no
		// offset can select the wrong branch.
		//
		// The two extra round trips widen the bracket, which is the safe direction: it can only move a case into the
		// ambiguous middle, never onto the wrong side of it.
		beforeSelect := dbNow(t, db)
		got, err := store.ListLiveBindings(t.Context(), uid)
		require.NoError(rt, err)
		afterSelect := dbNow(t, db)

		// A NULL expiry is timeless: it is live whatever the clock did.
		if nullExpiry {
			require.Lenf(rt, got, 1, "a binding with no expiry is always live")
			return
		}

		switch {
		case afterSelect.Before(*expires):
			// The expiry was still in the future for the whole query, so nothing the clock did can excuse a miss.
			require.Lenf(rt, got, 1,
				"binding expiring %v after the query finished should be live (offset_millis=%d)",
				expires.Sub(afterSelect), offsetMillis)
		case beforeSelect.After(*expires):
			// Already expired before the query began, and an expired row only gets more expired.
			require.Emptyf(rt, got,
				"binding that expired %v before the query began should not be live (offset_millis=%d)",
				beforeSelect.Sub(*expires), offsetMillis)
		default:
			// The expiry falls inside the query's own execution window, so both answers are correct and asserting either would
			// be asserting the scheduler. This is the case the old code got wrong: it insisted on "live" here. What is still
			// worth pinning is that the row is never returned TWICE, which is a property of the query rather than of timing.
			require.LessOrEqualf(rt, len(got), 1,
				"at most one binding row whichever side of the boundary the query landed (offset_millis=%d)", offsetMillis)
		}
	})
}

// TestListLiveBindings_RoleSelectivity_PBT confirms that for any random combination of (live + expired) bindings on the same user,
// only the live ones come back, in any order. The example test pins a specific 3-binding fixture; this PBT covers the wider space of
// "n live + m expired" combinations.
func TestListLiveBindings_RoleSelectivity_PBT(t *testing.T) {
	t.Parallel()
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
				UserID: uid, RoleID: role,
				ScopeType: "global", ScopeID: "*", ExpiresAt: &future,
			})
		}
		for _, role := range expiredRoles {
			past := time.Now().Add(-1 * time.Hour)
			insertBinding(t, db, bindingFixture{
				UserID: uid, RoleID: role,
				ScopeType: "global", ScopeID: "*", ExpiresAt: &past,
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

// uniqueEmail returns a per-property-iteration email so each PBT iteration's user is isolated. The role_bindings unique key is
// (user_id, role_id, scope_type, scope_id) so reusing a user across iterations would risk duplicate-key errors when the same role
// appears in two iterations' liveRoles draws.
//
// An atomic counter is the source of uniqueness; the rapid Draw is kept so each iteration still consumes one entropy slot (lets
// rapid shrink the test the same way it did before).
func uniqueEmail(rt *rapid.T) string {
	_ = rapid.StringMatching(`[a-z0-9]{4}`).Draw(rt, "email_entropy")
	return fmt.Sprintf("pbt-%d@test", pbtEmailCounter.Add(1))
}
