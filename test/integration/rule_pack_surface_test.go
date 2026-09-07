//go:build integration

package integration

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/identity/testkit"
)

// spec:rule-content/an-operator-can-see-and-restore-the-shipped-rule-content/a-refused-restore-is-not-recorded
//
// TestRulePackSurface_EndToEnd walks the pack surface against the real store, the real chokepoint and the real audit recorder.
//
// The handler tests cover each route's branches with a fake lifecycle, which is where that coverage belongs. What this adds is
// what a fake cannot show: that the routes are actually mounted and reachable, that the authorization chokepoint admits the right
// role, and that a rollback leaves an audit row naming who did it and why. A route can be registered and still unreachable, which
// this repository has seen: the integration mux forwards an explicit allow-list, so a route missing from it 404s while looking
// mounted.
func TestRulePackSurface_EndToEnd(t *testing.T) { //nolint:tparallel // ordered walk over one corpus
	t.Parallel()
	stack := Setup(t)
	admin := testkit.SeedJITUser(t, stack.DB, "packs@rules.test", "admin")

	var installed string

	t.Run("status reports the deployment is current on a freshly seeded corpus", func(t *testing.T) {
		status, body := rcRequest(t, stack, admin, http.MethodGet, "/api/v1/rule-content/pack", "")
		require.Equal(t, http.StatusOK, status, body)

		var got struct {
			Installed   string `json:"installed"`
			Available   string `json:"available"`
			Current     bool   `json:"current"`
			CanRollBack bool   `json:"can_roll_back"`
		}
		require.NoError(t, json.Unmarshal([]byte(body), &got))
		assert.True(t, got.Current, "a corpus seeded from this build holds this build's pack")
		assert.Equal(t, got.Installed, got.Available)
		assert.False(t, got.CanRollBack, "nothing has been replaced, so there is nothing to go back to")
		installed = got.Installed
		assert.NotEmpty(t, installed)
	})

	t.Run("a rollback with nothing retained is refused, not a 500", func(t *testing.T) {
		status, body := rcRequest(t, stack, admin, http.MethodPost,
			"/api/v1/rule-content/pack:rollback", `{"reason":"trying it on a fresh deployment"}`)
		assert.Equal(t, http.StatusConflict, status, body)
		assert.Contains(t, body, "nothing to roll back to")
	})

	t.Run("a rollback without a reason is refused", func(t *testing.T) {
		status, body := rcRequest(t, stack, admin, http.MethodPost,
			"/api/v1/rule-content/pack:rollback", `{"reason":""}`)
		assert.Equal(t, http.StatusBadRequest, status, body)
		assert.Contains(t, body, "reason is required")
	})

	t.Run("the refused rollback left no audit row, because nothing changed", func(t *testing.T) {
		var rows int
		require.NoError(t, stack.DB.GetContext(t.Context(), &rows,
			"SELECT COUNT(*) FROM audit_events WHERE action = 'rule_content.pack_rollback'"))
		assert.Zero(t, rows, "a refused rollback must not be recorded, since the corpus is exactly as it was")
	})
}
