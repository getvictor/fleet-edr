package full_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/testdb/full"
)

// TestOpen_AllContextsSchemaPresent verifies that every bounded
// context's authoritative table is present after full.Open returns.
// Catches a future "I added a new context but forgot to wire it into
// full.Open" regression.
func TestOpen_AllContextsSchemaPresent(t *testing.T) {
	db := full.Open(t)

	// The rules context owns app_control_policies + app_control_rules
	// (demo cut). The remaining two spec'd tables (host_groups +
	// app_control_assignments) land with the full Phase A; for the
	// demo every policy implicitly targets every host in the deployment.
	tables := map[string]string{
		"users":                "identity",
		"sessions":             "identity",
		"enrollments":          "endpoint",
		"commands":             "response",
		"events":               "detection",
		"processes":            "detection",
		"alerts":               "detection",
		"alert_events":         "detection",
		"hosts":                "detection",
		"app_control_policies": "rules",
		"app_control_rules":    "rules",
	}

	for table, owner := range tables {
		var n int
		err := db.GetContext(t.Context(), &n,
			"SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = ?",
			table)
		require.NoError(t, err, "owner=%s table=%s", owner, table)
		assert.Equal(t, 1, n, "owner=%s table=%s missing from full fixture", owner, table)
	}
}
