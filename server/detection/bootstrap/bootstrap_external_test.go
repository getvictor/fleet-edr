package bootstrap_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/detection/bootstrap"
	detectiontestkit "github.com/fleetdm/edr/server/detection/testkit"
	identitytestkit "github.com/fleetdm/edr/server/identity/testkit"
	"github.com/fleetdm/edr/server/testdb/full"
	visibilitybootstrap "github.com/fleetdm/edr/server/visibility/bootstrap"
)

// TestStoreAccessor lives in the external test package because it reaches for testdb/full to apply every context's schema. Keeping it
// in `package bootstrap` would create the cycle bootstrap → testdb/full → bootstrap.
func TestStoreAccessor(t *testing.T) {
	t.Parallel()
	db := full.Open(t)
	// Detection requires the visibility event stores (ADR-0015): a real MySQL EventLog (the full schema includes event_queue) and an
	// in-memory EventArchive, which is enough to exercise the accessors without a ClickHouse container.
	vis, err := visibilitybootstrap.New(visibilitybootstrap.Deps{DB: db})
	require.NoError(t, err)
	d, err := bootstrap.New(bootstrap.Deps{
		DB:           db,
		Mode:         bootstrap.ModeFull,
		AuthZ:        identitytestkit.AllowAllAuthZ{},
		EventLog:     vis.EventLog(),
		EventArchive: detectiontestkit.NewMemArchive(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	assert.NotNil(t, d.Store(), "Store accessor returns the persistence handle")
	assert.NotNil(t, d.Service(), "Service accessor returns the operator-facing api.Service")
}
