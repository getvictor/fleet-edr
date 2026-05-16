package bootstrap_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/fleetdm/edr/server/detection/bootstrap"
	identitytestkit "github.com/fleetdm/edr/server/identity/testkit"
	"github.com/fleetdm/edr/server/testdb/full"
)

// TestStoreAccessor lives in the external test package because it reaches for testdb/full to apply every context's schema. Keeping it
// in `package bootstrap` would create the cycle bootstrap → testdb/full → bootstrap.
func TestStoreAccessor(t *testing.T) {
	db := full.Open(t)
	d, err := bootstrap.New(bootstrap.Deps{
		DB:    db,
		Mode:  bootstrap.ModeFull,
		AuthZ: identitytestkit.AllowAllAuthZ{},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	assert.NotNil(t, d.Store(), "Store accessor returns the persistence handle")
	assert.NotNil(t, d.Service(), "Service accessor returns the operator-facing api.Service")
}
