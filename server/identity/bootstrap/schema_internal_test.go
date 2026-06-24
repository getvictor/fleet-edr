package bootstrap

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestApplySchema_NilDBRejected verifies the ApplySchema guard so a caller that wires the bootstrap without a DB (a real bug we have
// hit during cmd/main refactors) gets a typed error instead of a nil dereference. The guard runs before any DDL would execute.
func TestApplySchema_NilDBRejected(t *testing.T) {
	t.Parallel()
	err := ApplySchema(context.Background(), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "db must not be nil")
}
