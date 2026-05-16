package bootstrap

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestApplySchema_NilDBRejected exercises the nil-DB guard so a caller that wires bootstrap without a DB gets a typed error instead of
// a nil deref deep inside the loop.
func TestApplySchema_NilDBRejected(t *testing.T) {
	err := ApplySchema(context.Background(), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "db must not be nil")
}
