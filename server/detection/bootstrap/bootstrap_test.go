package bootstrap

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew_RejectsMissingDB(t *testing.T) {
	t.Parallel()
	_, err := New(Deps{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "DB")
}
