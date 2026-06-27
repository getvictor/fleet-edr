package bootstrap

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNew_NilDB(t *testing.T) {
	t.Parallel()
	_, err := New(Deps{DB: nil})
	require.Error(t, err)
}

func TestApplySchema_NilDB(t *testing.T) {
	t.Parallel()
	require.Error(t, ApplySchema(context.Background(), nil))
}

func TestApplyClickHouseSchema_NilDB(t *testing.T) {
	t.Parallel()
	require.Error(t, ApplyClickHouseSchema(context.Background(), nil))
}
