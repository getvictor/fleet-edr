package clickhouse

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNew_NilDB(t *testing.T) {
	t.Parallel()
	_, err := New(nil)
	require.Error(t, err)
}

func TestOpen_Unreachable(t *testing.T) {
	t.Parallel()
	// Port 1 has nothing listening, so the ping after dial fails fast: exercises Open's connection-error path without a live server.
	_, err := Open(context.Background(), "clickhouse://127.0.0.1:1/edr")
	require.Error(t, err)
}
