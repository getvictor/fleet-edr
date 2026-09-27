//go:build darwin && cgo

package main

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/agent/proctable"
)

// A parent the agent never saw exec (package_script_service after an agent restart, as found on edr-dev for issue #1161) must
// still resolve: the table misses it and the kernel answers. A process the table does hold is answered from the table.
func TestParentPath_FallsBackToTheKernelOnATableMiss(t *testing.T) {
	t.Parallel()
	pt := proctable.New()
	p := receiverLoopParams{pt: pt}

	got, ok := p.parentPath(os.Getpid())
	require.True(t, ok, "a live process missing from the table resolves through the kernel")
	assert.NotEmpty(t, got)

	pt.Update(int32(os.Getpid()), proctable.ProcessInfo{Path: "/from/the/table"}) //nolint:gosec // a pid fits in int32
	got, ok = p.parentPath(os.Getpid())
	require.True(t, ok)
	assert.Equal(t, "/from/the/table", got, "the table answers first when it holds the process")

	_, ok = receiverLoopParams{}.parentPath(99_999_999)
	assert.False(t, ok, "no table and no such process")
}
