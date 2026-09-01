package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// mustParseDeltas parses the in-flight change deltas under changesDir, failing the test on error. Shared by the REMOVED and
// MODIFIED exemption tests, which read two halves of the same single pass.
func mustParseDeltas(t *testing.T, changesDir string) *deltaSections {
	t.Helper()
	d, err := parseDeltaSections(changesDir)
	require.NoError(t, err)
	return d
}
