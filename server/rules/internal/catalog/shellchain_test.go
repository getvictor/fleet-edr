package catalog

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/rules/api"
)

// TestFindShellOnExecChainDoesNotReportAFailedLookupAsAbsentAncestry pins the one distinction the walk's third return value can
// plausibly get wrong.
//
// findShellOnExecChain reports two different kinds of nothing: "no shell on this chain" and "a shell was there, and its parent had
// no record". A THIRD thing can happen, which is that the parent lookup fails outright, and that is not a resolved absence: the
// parent may well exist. Folding it into incompleteAncestry would silently convert a datastore outage into a stream of "chain
// declined" observations while the error that should have nacked the batch disappeared, so the rule would acknowledge events it
// never actually evaluated.
//
// The error is therefore returned and the flag stays false, and both halves are asserted, because a mutant that sets the flag on
// the error path still returns the error and would pass on the error assertion alone.
func TestFindShellOnExecChainDoesNotReportAFailedLookupAsAbsentAncestry(t *testing.T) {
	t.Parallel()

	boom := errors.New("graph unavailable")
	// GetExecChain on this reader hands back the process it was given, so a shell path here IS the chain, and PPID above 1 sends
	// the walk into lookupParentOf rather than treating it as the genuine launchd-parented case.
	s := &recordingGraphReader{errByPID: boom}
	conn := &api.Process{PID: 100, PPID: 500, Path: "/bin/zsh"}

	shell, parent, incomplete, err := findShellOnExecChain(t.Context(), s, "host-a", conn)

	require.ErrorIs(t, err, boom, "a failed parent lookup must surface so the batch is nacked and replayed")
	assert.False(t, incomplete,
		"a lookup that FAILED is not a parent resolved as absent: reporting it as incomplete ancestry would turn an outage into "+
			"a silent stream of declines and acknowledge events that were never evaluated")
	assert.Nil(t, shell)
	assert.Nil(t, parent)
	assert.True(t, s.calledByPID, "the test only proves anything if the walk actually reached the parent lookup")
}
