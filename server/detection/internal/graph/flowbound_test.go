package graph

import (
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/fleetdm/edr/server/detection/api"
)

// spec:server-rest-api/per-process-detail-with-re-exec-chain/a-flow-that-ingests-after-its-process-exited-is-still-attributed-to-it
//
// The scan bound must not be measured from the process's own start. A daemon older than any fixed span would match its flows by
// identity and then have all of them pruned by a ceiling that expired before they were ingested, which is issue #716 again wearing a
// different hat: the flow is attributed correctly and then thrown away. The bug is invisible for a young process, which is why this is
// pinned against an old one.
func TestFlowScanBound_CeilingIsQueryTimeNotProcessAge(t *testing.T) {
	t.Parallel()

	now := time.Now().UnixNano()
	fortyDays := int64(40 * 24 * time.Hour)
	forkedLongAgo := now - fortyDays

	bound := flowScanBound(forkedLongAgo, now)

	assert.Equal(t, forkedLongAgo, bound.FromNs, "the floor stays anchored on the generation: a flow cannot precede its process")
	assert.Equal(t, now, bound.ToNs, "the ceiling is the query time")
	assert.GreaterOrEqual(t, bound.ToNs, now,
		"a flow ingested moments ago must be inside the bound for a process forked 40 days ago; a fork-relative ceiling would exclude it")
}

// generationLife feeds the identity arm's event-time bound. A live generation must stay open-ended: closing it at the query time would
// be harmless today but would drop a flow whose network-extension clock ran ahead of the server's.
func TestGenerationLife_LiveGenerationIsOpenEnded(t *testing.T) {
	t.Parallel()

	execAt := time.Now().UnixNano()
	live := generationLife(&api.Process{ForkTimeNs: execAt - int64(time.Second), ExecTimeNs: &execAt})
	assert.Equal(t, execAt-flowClockSkewPadNs, live.FromNs, "the floor is the exec instant, padded for clock skew")
	assert.Equal(t, int64(math.MaxInt64), live.ToNs, "a generation that has not exited has no upper edge")

	exitAt := execAt + int64(30*time.Second)
	exited := generationLife(&api.Process{ForkTimeNs: execAt - int64(time.Second), ExecTimeNs: &execAt, ExitTimeNs: &exitAt})
	assert.Equal(t, exitAt+flowClockSkewPadNs, exited.ToNs, "an exited generation closes at its exit, padded the same way")

	forkOnly := generationLife(&api.Process{ForkTimeNs: execAt})
	assert.Equal(t, execAt-flowClockSkewPadNs, forkOnly.FromNs, "a generation with no exec falls back to its fork")
}
