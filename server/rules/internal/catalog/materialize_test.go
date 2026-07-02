package catalog

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/rules/api"
)

// sudoersOpenEvent builds the write-mode /etc/sudoers open the sudoers_tamper rule keys on, for a pid that has no process row, so
// the tests below exercise exactly the materialization-race branch. ingestedAtNs controls which side of the grace window it lands on.
func sudoersOpenEvent(ingestedAtNs int64) api.Event {
	return api.Event{
		EventID:      "sud-materialize-race",
		HostID:       "fixture-host",
		TimestampNs:  1,
		IngestedAtNs: ingestedAtNs,
		EventType:    "open",
		Payload:      json.RawMessage(`{"pid":99999,"path":"/etc/sudoers","flags":1537}`),
	}
}

// TestResolveSubjectProcess_YoungMissRaisesRetryableError pins the fix for the 2026-07-02 nightly demo failure: with concurrent
// processor batches (issue #535) an event can be evaluated before the batch carrying its fork/exec commits, and the old silent skip
// permanently lost the alert. A young event whose subject process is missing must now fail evaluation with the retryable sentinel
// so the processor nacks and re-evaluates the batch.
// spec:server-detection-rules-engine/retryable-evaluation-on-unmaterialized-subject-process/a-young-event-s-subject-process-row-is-missing
func TestResolveSubjectProcess_YoungMissRaisesRetryableError(t *testing.T) {
	t.Parallel()
	s := openCatalogStore(t)
	ctx := t.Context()
	r := &SudoersTamper{}

	evt := sudoersOpenEvent(time.Now().UnixNano())
	findings, err := r.Evaluate(ctx, []api.Event{evt}, s.GraphReader())
	require.ErrorIs(t, err, api.ErrProcessNotYetMaterialized,
		"a young event with no subject process row must fail with the retryable sentinel, not skip silently")
	assert.Empty(t, findings)
}

// TestResolveSubjectProcess_StaleMissSkipsSilently pins the bound on the retry: once an event is older than the materialization
// grace window its subject process is assumed to never arrive, and evaluation degrades to the historical silent skip so a
// permanently orphaned event cannot hold its batch in a retry loop.
// spec:server-detection-rules-engine/retryable-evaluation-on-unmaterialized-subject-process/an-event-past-the-grace-window-has-no-subject-process-row
func TestResolveSubjectProcess_StaleMissSkipsSilently(t *testing.T) {
	t.Parallel()
	s := openCatalogStore(t)
	ctx := t.Context()
	r := &SudoersTamper{}

	evt := sudoersOpenEvent(time.Now().Add(-processMaterializationGrace - time.Second).UnixNano())
	findings, err := r.Evaluate(ctx, []api.Event{evt}, s.GraphReader())
	require.NoError(t, err, "an event past the grace window must not retry")
	assert.Empty(t, findings)
}

// TestWithinMaterializationGrace pins the window edges: a zero ingest stamp (fixture replay, unit tests) is never in grace so those
// inputs keep the historical skip semantics, the boundary is exclusive at exactly the grace age, and the window is symmetric so a
// modestly future-dated stamp (cross-replica clock skew) is in grace while a badly future-dated one cannot retry indefinitely.
func TestWithinMaterializationGrace(t *testing.T) {
	t.Parallel()
	now := time.Now().UnixNano()
	cases := []struct {
		name         string
		ingestedAtNs int64
		want         bool
	}{
		{"zero ingest stamp never in grace", 0, false},
		{"just ingested", now, true},
		{"one second old", now - int64(time.Second), true},
		{"exactly at the grace age", now - int64(processMaterializationGrace), false},
		{"well past the grace age", now - int64(processMaterializationGrace) - int64(time.Minute), false},
		{"future-dated within the skew allowance", now + int64(time.Second), true},
		{"future-dated beyond the grace bound", now + int64(processMaterializationGrace) + int64(time.Minute), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, withinMaterializationGrace(tc.ingestedAtNs, now))
		})
	}
}

// TestResolveSubjectProcess_FoundRowPassesThrough confirms the helper is transparent on the happy path: once the writer's process
// row exists the same event yields the finding, which is what the post-nack re-evaluation relies on.
func TestResolveSubjectProcess_FoundRowPassesThrough(t *testing.T) {
	t.Parallel()
	s := openCatalogStore(t)
	ctx := t.Context()
	r := &SudoersTamper{}

	const pid = 4242
	forkExec := []api.Event{
		{EventID: "mat-fork", HostID: "fixture-host", TimestampNs: 1, EventType: "fork",
			Payload: json.RawMessage(fmt.Sprintf(`{"child_pid":%d,"parent_pid":1}`, pid))},
		{EventID: "mat-exec", HostID: "fixture-host", TimestampNs: 2, EventType: "exec",
			Payload: json.RawMessage(fmt.Sprintf(`{"pid":%d,"ppid":1,"path":"/bin/cp"}`, pid))},
	}
	require.NoError(t, s.InsertEvents(ctx, forkExec))
	require.NoError(t, s.ProcessBatch(ctx, forkExec))

	evt := api.Event{
		EventID:      "mat-open",
		HostID:       "fixture-host",
		TimestampNs:  3,
		IngestedAtNs: time.Now().UnixNano(),
		EventType:    "open",
		Payload:      json.RawMessage(fmt.Sprintf(`{"pid":%d,"path":"/etc/sudoers","flags":1537}`, pid)),
	}
	findings, err := r.Evaluate(ctx, []api.Event{evt}, s.GraphReader())
	require.NoError(t, err)
	require.Len(t, findings, 1, "with the writer row materialized the same event fires the finding")
	assert.Equal(t, "sudoers_tamper", findings[0].RuleID)
}
