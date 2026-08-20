//go:build integration

// The generation a fork-without-exec child inherits its path from (issue #714). A fork carries no image of its own, so the builder
// copies the parent's, and it used to pick that image by parent pid alone: newest generation by fork time, no bound. That answers
// "what holds this pid now", not "what was this child's parent running", and the two differ whenever a fork is materialized after its
// parent's pid was recycled. The extension stamps events at handler time and concurrent claim batches (issue #535) reorder across
// batches, so the successor generation routinely lands first and the child was labelled with a binary its parent never ran.
//
// The lookup bounds the candidate by fork time and by nothing else, and "parent recorded as exited long before the child forked" is
// covered below precisely because that row must STILL supply the path. An aliveness test cannot correct an answer here (a parent is
// alive at its child's fork by construction) and on real data it blanked 29,880 rows to fix 3,413 fewer, so the case that pins its
// absence is load-bearing rather than incidental.
//
// Both implementations of the lookup are asserted at every instant here, on purpose. The batch overlay is what production folds
// against and the store's SQL is the per-event reference, and the existing differential test cannot catch a divergence between them
// because both of its arms drive the overlay.

package tests

import (
	"context"
	"fmt"
	"testing"

	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/detection/api"
	"github.com/fleetdm/edr/server/detection/internal/graph"
	"github.com/fleetdm/edr/server/detection/internal/mysql"
	detectiontestkit "github.com/fleetdm/edr/server/detection/testkit"
	"github.com/fleetdm/edr/server/testdb/full"
)

// The two parent images these scenarios distinguish: the generation that really forked the child, and the one that recycled its pid.
const (
	firstImage  = "/bin/first"
	secondImage = "/bin/second"
)

// openProcessStore opens a per-test database and the detection store over it. twoBuilders builds on this so every process-graph
// integration test constructs the store the same way.
func openProcessStore(t *testing.T) (*mysql.Store, *sqlx.DB) {
	t.Helper()
	db := full.Open(t)
	store, err := mysql.New(db, detectiontestkit.NewMemArchive(), nil)
	require.NoError(t, err)
	return store, db
}

// childForkEvt is forkEvt with an explicit event id. A child forked at the same instant as one of the seeded parent forks would
// otherwise reuse that fork's "f<ts>" id, which is exactly the shape the idempotence guard treats as an already-applied replay.
func childForkEvt(eventID string, ts int64, child, parent int) api.Event {
	e := forkEvt(ts, child, parent)
	e.EventID = eventID
	return e
}

// persistedPath returns the path the builder persisted for the newest row of (hostID, pid).
func persistedPath(ctx context.Context, t *testing.T, db *sqlx.DB, hostID string, pid int) string {
	t.Helper()
	var path string
	require.NoError(t, db.GetContext(ctx, &path,
		`SELECT path FROM processes WHERE host_id = ? AND pid = ? ORDER BY id DESC LIMIT 1`, hostID, pid))
	return path
}

// requireInheritedPath applies a child fork at forkAt against an already-seeded parent history and asserts both implementations of
// the lookup answer want: the store's SQL predicate directly, and the batch overlay by way of the path the fork actually persisted.
// Asserting both is the point of this file, since no other test can separate them.
func requireInheritedPath(ctx context.Context, t *testing.T, b *graph.Builder, store *mysql.Store, db *sqlx.DB,
	host string, parentPID, childPID int, forkAt int64, want string,
) {
	t.Helper()
	got, err := store.GetParentPath(ctx, host, parentPID, forkAt)
	require.NoError(t, err)
	require.Equal(t, want, got, "store predicate at fork time %d", forkAt)

	fork := childForkEvt(fmt.Sprintf("child-fork-%d", childPID), forkAt, childPID, parentPID)
	require.NoError(t, b.ProcessBatch(ctx, rewriteHost([]api.Event{fork}, host)))
	require.Equal(t, want, persistedPath(ctx, t, db, host, childPID), "batch overlay predicate at fork time %d", forkAt)
}

// spec:server-process-graph-builder/fork-creates-a-process-record/a-fork-arrives-after-its-parent-s-pid-was-recycled
// spec:server-process-graph-builder/fork-creates-a-process-record/a-parent-whose-exit-was-never-observed-still-supplies-the-path
// spec:server-process-graph-builder/fork-creates-a-process-record/a-parent-recorded-as-exited-before-its-child-forked-still-resolves
// spec:server-process-graph-builder/fork-creates-a-process-record/no-generation-of-the-parent-pid-had-forked-yet
func TestForkInheritsPathOfTheParentGenerationThatHadForkedByThen(t *testing.T) {
	t.Parallel()

	const parentPID, childPID = 500, 600

	cases := []struct {
		name string
		// seed is applied one ProcessBatch per element BEFORE the child's fork, so that fork resolves against generations already
		// persisted rather than against rows its own batch created. That is the ordering reordering-under-concurrency produces, and
		// the only one in which the overlay's preload holds a generation newer than the event being folded.
		seed [][]api.Event
		// forkAt is the child fork's timestamp, applied as its own final batch.
		forkAt int64
		want   string
	}{
		{
			// The defect. Before the fork bound, this child took secondImage, the image of a generation that had not yet forked when
			// the child did.
			name: "parent pid recycled after an observed exit",
			seed: [][]api.Event{
				{forkEvt(100, parentPID, 1), execEvt(101, parentPID, 1, firstImage), exitEvt(160, parentPID, 0)},
				{forkEvt(200, parentPID, 1), execEvt(201, parentPID, 1, secondImage)},
			},
			forkAt: 150,
			want:   firstImage,
		},
		{
			// Same as above but the prior generation's exit was never observed, so its exit_time_ns is one the pid-reuse sweep
			// synthesized at the recycling fork's timestamp. A child forked at 150 belongs to it either way: it is the newest
			// generation that had forked by then.
			name: "parent pid recycled with the prior generation closed by the pid-reuse sweep",
			seed: [][]api.Event{
				{forkEvt(100, parentPID, 1), execEvt(101, parentPID, 1, firstImage)},
				{forkEvt(200, parentPID, 1), execEvt(201, parentPID, 1, secondImage)},
			},
			forkAt: 150,
			want:   firstImage,
		},
		{
			name: "fork after the recycle inherits the recycling generation",
			seed: [][]api.Event{
				{forkEvt(100, parentPID, 1), execEvt(101, parentPID, 1, firstImage), exitEvt(160, parentPID, 0)},
				{forkEvt(200, parentPID, 1), execEvt(201, parentPID, 1, secondImage)},
			},
			forkAt: 250,
			want:   secondImage,
		},
		{
			// A host whose exit events are late, reordered, or dropped must keep inheriting paths. Nothing here consults exit_time_ns,
			// so this holds for free, which is the reason it holds at all.
			name: "parent with no observed exit still supplies the path",
			seed: [][]api.Event{
				{forkEvt(100, parentPID, 1), execEvt(101, parentPID, 1, firstImage)},
			},
			forkAt: 150,
			want:   firstImage,
		},
		{
			// The case that pins the deliberate absence of an aliveness test, and the shape that dominates real data: the child's true
			// parent generation was never recorded, so the newest generation that HAD forked is stored as long since exited. A parent
			// cannot fork after it dies, so the exit record is what is wrong, and the best available evidence is still this row. An
			// aliveness test would blank the path instead, which measured 29,880 rows against 3,413 fewer fixes.
			name: "parent recorded as exited long before the child forked still supplies the path",
			seed: [][]api.Event{
				{forkEvt(100, parentPID, 1), execEvt(101, parentPID, 1, firstImage), exitEvt(160, parentPID, 0)},
			},
			forkAt: 250,
			want:   firstImage,
		},
		{
			// The only shape that legitimately yields nothing, and it is rare: 5 rows of 154,660 on the dev database.
			name: "no generation of the parent pid had forked yet",
			seed: [][]api.Event{
				{forkEvt(200, parentPID, 1), execEvt(201, parentPID, 1, secondImage)},
			},
			forkAt: 150,
			want:   "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			store, db := openProcessStore(t)
			b := graph.NewBuilder(store, discardLogger())
			ctx := t.Context()
			host := "parentpath-" + t.Name()

			for _, batch := range tc.seed {
				require.NoError(t, b.ProcessBatch(ctx, rewriteHost(batch, host)))
			}
			requireInheritedPath(ctx, t, b, store, db, host, parentPID, childPID, tc.forkAt, tc.want)
		})
	}
}

// spec:server-process-graph-builder/fork-creates-a-process-record/a-fork-arrives-after-its-parent-s-pid-was-recycled
// spec:server-process-graph-builder/fork-creates-a-process-record/a-parent-recorded-as-exited-before-its-child-forked-still-resolves
// spec:server-process-graph-builder/fork-creates-a-process-record/no-generation-of-the-parent-pid-had-forked-yet
func TestInheritedPathAtEachBoundaryOfTheParentGenerations(t *testing.T) {
	t.Parallel()

	const parentPID, childPID = 500, 600

	// One parent pid with two generations: firstImage recorded as running [100, 160], then a recycling generation from 200 with no
	// observed exit. Only the instants before the first generation forked have no candidate; the window between the two belongs to
	// the first generation, whose recorded exit does not disqualify it.
	seed := [][]api.Event{
		{forkEvt(100, parentPID, 1), execEvt(101, parentPID, 1, firstImage), exitEvt(160, parentPID, 0)},
		{forkEvt(200, parentPID, 1), execEvt(201, parentPID, 1, secondImage)},
	}

	cases := []struct {
		name   string
		forkAt int64
		want   string
	}{
		{name: "before the first generation forked", forkAt: 99, want: ""},
		{name: "at the first generation's fork instant", forkAt: 100, want: firstImage},
		{name: "inside the first generation's recorded life", forkAt: 150, want: firstImage},
		{name: "at the first generation's recorded exit instant", forkAt: 160, want: firstImage},
		{name: "after the first generation's recorded exit, before the recycle", forkAt: 180, want: firstImage},
		{name: "at the recycling generation's fork instant", forkAt: 200, want: secondImage},
		{name: "long after the recycling generation forked, with no exit observed", forkAt: 100_000, want: secondImage},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			store, db := openProcessStore(t)
			b := graph.NewBuilder(store, discardLogger())
			ctx := t.Context()
			host := "boundary-" + t.Name()

			for _, batch := range seed {
				require.NoError(t, b.ProcessBatch(ctx, rewriteHost(batch, host)))
			}
			requireInheritedPath(ctx, t, b, store, db, host, parentPID, childPID, tc.forkAt, tc.want)
		})
	}
}
