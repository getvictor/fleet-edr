//go:build integration

// Differential coverage for issue #535: the set-based batched graph builder MUST produce a process forest identical to applying
// the same events one at a time in timestamp order. The two paths are compared by running the same events under two isolated
// host_id prefixes on one database, then comparing the resulting process rows up to id-isomorphism.
//
// Why size-1 batches are a faithful per-event reference: a one-event ProcessBatch preloads that event's keys, folds the single
// event against an overlay that therefore holds only committed rows, and flushes, so each event reads the real persisted state the
// previous event left, with no in-memory cross-event state. A single big ProcessBatch instead resolves later events against the
// in-memory overlay (rows created earlier in the same batch). Equality between the two is exactly the property that the in-memory
// overlay reproduces the SQL resolution semantics and that batching boundaries do not change the forest.

package tests

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"testing"

	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"

	"github.com/fleetdm/edr/server/detection/api"
	"github.com/fleetdm/edr/server/detection/internal/graph"
	"github.com/fleetdm/edr/server/detection/internal/mysql"
	detectiontestkit "github.com/fleetdm/edr/server/detection/testkit"
	"github.com/fleetdm/edr/server/testdb/full"
)

// normRow is a process row normalised for forest comparison: the absolute auto-increment id and host_id are dropped, and the
// re-exec back-reference is replaced by the canonical rank of the row it points at, so two structurally identical forests built
// under different ids and host prefixes compare equal.
type normRow struct {
	PID              int
	PPID             int
	Path             string
	Args             string
	UID              *int
	GID              *int
	CodeSigning      string
	SHA256           *string
	CDHash           *string
	PIDVersion       *uint32
	ForkTimeNs       int64
	ForkIngestedAtNs *int64
	ExecTimeNs       *int64
	ExitTimeNs       *int64
	ExitIngestedAtNs *int64
	ExitReason       *string
	ExitCode         *int
	IsSnapshot       bool
	LastSeenNs       *int64
	PrevRank         int // canonical rank of the previous_exec row, or -1
}

// dumpNormalizedForest reads every process row for hostID and returns it in a canonical, id-independent order. Rows are sorted by a
// key built from immutable/observable fields (pid, fork time, exec time, exit time, path) that uniquely orders the generated
// forests; the sorted index is each row's canonical rank, and previous_exec_id is rewritten to the rank of its target.
func dumpNormalizedForest(t *testing.T, db *sqlx.DB, ctx context.Context, hostID string) []normRow {
	t.Helper()
	var rows []api.Process
	require.NoError(t, db.SelectContext(ctx, &rows, `
		SELECT id, host_id, pid, ppid, path, args, uid, gid, code_signing, sha256, cdhash, pidversion,
		       fork_time_ns, fork_ingested_at_ns, exec_time_ns, exit_time_ns,
		       exit_ingested_at_ns, exit_reason, exit_code, previous_exec_id,
		       is_snapshot, last_seen_ns
		FROM processes WHERE host_id = ?`, hostID))

	sorted := slices.Clone(rows)
	sort.SliceStable(sorted, func(i, j int) bool { return rowSortKey(sorted[i]) < rowSortKey(sorted[j]) })

	rank := make(map[int64]int, len(sorted))
	for i, r := range sorted {
		rank[r.ID] = i
	}

	out := make([]normRow, len(sorted))
	for i, r := range sorted {
		prev := -1
		if r.PreviousExecID != nil {
			if pr, ok := rank[*r.PreviousExecID]; ok {
				prev = pr
			} else {
				prev = -2 // dangling reference: still deterministic, surfaces a divergence rather than hiding it
			}
		}
		out[i] = normRow{
			PID: r.PID, PPID: r.PPID, Path: r.Path,
			Args: string(r.Args), UID: r.UID, GID: r.GID,
			CodeSigning: string(r.CodeSigning), SHA256: r.SHA256, CDHash: r.CDHash, PIDVersion: r.PIDVersion,
			ForkTimeNs: r.ForkTimeNs, ForkIngestedAtNs: r.ForkIngestedAtNs,
			ExecTimeNs: r.ExecTimeNs, ExitTimeNs: r.ExitTimeNs, ExitIngestedAtNs: r.ExitIngestedAtNs,
			ExitReason: r.ExitReason, ExitCode: r.ExitCode,
			IsSnapshot: r.IsSnapshot, LastSeenNs: r.LastSeenNs,
			PrevRank: prev,
		}
	}
	return out
}

func rowSortKey(r api.Process) string {
	return fmt.Sprintf("%012d|%020d|%020d|%020d|%s|%s",
		r.PID, r.ForkTimeNs, ptrOr(r.ExecTimeNs, -1), ptrOr(r.ExitTimeNs, -1), r.Path, strOr(r.ExitReason))
}

func ptrOr(p *int64, d int64) int64 {
	if p == nil {
		return d
	}
	return *p
}

func strOr(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// rewriteHost clones events with their host_id replaced, so the reference and batched runs are fully isolated on one database.
func rewriteHost(events []api.Event, hostID string) []api.Event {
	out := slices.Clone(events)
	for i := range out {
		out[i].HostID = hostID
	}
	return out
}

// requireBatchInvariant asserts that applying baseEvents as one batch yields the same forest as applying them one event at a time
// in timestamp order. bRef and bBatch share one db and write under distinct host prefixes derived from tag.
func requireBatchInvariant(t *testing.T, db *sqlx.DB, bRef, bBatch *graph.Builder, baseEvents []api.Event, tag string) {
	t.Helper()
	ctx := t.Context()

	refHost := "ref-" + tag
	refEvents := rewriteHost(baseEvents, refHost)
	// The per-event reference processes in timestamp order, mirroring ProcessBatch's internal stable sort, then applies each event
	// as its own batch so every read sees the committed state of the prior event.
	slices.SortStableFunc(refEvents, func(a, b api.Event) int { return int(a.TimestampNs - b.TimestampNs) })
	for _, e := range refEvents {
		require.NoError(t, bRef.ProcessBatch(ctx, []api.Event{e}))
	}

	batchHost := "batch-" + tag
	require.NoError(t, bBatch.ProcessBatch(ctx, rewriteHost(baseEvents, batchHost)))

	ref := dumpNormalizedForest(t, db, ctx, refHost)
	batched := dumpNormalizedForest(t, db, ctx, batchHost)
	require.Equal(t, ref, batched, "batched forest must equal the per-event forest for %s", tag)
}

func twoBuilders(t *testing.T) (*graph.Builder, *graph.Builder, *sqlx.DB) {
	t.Helper()
	db := full.Open(t)
	store, err := mysql.New(db, detectiontestkit.NewMemArchive())
	require.NoError(t, err)
	return graph.NewBuilder(store, discardLogger()), graph.NewBuilder(store, discardLogger()), db
}

// forkEvt/execEvt/exitEvt/snapExecEvt/heartbeatEvt are terse builders for the differential scenarios. ts doubles as the event id
// suffix so ids stay unique within a scenario.
func forkEvt(ts int64, child, parent int) api.Event {
	return api.Event{EventID: "f" + strconv.FormatInt(ts, 10), HostID: "x", TimestampNs: ts, IngestedAtNs: ts + 1, EventType: "fork",
		Payload: json.RawMessage(fmt.Sprintf(`{"child_pid":%d,"parent_pid":%d}`, child, parent))}
}

func execEvt(ts int64, pid, ppid int, path string) api.Event {
	return api.Event{EventID: "e" + strconv.FormatInt(ts, 10), HostID: "x", TimestampNs: ts, IngestedAtNs: ts + 1, EventType: "exec",
		Payload: json.RawMessage(fmt.Sprintf(`{"pid":%d,"ppid":%d,"path":%q,"uid":501,"gid":20}`, pid, ppid, path))}
}

func exitEvt(ts int64, pid, code int) api.Event {
	return api.Event{EventID: "q" + strconv.FormatInt(ts, 10), HostID: "x", TimestampNs: ts, IngestedAtNs: ts + 1, EventType: "exit",
		Payload: json.RawMessage(fmt.Sprintf(`{"pid":%d,"exit_code":%d}`, pid, code))}
}

func snapExecEvt(ts int64, pid, ppid int, path string) api.Event {
	return api.Event{EventID: "s" + strconv.FormatInt(ts, 10), HostID: "x", TimestampNs: ts, IngestedAtNs: ts + 1, EventType: "exec",
		Payload: json.RawMessage(fmt.Sprintf(`{"pid":%d,"ppid":%d,"path":%q,"snapshot":true}`, pid, ppid, path))}
}

func heartbeatEvt(ts int64, pid int) api.Event {
	return api.Event{EventID: "h" + strconv.FormatInt(ts, 10), HostID: "x", TimestampNs: ts, IngestedAtNs: ts + 1, EventType: "snapshot_heartbeat",
		Payload: json.RawMessage(fmt.Sprintf(`{"pid":%d}`, pid))}
}

// spec:server-process-graph-builder/set-based-batch-materialization-is-equivalent-to-per-event-application/batched-materialization-equals-per-event-materialization
func TestProcessBatch_DifferentialCraftedScenarios(t *testing.T) {
	t.Parallel()
	bRef, bBatch, db := twoBuilders(t)
	base := int64(1_000_000_000)

	cases := []struct {
		name   string
		events []api.Event
	}{
		{"fork exec exit", []api.Event{forkEvt(base, 100, 1), execEvt(base+1, 100, 1, "/bin/a"), exitEvt(base+2, 100, 0)}},
		{"re-exec chain python sh bash", []api.Event{
			forkEvt(base, 200, 1), execEvt(base+1, 200, 1, "/usr/bin/python"),
			execEvt(base+2, 200, 1, "/bin/sh"), execEvt(base+3, 200, 1, "/bin/bash"), exitEvt(base+4, 200, 0),
		}},
		{"pid reuse", []api.Event{
			forkEvt(base, 300, 1), execEvt(base+1, 300, 1, "/bin/first"),
			forkEvt(base+2, 300, 9), execEvt(base+3, 300, 9, "/bin/second"),
		}},
		{"exec without fork", []api.Event{execEvt(base, 400, 1, "/bin/orphan"), exitEvt(base+1, 400, 0)}},
		{"snapshot exec then heartbeat", []api.Event{
			snapExecEvt(base, 500, 1, "/Applications/Safari.app"), heartbeatEvt(base+1, 500),
		}},
		{"exit before snapshot exec race", []api.Event{
			exitEvt(base, 600, 0), snapExecEvt(base+1, 600, 1, "/bin/late"),
		}},
		{"fork without exec inherits parent path", []api.Event{
			forkEvt(base, 700, 1), execEvt(base+1, 700, 1, "/bin/parent"), forkEvt(base+2, 701, 700),
		}},
		{"re-exec then pid reuse", []api.Event{
			forkEvt(base, 800, 1), execEvt(base+1, 800, 1, "/bin/a"), execEvt(base+2, 800, 1, "/bin/b"),
			forkEvt(base+3, 800, 9), execEvt(base+4, 800, 9, "/bin/c"),
		}},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			requireBatchInvariant(t, db, bRef, bBatch, tc.events, "crafted"+strconv.Itoa(i))
		})
	}
}

// spec:server-process-graph-builder/set-based-batch-materialization-is-equivalent-to-per-event-application/batched-materialization-equals-per-event-materialization
func TestProcessBatch_DifferentialProperty(t *testing.T) {
	t.Parallel()
	bRef, bBatch, db := twoBuilders(t)
	iter := 0

	rapid.Check(t, func(rt *rapid.T) {
		iter++
		events := genEventSequence(rt)
		requireBatchInvariant(t, db, bRef, bBatch, events, "pbt"+strconv.Itoa(iter))
	})
}

// genEventSequence draws a random sequence of fork/exec/exit/snapshot/heartbeat events over a small PID space with strictly
// increasing timestamps. The small PID space makes re-exec, PID reuse, exec-without-fork, and exit-then-fork collisions frequent,
// which is exactly where the in-memory overlay must match the SQL resolution.
func genEventSequence(rt *rapid.T) []api.Event {
	n := rapid.IntRange(1, 30).Draw(rt, "n")
	pids := []int{100, 101, 102}
	parents := []int{1, 100, 101, 102}
	base := int64(2_000_000_000)
	var events []api.Event
	for i := range n {
		ts := base + int64(i)*1000
		switch rapid.SampledFrom([]string{"fork", "exec", "exit", "snap_exec", "heartbeat"}).Draw(rt, "type"+strconv.Itoa(i)) {
		case "fork":
			events = append(events, forkEvt(ts, rapid.SampledFrom(pids).Draw(rt, "fc"+strconv.Itoa(i)), rapid.SampledFrom(parents).Draw(rt, "fp"+strconv.Itoa(i))))
		case "exec":
			pid := rapid.SampledFrom(pids).Draw(rt, "ep"+strconv.Itoa(i))
			events = append(events, execEvt(ts, pid, 1, "/bin/img"+strconv.Itoa(i)))
		case "exit":
			events = append(events, exitEvt(ts, rapid.SampledFrom(pids).Draw(rt, "xp"+strconv.Itoa(i)), rapid.IntRange(0, 9).Draw(rt, "xc"+strconv.Itoa(i))))
		case "snap_exec":
			pid := rapid.SampledFrom(pids).Draw(rt, "sp"+strconv.Itoa(i))
			events = append(events, snapExecEvt(ts, pid, 1, "/App/snap"+strconv.Itoa(i)))
		case "heartbeat":
			events = append(events, heartbeatEvt(ts, rapid.SampledFrom(pids).Draw(rt, "hp"+strconv.Itoa(i))))
		}
	}
	return events
}
