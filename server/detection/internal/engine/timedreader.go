package engine

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/fleetdm/edr/server/detection/api"
)

// waitAccumulator collects how long ONE evaluation spent waiting on graph reads.
//
// The evaluation budget subtracts this. Review found why it has to: a rule's reads go to MySQL synchronously, so charging a rule
// for them means a slow database disables rules rather than slow rules, and it disables them in proportion to how much of the graph
// they consult. A database slowdown would take out most of the catalog at once, which is precisely the moment detections matter
// most, and the rules it would take out first are the ones doing the most correlation.
//
// What the budget is left measuring is the rule's own matching: its patterns, its walks over the batch, its own logic. That is the
// thing an author controls and the thing #767 set out to bound.
//
// It travels in the CONTEXT rather than in the reader, which is the fix for the attribution bug review found. The Sigma adapter
// memoizes each event's graph lookups across every rule in the batch, and those closures capture the api.GraphReader belonging to
// whichever rule built the memo. A reader that accumulated into its own field therefore credited the FIRST rule for a read that a
// LATER rule triggered, leaving the later rule's total at zero, so the slow database it waited on was charged to it after all and
// could still get it skipped. The lazy closures are invoked with the invoking rule's own context (sigmaEvent rebinds it, for the
// same reason expressed there about OTel spans), so reading the accumulator out of the context puts the time on the rule that
// actually waited.
//
// Atomic because the accumulator now outlives a single call stack: it is reachable from any closure holding this rule's context,
// and a rule is free to fan its own reads out across goroutines. The cost is one atomic add per graph read, against a read that
// just went to MySQL.
type waitAccumulator struct {
	ns atomic.Int64
}

type waitAccumulatorKey struct{}

func withWaitAccumulator(ctx context.Context, acc *waitAccumulator) context.Context {
	return context.WithValue(ctx, waitAccumulatorKey{}, acc)
}

// waitAccumulatorFrom returns the accumulator for the evaluation in progress, or nil when there is none.
//
// Nil is a normal answer rather than a defect. The reader is shared with callers outside an evaluation (a projection resolving an
// alert's detail, and every test that reads the graph directly), and none of them is being charged a budget.
func waitAccumulatorFrom(ctx context.Context) *waitAccumulator {
	acc, _ := ctx.Value(waitAccumulatorKey{}).(*waitAccumulator)
	return acc
}

// timedReader reports every graph read into the accumulator carried by the context of whichever evaluation asked for it.
//
// Stateless, which is a consequence of the context-carried accumulator rather than a separate decision: with the total living in
// the context there is nothing per-evaluation left to hold. It is still constructed per evaluation, because Engine.ruleReader is
// replaced after New by tests and a wrapper snapshotted at construction time would keep reading the original.
var _ api.GraphReader = (*timedReader)(nil)

type timedReader struct {
	inner api.GraphReader
}

// observeWait is called through defer with time.Now() as its argument, which Go evaluates at the defer statement, so start is the
// instant before the read rather than after it.
func observeWait(ctx context.Context, start time.Time) {
	if acc := waitAccumulatorFrom(ctx); acc != nil {
		acc.ns.Add(int64(time.Since(start)))
	}
}

func (r *timedReader) GetProcessByPID(ctx context.Context, hostID string, pid int, atNs int64) (*api.Process, error) {
	defer observeWait(ctx, time.Now())
	return r.inner.GetProcessByPID(ctx, hostID, pid, atNs)
}

func (r *timedReader) GetProcessByPIDVersion(
	ctx context.Context, hostID string, pid int, pidversion uint32, atNs int64,
) (*api.Process, error) {
	defer observeWait(ctx, time.Now())
	return r.inner.GetProcessByPIDVersion(ctx, hostID, pid, pidversion, atNs)
}

func (r *timedReader) GetChildProcesses(
	ctx context.Context, hostID string, ppid int, tr api.TimeRange,
) ([]api.Process, error) {
	defer observeWait(ctx, time.Now())
	return r.inner.GetChildProcesses(ctx, hostID, ppid, tr)
}

func (r *timedReader) GetNetworkEventsForProcess(
	ctx context.Context, hostID string, pid int, tr api.TimeRange,
) ([]api.Event, error) {
	defer observeWait(ctx, time.Now())
	return r.inner.GetNetworkEventsForProcess(ctx, hostID, pid, tr)
}

func (r *timedReader) GetExecChain(ctx context.Context, current api.Process) ([]api.Process, error) {
	defer observeWait(ctx, time.Now())
	return r.inner.GetExecChain(ctx, current)
}

func (r *timedReader) GetHostEventsByType(
	ctx context.Context, hostID, eventType string, tr api.TimeRange,
) ([]api.Event, error) {
	defer observeWait(ctx, time.Now())
	return r.inner.GetHostEventsByType(ctx, hostID, eventType, tr)
}
