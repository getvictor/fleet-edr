package engine

import (
	"context"
	"time"

	"github.com/fleetdm/edr/server/detection/api"
)

// timedReader wraps the graph reader for ONE evaluation and accumulates how long that rule spent waiting on reads.
//
// The evaluation budget subtracts this. Review found why it has to: a rule's reads go to MySQL synchronously, so charging a rule
// for them means a slow database disables rules rather than slow rules, and it disables them in proportion to how much of the graph
// they consult. A database slowdown would take out most of the catalog at once, which is precisely the moment detections matter
// most, and the rules it would take out first are the ones doing the most correlation.
//
// What the budget is left measuring is the rule's own matching: its patterns, its walks over the batch, its own logic. That is the
// thing an author controls and the thing #767 set out to bound.
//
// One instance per evaluation, so the accumulator needs no synchronisation even though Evaluate runs from concurrent workers and
// they share the reader underneath. That is also why this is not a field on Engine.
var _ api.GraphReader = (*timedReader)(nil)

type timedReader struct {
	inner   api.GraphReader
	waiting time.Duration
}

func (r *timedReader) observe(start time.Time) { r.waiting += time.Since(start) }

func (r *timedReader) GetProcessByPID(ctx context.Context, hostID string, pid int, atNs int64) (*api.Process, error) {
	defer r.observe(time.Now())
	return r.inner.GetProcessByPID(ctx, hostID, pid, atNs)
}

func (r *timedReader) GetProcessByPIDVersion(
	ctx context.Context, hostID string, pid int, pidversion uint32, atNs int64,
) (*api.Process, error) {
	defer r.observe(time.Now())
	return r.inner.GetProcessByPIDVersion(ctx, hostID, pid, pidversion, atNs)
}

func (r *timedReader) GetChildProcesses(
	ctx context.Context, hostID string, ppid int, tr api.TimeRange,
) ([]api.Process, error) {
	defer r.observe(time.Now())
	return r.inner.GetChildProcesses(ctx, hostID, ppid, tr)
}

func (r *timedReader) GetNetworkEventsForProcess(
	ctx context.Context, hostID string, pid int, tr api.TimeRange,
) ([]api.Event, error) {
	defer r.observe(time.Now())
	return r.inner.GetNetworkEventsForProcess(ctx, hostID, pid, tr)
}

func (r *timedReader) GetExecChain(ctx context.Context, current api.Process) ([]api.Process, error) {
	defer r.observe(time.Now())
	return r.inner.GetExecChain(ctx, current)
}

func (r *timedReader) GetHostEventsByType(
	ctx context.Context, hostID, eventType string, tr api.TimeRange,
) ([]api.Event, error) {
	defer r.observe(time.Now())
	return r.inner.GetHostEventsByType(ctx, hostID, eventType, tr)
}
