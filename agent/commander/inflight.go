package commander

import "sync"

// InFlight tracks the command IDs this process is executing right now, shared by the poll transport and the push transport.
//
// The executor's ledger records a durable "executing" claim before the side effect runs, and a claim it did not win is normally proof
// that a PRIOR attempt was interrupted: the executor terminalizes it as failed so the server stops re-delivering, and never re-runs
// the side effect. That reading depended on the two transports never running at once, which the poll's unbounded deferral to the
// control stream used to guarantee and no longer does (issue #711): the poll is now a bounded floor, so a command can be delivered by
// push and by poll at the same time.
//
// Without this, the losing transport would see the winner's live claim, read it as a crash, and report a command failed while it was
// still executing. The durable ledger cannot tell those apart, because "executing" looks identical whether the attempt is running in
// another goroutine or died with the process. Liveness is process-local, so it is tracked in process rather than pushed into the
// ledger: a claim left by a crash cannot appear here, since the map died with the process that made it.
//
// The zero value is not usable; use NewInFlight. A nil *InFlight disables the check, which is the single-transport case.
type InFlight struct {
	mu  sync.Mutex
	ids map[int64]struct{}
}

// NewInFlight returns an empty tracker.
func NewInFlight() *InFlight {
	return &InFlight{ids: make(map[int64]struct{})}
}

// Begin claims id for this attempt, reporting false when another attempt in this process already holds it. A nil tracker always
// succeeds, so a caller with no second transport needs no special case.
func (f *InFlight) Begin(id int64) bool {
	if f == nil {
		return true
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, held := f.ids[id]; held {
		return false
	}
	f.ids[id] = struct{}{}
	return true
}

// End releases id. Safe on a nil tracker and on an id that was never begun.
func (f *InFlight) End(id int64) {
	if f == nil {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.ids, id)
}
