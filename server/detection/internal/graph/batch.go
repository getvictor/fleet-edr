package graph

import (
	"context"
	"encoding/json"

	"github.com/fleetdm/edr/server/detection/api"
	"github.com/fleetdm/edr/server/detection/internal/mysql"
)

// processStore is the read/write surface the builder's per-event handlers issue against while folding a batch. Two implementations
// satisfy it: *mysql.Store (the per-event path, one round-trip per call, retained as the differential-test reference) and
// *batchSession (the production path, which resolves reads against an in-memory overlay of one bulk preload and defers all writes to
// a single set-based flush). Because the handlers are written against this interface, the exact same handler code drives both, which
// is what lets the differential property test assert the two produce identical process forests.
type processStore interface {
	GetProcessByPID(ctx context.Context, hostID string, pid int, atTimeNs int64) (*api.Process, error)
	GetParentPath(ctx context.Context, hostID string, pid int) (string, error)
	InsertProcess(ctx context.Context, p api.Process) (int64, error)
	UpdateProcessExec(ctx context.Context, u mysql.ProcessExecUpdate) error
	UpdateProcessExit(ctx context.Context, hostID string, pid int, exitTimeNs, exitIngestedAtNs int64, exitCode int, reason string) (int64, error)
	CloseStaleProcess(ctx context.Context, hostID string, pid int, closedAtNs int64) error
	ReExec(ctx context.Context, priorID int64, exitTimeNs, exitIngestedAtNs int64, newRow api.Process) (newID int64, reLinked bool, err error)
	UpdateLastSeenForSnapshot(ctx context.Context, hostID string, pid int, lastSeenNs int64) error
}

// procRow is one process row in the in-memory overlay during a batch fold. proc holds the current field values; loaded marks a row
// read at preload (real auto-increment id) versus one created during this batch (provisional negative id). dirty marks a loaded row
// whose mutable columns changed and so must be flushed. seq mirrors auto-increment ordering so the in-memory "ORDER BY fork_time_ns
// DESC, id DESC" tiebreak matches the SQL one: loaded rows rank by their real id, and a row created this batch ranks above every
// preloaded row (its eventual id is higher) in creation order.
type procRow struct {
	proc    api.Process
	loaded  bool
	dirty   bool
	seq     int64
	creIdx  int // index into batchSession.newRows for a new row; -1 for a loaded row
	prevNew int // index into batchSession.newRows of a same-batch re-exec predecessor; -1 otherwise
}

// batchSession is the in-memory overlay a single ProcessBatch folds against. It preloads every candidate process row for the batch's
// (host_id, pid) set once, serves the builder's reads from memory (reproducing the SQL predicates exactly, including rows created
// earlier in the same batch), records writes as in-memory mutations, and emits a mysql.ProcessBatchPlan for one set-based flush. It
// is created and discarded per batch, so it holds no cross-request state (ADR-0010).
type batchSession struct {
	rows     []*procRow
	newRows  []*procRow
	byKey    map[mysql.HostPID][]*procRow
	seqBase  int64 // max preloaded id; new rows get seq = seqBase + creationIndex + 1
	nextProv int64 // provisional id allocator, decreasing from -1
}

// newBatchSession bulk-loads the candidate rows for keys and builds the in-memory index.
func newBatchSession(ctx context.Context, store *mysql.Store, keys []mysql.HostPID) (*batchSession, error) {
	loaded, err := store.LoadProcessesForKeys(ctx, keys)
	if err != nil {
		return nil, err
	}
	s := &batchSession{
		byKey:    make(map[mysql.HostPID][]*procRow, len(keys)),
		nextProv: -1,
	}
	for i := range loaded {
		r := &procRow{proc: loaded[i], loaded: true, seq: loaded[i].ID, creIdx: -1, prevNew: -1}
		s.rows = append(s.rows, r)
		key := mysql.HostPID{HostID: r.proc.HostID, PID: r.proc.PID}
		s.byKey[key] = append(s.byKey[key], r)
		if r.proc.ID > s.seqBase {
			s.seqBase = r.proc.ID
		}
	}
	return s, nil
}

// rankGreater reports whether a sorts before b under "ORDER BY fork_time_ns DESC, id DESC": a later fork time wins, ties broken by
// the higher sequence (newer row).
func rankGreater(a, b *procRow) bool {
	if a.proc.ForkTimeNs != b.proc.ForkTimeNs {
		return a.proc.ForkTimeNs > b.proc.ForkTimeNs
	}
	return a.seq > b.seq
}

// GetProcessByPID returns the row whose (host, pid) brackets atTimeNs, mirroring the store query: fork_time_ns <= atTimeNs AND
// (exit_time_ns IS NULL OR exit_time_ns >= atTimeNs), most recent by (fork_time_ns, id). Returns a copy so handlers cannot mutate
// the overlay through the returned pointer.
func (s *batchSession) GetProcessByPID(_ context.Context, hostID string, pid int, atTimeNs int64) (*api.Process, error) {
	var best *procRow
	for _, r := range s.byKey[mysql.HostPID{HostID: hostID, PID: pid}] {
		if r.proc.ForkTimeNs > atTimeNs {
			continue
		}
		if r.proc.ExitTimeNs != nil && *r.proc.ExitTimeNs < atTimeNs {
			continue
		}
		if best == nil || rankGreater(r, best) {
			best = r
		}
	}
	if best == nil {
		return nil, nil
	}
	p := best.proc
	return &p, nil
}

// GetParentPath returns the path of the most-recent (by fork_time_ns, id) row for (host, pid), or "" when none, mirroring the store
// query (no exit-time filter).
func (s *batchSession) GetParentPath(_ context.Context, hostID string, pid int) (string, error) {
	var best *procRow
	for _, r := range s.byKey[mysql.HostPID{HostID: hostID, PID: pid}] {
		if best == nil || rankGreater(r, best) {
			best = r
		}
	}
	if best == nil {
		return "", nil
	}
	return best.proc.Path, nil
}

// mostRecentLive returns the most-recent non-exited row for (host, pid), the target of the single-row exec/exit UPDATEs. nil when
// every row for the key has exited.
func (s *batchSession) mostRecentLive(hostID string, pid int) *procRow {
	var best *procRow
	for _, r := range s.byKey[mysql.HostPID{HostID: hostID, PID: pid}] {
		if r.proc.ExitTimeNs != nil {
			continue
		}
		if best == nil || rankGreater(r, best) {
			best = r
		}
	}
	return best
}

// insertRow appends a new row to the overlay with a provisional id and the auto-increment-mirroring sequence, indexing it for reads.
// prevNewIdx links a same-batch re-exec child to its predecessor's eventual id; -1 when there is none.
func (s *batchSession) insertRow(p api.Process, prevNewIdx int) int64 {
	id := s.nextProv
	s.nextProv--
	p.ID = id
	creIdx := len(s.newRows)
	r := &procRow{proc: p, loaded: false, seq: s.seqBase + int64(creIdx) + 1, creIdx: creIdx, prevNew: prevNewIdx}
	s.rows = append(s.rows, r)
	s.newRows = append(s.newRows, r)
	key := mysql.HostPID{HostID: p.HostID, PID: p.PID}
	s.byKey[key] = append(s.byKey[key], r)
	return id
}

func (s *batchSession) InsertProcess(_ context.Context, p api.Process) (int64, error) {
	return s.insertRow(p, -1), nil
}

// markDirty flags a loaded row for flush. New rows carry their full final state in the plan's NewRows, so they need no dirty flag.
func markDirty(r *procRow) {
	if r.loaded {
		r.dirty = true
	}
}

func (s *batchSession) UpdateProcessExec(_ context.Context, u mysql.ProcessExecUpdate) error {
	r := s.mostRecentLive(u.HostID, u.PID)
	if r == nil {
		return nil // matches the store UPDATE affecting zero rows
	}
	r.proc.Path = u.Path
	r.proc.Args = u.Args
	r.proc.UID = u.UID
	r.proc.GID = u.GID
	r.proc.CodeSigning = u.CodeSigning
	r.proc.SHA256 = u.SHA256
	r.proc.CDHash = u.CDHash
	et := u.ExecTimeNs
	r.proc.ExecTimeNs = &et
	if u.PIDVersion != nil { // COALESCE(?, pidversion): a present value wins, a nil keeps the existing one
		r.proc.PIDVersion = u.PIDVersion
	}
	markDirty(r)
	return nil
}

func (s *batchSession) UpdateProcessExit(_ context.Context, hostID string, pid int,
	exitTimeNs, exitIngestedAtNs int64, exitCode int, reason string,
) (int64, error) {
	if reason == "" {
		reason = api.ExitReasonEvent // mirrors the store's normalisation
	}
	r := s.mostRecentLive(hostID, pid)
	if r == nil {
		return 0, nil
	}
	et := exitTimeNs
	r.proc.ExitTimeNs = &et
	ei := exitIngestedAtNs
	r.proc.ExitIngestedAtNs = &ei
	rs := reason
	r.proc.ExitReason = &rs
	ec := exitCode
	r.proc.ExitCode = &ec
	markDirty(r)
	return 1, nil
}

func (s *batchSession) CloseStaleProcess(_ context.Context, hostID string, pid int, closedAtNs int64) error {
	for _, r := range s.byKey[mysql.HostPID{HostID: hostID, PID: pid}] {
		if r.proc.ExitTimeNs != nil {
			continue
		}
		ct := closedAtNs
		r.proc.ExitTimeNs = &ct
		ci := closedAtNs
		r.proc.ExitIngestedAtNs = &ci
		rs := api.ExitReasonPIDReuse
		r.proc.ExitReason = &rs
		markDirty(r)
	}
	return nil
}

func (s *batchSession) findByID(id int64) *procRow {
	for _, r := range s.rows {
		if r.proc.ID == id {
			return r
		}
	}
	return nil
}

func (s *batchSession) ReExec(_ context.Context, priorID int64,
	exitTimeNs, exitIngestedAtNs int64, newRow api.Process,
) (int64, bool, error) {
	prior := s.findByID(priorID)
	// reLinked mirrors the store's UPDATE predicate: prior exists AND (exit_time_ns IS NULL OR exit_reason = ttl_reconciliation).
	reLinked := prior != nil && (prior.proc.ExitTimeNs == nil ||
		(prior.proc.ExitReason != nil && *prior.proc.ExitReason == api.ExitReasonTTLReconciliation))
	prevNewIdx := -1
	if reLinked {
		et := exitTimeNs
		prior.proc.ExitTimeNs = &et
		ei := exitIngestedAtNs
		prior.proc.ExitIngestedAtNs = &ei
		rs := api.ExitReasonReExec
		prior.proc.ExitReason = &rs
		markDirty(prior)
		if prior.loaded {
			id := prior.proc.ID
			newRow.PreviousExecID = &id
		} else {
			prevNewIdx = prior.creIdx // predecessor created this batch: resolved to a real id at flush
			newRow.PreviousExecID = nil
		}
	} else {
		newRow.PreviousExecID = nil
	}
	return s.insertRow(newRow, prevNewIdx), reLinked, nil
}

func (s *batchSession) UpdateLastSeenForSnapshot(_ context.Context, hostID string, pid int, lastSeenNs int64) error {
	var best *procRow
	for _, r := range s.byKey[mysql.HostPID{HostID: hostID, PID: pid}] {
		if !r.proc.IsSnapshot || r.proc.ExitTimeNs != nil {
			continue
		}
		if best == nil || rankGreater(r, best) {
			best = r
		}
	}
	if best == nil {
		return nil
	}
	ls := lastSeenNs
	best.proc.LastSeenNs = &ls
	markDirty(best)
	return nil
}

// plan converts the folded overlay into the set-based write plan: every new row (creation order, with same-batch re-exec links
// carried as PrevNewIndex) and every modified preloaded row (its full final mutable state).
func (s *batchSession) plan() mysql.ProcessBatchPlan {
	var p mysql.ProcessBatchPlan
	for _, r := range s.newRows {
		p.NewRows = append(p.NewRows, mysql.NewProcessRow{Proc: r.proc, PrevNewIndex: r.prevNew})
	}
	for _, r := range s.rows {
		if r.loaded && r.dirty {
			p.Updates = append(p.Updates, rowUpdate(r.proc))
		}
	}
	return p
}

// rowUpdate captures the mutable column set of a modified preloaded row for the batched UPDATE.
func rowUpdate(p api.Process) mysql.ProcessRowUpdate {
	return mysql.ProcessRowUpdate{
		ID:               p.ID,
		Path:             p.Path,
		Args:             p.Args,
		UID:              p.UID,
		GID:              p.GID,
		CodeSigning:      p.CodeSigning,
		SHA256:           p.SHA256,
		CDHash:           p.CDHash,
		ExecTimeNs:       p.ExecTimeNs,
		PIDVersion:       p.PIDVersion,
		ExitTimeNs:       p.ExitTimeNs,
		ExitIngestedAtNs: p.ExitIngestedAtNs,
		ExitReason:       p.ExitReason,
		ExitCode:         p.ExitCode,
		LastSeenNs:       p.LastSeenNs,
	}
}

// pidEnvelope is the minimal payload shape the preloader reads to discover which (host_id, pid) lineages a batch touches, without
// the full per-event decode the handlers do. A fork touches both its child and parent pid (the parent for path inheritance); every
// other handled event touches its own pid.
type pidEnvelope struct {
	PID       int `json:"pid"`
	ChildPID  int `json:"child_pid"`
	ParentPID int `json:"parent_pid"`
}

// collectKeys returns the distinct (host_id, pid) keys the batch will read or write, so the session can preload them in one query.
// A payload that fails the minimal decode is skipped here; the handler re-decodes it and drops it as a permanent error, so a
// malformed event never needed a preloaded row anyway.
func collectKeys(events []api.Event) []mysql.HostPID {
	seen := make(map[mysql.HostPID]struct{})
	var keys []mysql.HostPID
	add := func(hostID string, pid int) {
		k := mysql.HostPID{HostID: hostID, PID: pid}
		if _, ok := seen[k]; ok {
			return
		}
		seen[k] = struct{}{}
		keys = append(keys, k)
	}
	for _, evt := range events {
		switch evt.EventType {
		case "fork", "exec", "exit", "snapshot_heartbeat":
		default:
			continue
		}
		var p pidEnvelope
		if err := json.Unmarshal(evt.Payload, &p); err != nil {
			continue
		}
		if evt.EventType == "fork" {
			add(evt.HostID, p.ChildPID)
			add(evt.HostID, p.ParentPID)
			continue
		}
		add(evt.HostID, p.PID)
	}
	return keys
}
