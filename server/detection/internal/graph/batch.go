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
	GetParentPath(ctx context.Context, hostID string, pid int, atTimeNs int64) (string, error)
	EventAlreadyApplied(ctx context.Context, hostID string, pid int, eventID string) (bool, error)
	InsertProcess(ctx context.Context, p api.Process) (int64, error)
	UpdateProcessExec(ctx context.Context, u mysql.ProcessExecUpdate) error
	UpdateProcessExit(ctx context.Context, u mysql.ProcessExitUpdate) (int64, error)
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

// GetProcessByPID returns the row whose (host, pid) lifetime brackets atTimeNs, mirroring the store query: fork_time_ns <= atTimeNs
// AND (exit_time_ns IS NULL OR exit_time_ns >= atTimeNs), most recent by (fork_time_ns, id). Returns a copy so handlers cannot mutate
// the overlay through the returned pointer.
//
// The aliveness half of that bracket is deliberately NOT shared with GetParentPath below, even though both answer "which generation
// held this pid" for an instant. The instants differ in what backs them: this one arrives from an unrelated event (a network flow's
// timestamp), so a generation recorded as already exited genuinely must not match, while GetParentPath's instant is a fork whose
// parent was alive by construction. Collapsing the two back into one predicate reinstates a measured 4:1 regression; see the store's
// GetParentPath docstring for the numbers.
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

// EventAlreadyApplied reports whether any overlay row for (host, pid) already records eventID as its creator (source_event_id) or the
// applier of its current image / exit (exec_event_id / exit_event_id). It mirrors the store query against the in-memory overlay so a
// re-processed event is a no-op in both the batched and per-event paths (migration 00011).
func (s *batchSession) EventAlreadyApplied(_ context.Context, hostID string, pid int, eventID string) (bool, error) {
	for _, r := range s.byKey[mysql.HostPID{HostID: hostID, PID: pid}] {
		if matchesEventID(r.proc.SourceEventID, eventID) ||
			matchesEventID(r.proc.ExecEventID, eventID) ||
			matchesEventID(r.proc.ExitEventID, eventID) {
			return true, nil
		}
	}
	return false, nil
}

// matchesEventID reports whether a nullable event-id column equals eventID.
func matchesEventID(field *string, eventID string) bool {
	return field != nil && *field == eventID
}

// GetParentPath returns the path of the newest generation of (host, pid) that had forked by atTimeNs, the child's fork time, or "" when
// none had forked yet. It mirrors the store query, fork bound included; an overlay that dropped the bound would silently reintroduce
// issue #714 for every batch larger than one event, since the batched path is the production one.
//
// It applies no aliveness test, which is the one place this overlay's two pid-plus-instant reads legitimately differ. A parent is
// alive at its child's fork by construction, so an exit timestamp can only disqualify the sole candidate on data that handler-time
// stamping and synthesized pid-reuse closes make unreliable. Do not "fix" the inconsistency with GetProcessByPID above by adding the
// exit test here; the store's GetParentPath docstring carries the measurement that rejected it.
func (s *batchSession) GetParentPath(_ context.Context, hostID string, pid int, atTimeNs int64) (string, error) {
	var best *procRow
	for _, r := range s.byKey[mysql.HostPID{HostID: hostID, PID: pid}] {
		if r.proc.ForkTimeNs > atTimeNs {
			continue
		}
		if best == nil || imageRankGreater(r, best, atTimeNs) {
			best = r
		}
	}
	if best == nil {
		return "", nil
	}
	return best.proc.Path, nil
}

// imageRankGreater reports whether a is the better answer than b for "what was this PID running at atTimeNs", mirroring the store's
// ordering: the generation decides first, then whether the image had been applied by the instant, then which applied image sits
// nearest it, and the row sequence only breaks a remaining tie.
//
// It cannot reuse rankGreater, which orders by fork time and then by row sequence. Every image in a re-exec chain carries the SAME
// fork time (insertReExec preserves it), so sequence order there means "whatever the PID ran last" rather than "what it was running
// then", and picking that hands a child an image its parent had not yet exec'd. The generation still decides first; the image is
// resolved inside it.
func imageRankGreater(a, b *procRow, atTimeNs int64) bool {
	if a.proc.ForkTimeNs != b.proc.ForkTimeNs {
		return a.proc.ForkTimeNs > b.proc.ForkTimeNs
	}
	aApplied, bApplied := imageApplied(a, atTimeNs), imageApplied(b, atTimeNs)
	if aApplied != bApplied {
		return aApplied
	}
	aStart, bStart := imageStart(a), imageStart(b)
	if aStart != bStart {
		if aApplied {
			// Both images were in force at some point by the instant, so the later one is the one that was in force AT it.
			return aStart > bStart
		}
		// Neither had been applied yet, so the child forked inside the generation's own fork-to-exec window and the chain's
		// earliest image is the closest surviving evidence of what its parent was running.
		return aStart < bStart
	}
	return a.seq > b.seq
}

// imageApplied reports whether r's image was in place at atTimeNs. A row with no exec carries the path it inherited at fork, which is
// in place from the fork onward, so it counts as applied.
func imageApplied(r *procRow, atTimeNs int64) bool {
	return r.proc.ExecTimeNs == nil || *r.proc.ExecTimeNs <= atTimeNs
}

// imageStart is when r's path became the PID's image: its exec, or its fork for a row that never exec'd and so still carries the path
// it inherited. Used as the ordering key within one generation.
//
// This compares timestamps rather than measuring a distance between them. An earlier revision ranked by ABS(exec_time_ns minus the instant),
// which reads as "nearest the instant" and overflows on the accepted input domain: intake rejects only a zero timestamp, so a fork at
// a negative instant against an exec near the maximum wraps the difference and outranks a genuinely nearer image (and in SQL raises
// MySQL ERROR 1690 rather than wrapping). Timestamps come from the agent, so no arithmetic on them is safe.
func imageStart(r *procRow) int64 {
	if r.proc.ExecTimeNs == nil {
		return r.proc.ForkTimeNs
	}
	return *r.proc.ExecTimeNs
}

// mostRecentLive returns the most-recent non-exited row for (host, pid), the target of the single-row exec UPDATE. nil when every row
// for the key has exited.
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

// mostRecentLiveForkedAtOrBefore is mostRecentLive restricted to rows that forked at or before atNs, the target of the exit UPDATE. An
// exit cannot close a process that forked after it; the bound is a no-op in single-pass ingest (the live row always forked before its
// exit) but on re-processing (migration 00011) it stops a replayed exit from closing a LATER generation of a reused pid that the
// preload already holds. Mirrors the store's WHERE fork_time_ns <= exitTimeNs.
func (s *batchSession) mostRecentLiveForkedAtOrBefore(hostID string, pid int, atNs int64) *procRow {
	var best *procRow
	for _, r := range s.byKey[mysql.HostPID{HostID: hostID, PID: pid}] {
		if r.proc.ExitTimeNs != nil || r.proc.ForkTimeNs > atNs {
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
	r.proc.ExecEventID = u.ExecEventID
	markDirty(r)
	return nil
}

func (s *batchSession) UpdateProcessExit(_ context.Context, u mysql.ProcessExitUpdate) (int64, error) {
	reason := u.Reason
	if reason == "" {
		reason = api.ExitReasonEvent // mirrors the store's normalisation
	}
	r := s.mostRecentLiveForkedAtOrBefore(u.HostID, u.PID, u.ExitTimeNs)
	if r == nil {
		return 0, nil
	}
	et := u.ExitTimeNs
	r.proc.ExitTimeNs = &et
	ei := u.ExitIngestedAtNs
	r.proc.ExitIngestedAtNs = &ei
	rs := reason
	r.proc.ExitReason = &rs
	ec := u.ExitCode
	r.proc.ExitCode = &ec
	eid := u.ExitEventID
	r.proc.ExitEventID = &eid
	markDirty(r)
	return 1, nil
}

// CloseStaleProcess mirrors mysql.Store.CloseStaleProcess exactly, including its fork_time_ns < closedAtNs bound; the differential
// test asserts the overlay and the store agree. See the store's docstring for why that bound is load-bearing (issue #661).
func (s *batchSession) CloseStaleProcess(_ context.Context, hostID string, pid int, closedAtNs int64) error {
	for _, r := range s.byKey[mysql.HostPID{HostID: hostID, PID: pid}] {
		if r.proc.ExitTimeNs != nil {
			continue
		}
		// Only a generation that started before this fork can be the one the fork displaces. A row stamped at or after the fork is a
		// later generation that was merely processed first (a concurrent batch delivered its exec ahead of the fork).
		if r.proc.ForkTimeNs >= closedAtNs {
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
	// Monotonic: last_seen_ns only advances, mirroring the store's GREATEST. A replayed earlier heartbeat must not drag a freshness
	// value the first pass already advanced back to an older timestamp (migration 00011).
	if best.proc.LastSeenNs != nil && *best.proc.LastSeenNs >= lastSeenNs {
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
		ExecEventID:      p.ExecEventID,
		ExitTimeNs:       p.ExitTimeNs,
		ExitIngestedAtNs: p.ExitIngestedAtNs,
		ExitReason:       p.ExitReason,
		ExitCode:         p.ExitCode,
		ExitEventID:      p.ExitEventID,
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
