package pipeline

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/fleetdm/edr/server/coordination/leader"
	"github.com/fleetdm/edr/server/detection/api"
	rulesapi "github.com/fleetdm/edr/server/rules/api"
	visibilityapi "github.com/fleetdm/edr/server/visibility/api"
)

// batchBuilder materializes a claimed event batch into the process graph before rule evaluation reads it. *graph.Builder is the
// production implementation; the interface lets the processor's unit tests drive its claim / nack / ack accounting without a graph
// store or a live MySQL.
type batchBuilder interface {
	ProcessBatch(ctx context.Context, events []visibilityapi.Event) error
}

// batchEvaluator runs the detection rules over a materialized batch. *engine.Engine is the production implementation.
//
// The tally it returns is what the batch found in monitor mode, and it comes back rather than being written by the engine so this
// processor can record it on whichever transition ends the batch's life. A nacked batch is replayed whole, so anything the engine
// wrote while evaluating would be counted twice; a tally handed back is counted once, by whichever attempt succeeds.
//
// It is returned ALONGSIDE an error too, and not instead of one. An error usually means a replay, where this attempt's tally is
// discarded because a later one will produce it again; but the queue can also withdraw the batch from processing for good, and
// then this attempt is the only one there will ever be. The engine cannot tell those apart because only the queue knows, so it
// hands the tally over on every path and the decision is made here (#843).
type batchEvaluator interface {
	Evaluate(ctx context.Context, events []visibilityapi.Event) (rulesapi.MonitorTally, error)
}

// hostClaimLockPrefix namespaces the per-host advisory locks the processor serializes on, keeping them clear of the leader-election
// lock names the same coordinator hands out for retention and the process-TTL sweep.
const hostClaimLockPrefix = "edr:evq:host:"

// mysqlLockNameMax is MySQL's hard limit on a GET_LOCK name. Exceeding it is an error, not a truncation, so a long host id would make
// every claim attempt for that host fail and strand its backlog. host_id is VARCHAR(255) in event_queue, so the limit is reachable
// from the schema even though enrollment issues 36-character UUIDs today.
const mysqlLockNameMax = 64

// hostCandidateFactor scales how many candidate hosts a worker asks for per cycle, relative to the worker count. Asking for several
// per worker is what keeps the fleet spread out: workers wake on the same tick, and each rotates its scan to a different offset, so a
// window a few times wider than the worker count leaves every worker a host of its own to try before any two collide.
const hostCandidateFactor = 4

// minHostCandidates floors the candidate window so a single-worker processor still looks past one blocked host.
const minHostCandidates = 4

// Processor claims events from the visibility EventLog work queue and runs them through the graph builder, then evaluates detection
// rules over the same batch. Decouples event ingestion from graph materialization so the write path (intake) runs independently of the
// processing path. Post-cutover (ADR-0015) the queue is the only work source; the durable archive is read-only correlation storage.
type Processor struct {
	eventLog    visibilityapi.EventLog
	builder     batchBuilder
	detection   batchEvaluator
	coordinator leader.Coordinator
	metrics     api.MetricsRecorder
	// monitorMatches persists what a batch found in monitor mode, once that batch will not be processed again. Nil records nothing,
	// which is the shape for a deployment or test with no rules-context store wired: monitor mode still suppresses the alert
	// either way.
	monitorMatches rulesapi.MonitorMatchRecorder
	logger         *slog.Logger
	interval       time.Duration
	batch          int
	concurrency    int
	clamp          *concurrencyClamp
}

// ProcessorOptions configures a Processor. It is a struct rather than positional parameters because the coordinator took the
// constructor past the seven-argument ceiling, and it matches the sibling pipeline constructors (ProcessTTLOptions, RetentionOptions,
// QueuePruneOptions).
type ProcessorOptions struct {
	// Logger defaults to slog.Default() when nil.
	Logger *slog.Logger
	// Interval is the poll cadence for each worker loop.
	Interval time.Duration
	// Batch caps the events one claim takes. Clamped to at least 1.
	Batch int
	// Concurrency is the number of in-process worker loops (issue #535). Each serializes on a different host, so the effective
	// parallelism is bounded by the number of hosts with pending work, not by this value alone. Ignored (forced to 1) when
	// Coordinator is nil, since without a lock there is nothing to keep two workers off one host.
	Concurrency int
	// Coordinator provides the per-host advisory lock that serializes one host's stream onto one worker at a time (issue #717). It
	// is the ONLY mechanism here that serializes a host across replicas, because the lock lives in MySQL.
	//
	// Optional, but a deployment that omits it is only safe as a single replica. With no coordinator the processor falls back to one
	// worker, which bounds a host to one claimer WITHIN this process; it cannot stop a second replica from claiming the same host
	// and folding its stream concurrently, which recreates the duplicate generations and missing re-exec links of issue #717. Run
	// multi-replica with a coordinator.
	Coordinator leader.Coordinator
	// ConnBudget is the MySQL pool's MaxOpenConns, used to size Concurrency so the workers cannot deadlock on the pool. A worker
	// under the per-host lock holds TWO connections at once: the one GET_LOCK pins for the critical section, plus the one the claim
	// and flush run on. With ConnBudget below twice Concurrency, workers can take every connection as a lock connection and then
	// block forever waiting for a claim connection, which presents as a silent stall rather than an error.
	//
	// The budget is the WHOLE pool, shared with the request path and the background sweeps, so workers are held to a share of it
	// (workerPoolShareDivisor) rather than all of it. A budget too small for even one worker is a configuration error NewProcessor
	// refuses, because clamping to one worker there would produce exactly the stall the sizing exists to prevent. Zero means unknown
	// and skips both the sizing and the refusal.
	ConnBudget int
	// ReservedConns is how many pooled connections are already spoken for by something else that holds them for its whole
	// lifetime, and so are not available to workers however large the pool looks. Today that is the coordinator's leader-gated
	// loops (LeaderGatedLoops), each of which pins one connection for its lock from boot to shutdown.
	//
	// It is injected rather than assumed because this package should not encode how many background sweeps its caller starts:
	// the bootstrap that wires those loops is the only thing that knows. Zero means nothing is reserved (issue #722).
	ReservedConns int
}

// connsPerWorker is how many pooled connections one worker occupies inside its critical section: the GET_LOCK connection the
// coordinator pins, plus the connection the claim and flush use.
const connsPerWorker = 2

// workerPoolShareDivisor keeps the worker fleet from sizing itself to the whole pool. ConnBudget is the process-wide MaxOpenConns,
// shared with the ingest handlers, the retention and TTL sweeps, the queue prune and every request-path query, so sizing workers at
// ConnBudget/connsPerWorker would let them hold nearly every connection inside their critical sections and starve the rest of the
// server. Halving that leaves most of the pool for everyone else. It does not bind at the shipped defaults (a 25-connection pool
// affords 6 workers against a configured 4); it is what keeps a future concurrency increase from quietly consuming the pool.
const workerPoolShareDivisor = 2

// minConnsForOneWorker is the smallest usable budget: below it there is no worker count that can run, so the configuration is
// refused rather than clamped. It is connsPerWorker scaled by the share divisor, which is the same arithmetic the affordability
// calculation uses, so the guard and its error message quote one number instead of two that disagree.
//
// They used to disagree: the guard refused below connsPerWorker (2) while its message told the operator to raise the pool to 4, so
// budgets of 2 and 3 passed a check whose own advice rejected them and were then clamped to a worker that could not make progress
// (issue #722).
const minConnsForOneWorker = connsPerWorker * workerPoolShareDivisor

// concurrencyClamp records that the effective worker count came out below the configured one, and why. The constructor decides it but
// cannot log it: it has no context, and fabricating a background one there is what contextcheck (rightly) rejects. Run emits it once
// at startup instead, so an operator whose configured concurrency was not honored sees the reason in the logs.
type concurrencyClamp struct {
	reason string
	attrs  []any
}

// NewProcessor creates a Processor that claims from the given EventLog. Workers claim per host and serialize on that host, so a
// host's events always reach the graph builder in causal order (issue #717) while different hosts still process in parallel. The
// workers share this Processor's builder and engine, both of which are safe under concurrent batches for DIFFERENT hosts (the graph
// builder serialises its cross-batch exit buffer, and rule evaluation is read-then-dedup-insert).
// It returns an error for a configuration it cannot run rather than starting a pipeline that cannot make progress: see the connection
// budget check below.
func NewProcessor(
	eventLog visibilityapi.EventLog,
	builder batchBuilder,
	det batchEvaluator,
	opts ProcessorOptions,
) (*Processor, error) {
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	concurrency := max(opts.Concurrency, 1)
	// Without a coordinator two workers in THIS process could claim the same host and fold its stream out of order, which is the
	// defect #717 fixes, so fall back to one worker. That bound is intra-replica only: nothing here stops another replica's worker
	// from claiming the same host, so the warning says so rather than implying the guarantee still holds fleet-wide.
	var clamp *concurrencyClamp
	if opts.Coordinator == nil && concurrency > 1 {
		clamp = &concurrencyClamp{
			reason: "detection processor has no coordinator; running a single worker, which orders one host's events only within " +
				"this replica: run with a coordinator in any multi-replica deployment",
			attrs: []any{"requested_concurrency", concurrency, "effective_concurrency", 1},
		}
		concurrency = 1
	}
	// Size the fleet to what the pool can actually serve. Exceeding it does not degrade gracefully: every worker can hold a lock
	// connection while waiting for a claim connection that no one will release, so the processor stops dead with nothing logged.
	//
	// Clamping cannot rescue a budget too small for even one worker. A single worker still needs connsPerWorker connections, so a
	// pool below that deadlocks the one worker the clamp would leave: it pins the only connection for GET_LOCK and then waits
	// forever for a claim connection. That is the exact stall the clamp exists to avoid, so refuse the configuration instead. A
	// deployment that will not boot states its problem; one that boots and silently never processes an event does not.
	if opts.Coordinator != nil && opts.ConnBudget > 0 {
		// Subtract what is already pinned before sizing anything. Connections held by the leader-gated loops are never returned
		// while the process runs, so counting them as available sizes the fleet against connections that do not exist.
		available := opts.ConnBudget - opts.ReservedConns
		if available < minConnsForOneWorker {
			return nil, fmt.Errorf(
				"detection processor: MySQL pool of %d connection(s) leaves %d after %d reserved for the leader-gated loops, which "+
					"cannot serve one worker; the per-host claim lock needs %d connections per worker (one pinned by GET_LOCK, one "+
					"for the claim and flush) and workers take at most half the pool, so raise the pool to at least %d",
				opts.ConnBudget, available, opts.ReservedConns, connsPerWorker, opts.ReservedConns+minConnsForOneWorker)
		}
		// No max(..., 1) floor: the refusal above guarantees at least one worker is affordable, so a floor here could only ever
		// manufacture a worker the pool cannot serve, which is the stall this whole check exists to prevent.
		if affordable := available / minConnsForOneWorker; concurrency > affordable {
			clamp = &concurrencyClamp{
				reason: "detection processor concurrency clamped to the connection budget",
				attrs: []any{
					"requested_concurrency", concurrency, "effective_concurrency", affordable,
					"max_open_conns", opts.ConnBudget, "reserved_conns", opts.ReservedConns,
					"available_conns", available, "conns_per_worker", connsPerWorker,
					"pool_share_divisor", workerPoolShareDivisor,
				},
			}
			concurrency = affordable
		}
	}
	// A non-positive batch size would make the drain loop (`for processOnce(ctx) >= p.batch`) spin: an empty claim returns 0 and
	// 0 >= 0 stays true forever. Clamp to at least 1 so an empty queue always breaks the drain and yields back to the ticker.
	batchSize := max(opts.Batch, 1)
	return &Processor{
		eventLog:    eventLog,
		builder:     builder,
		detection:   det,
		coordinator: opts.Coordinator,
		logger:      logger,
		interval:    opts.Interval,
		batch:       batchSize,
		concurrency: concurrency,
		clamp:       clamp,
	}, nil
}

// hostClaimLockName is the advisory-lock name for one host's claim. It uses the raw host id so a held lock is legible in
// performance_schema.metadata_locks during an incident, falling back to a hash only when the composed name would exceed MySQL's
// 64-character limit (which GET_LOCK rejects outright rather than truncating).
func hostClaimLockName(hostID string) string {
	name := hostClaimLockPrefix + hostID
	if len(name) <= mysqlLockNameMax {
		return name
	}
	sum := sha256.Sum256([]byte(hostID))
	return (hostClaimLockPrefix + hex.EncodeToString(sum[:]))[:mysqlLockNameMax]
}

// SetMetrics installs the OTel recorder the processor counts materialization-miss retries on (issue #631). Called by
// Runner.SetMetrics during cmd/main's two-phase wiring; nil-safe (an unset recorder no-ops the retry counter). Set-once before Run,
// like the sibling runners' recorders, so the running worker loops only read it.
func (p *Processor) SetMetrics(m api.MetricsRecorder) { p.metrics = m }

// SetMonitorMatchRecorder wires the durable monitor-match counter AFTER construction, mirroring SetMetrics. cmd/main passes the
// rules context's store once both contexts are built; the rules context owns the table, so the wiring direction matches the
// engine's mode resolver rather than reaching across it (ADR-0004).
func (p *Processor) SetMonitorMatchRecorder(r rulesapi.MonitorMatchRecorder) { p.monitorMatches = r }

// Run fans out p.concurrency worker loops and blocks until ctx is cancelled and every worker returns. Each worker claims its own
// disjoint batches, so the processor scales across the replica's cores the same way it scales across replicas (server-availability spec).
func (p *Processor) Run(ctx context.Context) error {
	if p.clamp != nil {
		p.logger.WarnContext(ctx, p.clamp.reason, p.clamp.attrs...)
	}
	var wg sync.WaitGroup
	for i := range p.concurrency {
		wg.Go(func() {
			p.runWorker(ctx, i)
		})
	}
	wg.Wait()
	return nil
}

// runWorker is one claim loop. On each tick it drains: while a cycle returns a full batch there is likely more backlog, so it claims
// again immediately rather than waiting a full interval, which lets the worker fleet work a backlog down quickly. A non-full cycle
// (empty, or a nacked failure) yields back to the ticker so a persistently failing batch cannot hot-spin. workerIndex rotates this
// worker's scan over the candidate hosts so simultaneous ticks do not all contend for the same host's lock.
func (p *Processor) runWorker(ctx context.Context, workerIndex int) {
	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for p.processOnce(ctx, workerIndex) >= p.batch {
				if ctx.Err() != nil {
					return
				}
			}
		}
	}
}

// ProcessOnce runs a single processing cycle. Exported for testing.
func (p *Processor) ProcessOnce(ctx context.Context) {
	p.processOnce(ctx, 0)
}

// processOnce picks a host with pending work and processes one batch of it, returning the number of events claimed (0 on an empty
// queue, a claim error, a host whose lock is held by another worker, or a builder/detection failure that nacked the batch). The count
// lets runWorker decide whether to keep draining.
//
// It walks the candidate hosts rather than committing to the first: a host whose lock is already held by another worker yields
// nothing, and moving on is what keeps the fleet busy instead of queueing behind one host. Returning 0 when every candidate is taken
// falls back to the ticker rather than spinning.
func (p *Processor) processOnce(ctx context.Context, workerIndex int) int {
	hosts, err := p.eventLog.PendingHosts(ctx, p.hostCandidates())
	if err != nil {
		p.logger.ErrorContext(ctx, "list pending hosts", "err", err)
		return 0
	}
	if len(hosts) == 0 {
		return 0
	}
	for offset := range hosts {
		if ctx.Err() != nil {
			return 0
		}
		host := hosts[(workerIndex+offset)%len(hosts)]
		claimed, ran := p.processHost(ctx, host)
		if ran && claimed > 0 {
			return claimed
		}
		// Holding the lock but claiming nothing is not a reason to stop for this tick. PendingHosts is a hint, and a hint is a
		// snapshot: the host's backlog may have been drained by another worker between the two calls, or an event may have gone in
		// flight since, putting the rest of that host's stream behind a claim bound. The hint already excludes hosts blocked that
		// way when it is taken, so this is now the narrow race rather than the standing case it was, but either way this host has
		// no work for us right now and the next candidate might, so keep walking rather than idling until the next tick.
	}
	return 0
}

// hostCandidates is how many hosts one cycle considers: wide enough that concurrent workers rotate onto different hosts, floored so a
// single worker still looks past a host another replica is holding.
func (p *Processor) hostCandidates() int {
	return max(p.concurrency*hostCandidateFactor, minHostCandidates)
}

// processHost claims and processes one batch for host, under that host's advisory lock. It reports the events claimed and whether this
// worker actually ran (false means another worker or replica holds the host, so the caller should try a different one).
//
// The lock spans claim, fold, and flush, and nothing else. That is the window in which a second claimer would break the graph
// builder's per-host ordering assumption: it resolves each exec against the rows already flushed, so an unflushed fork is
// indistinguishable from a missing one. Detection is deliberately outside the lock because it only reads the graph, so there is no
// reason to hold a fleet-visible lock across it. The keep-alive added in #721 means a longer section would no longer risk a silent
// release, but a short one is still the right shape.
func (p *Processor) processHost(ctx context.Context, host string) (int, bool) {
	var (
		events      []visibilityapi.Event
		claimStamp  int64
		buildFailed bool
		// carried is what the queue handed back when a fold-stage nack withdrew the whole batch: matches an EARLIER attempt
		// resolved and this one never saw. Recorded after the lock is released rather than inside the section, so a fleet-visible
		// host lock is not held across a telemetry write (issue #893).
		carried []byte
	)
	claimAndBuild := func(lockedCtx context.Context) error {
		claimed, stamp, err := p.eventLog.ClaimForHost(lockedCtx, host, p.batch)
		if err != nil {
			p.logger.ErrorContext(lockedCtx, "claim events", "host_id", host, "err", err)
			return nil
		}
		if len(claimed) == 0 {
			return nil
		}
		events, claimStamp = claimed, stamp
		if err := p.builder.ProcessBatch(lockedCtx, claimed); err != nil {
			p.logger.WarnContext(lockedCtx, "graph builder failure, will retry batch", "err", err)
			buildFailed = true
			// Requeue inside the lock, not after it. A failed batch's rows stay in flight until the Nack lands, and releasing the
			// host first would let the next claimer take this host's LATER events and fold them ahead of these, so the retry would
			// arrive behind generations it precedes. The claim's in-flight bound makes that window harmless even if this Nack
			// fails, but closing the window is cheaper than relying on the bound to cover it.
			//
			// No tally is handed over: this attempt failed before detection ran, so it resolved nothing. Nack keeps whatever an
			// EARLIER attempt supplied rather than clearing it, which is what lets the withdrawal below report matches this
			// attempt never saw (issue #893).
			nacked, nackErr := p.eventLog.Nack(lockedCtx, eventIDsOf(claimed), stamp, nil)
			if nackErr != nil {
				p.logger.ErrorContext(lockedCtx, "nack events after builder failure", "err", nackErr)
			}
			p.reportLostClaim(lockedCtx, nackErr, nacked.Held, host, len(claimed))
			p.reportSetAside(lockedCtx, host, nacked.SetAside, stageBuilder)
			carried = nacked.CarriedTally
		}
		return nil
	}

	if p.coordinator == nil {
		// Single-worker mode (NewProcessor forces it when no coordinator is wired). One worker keeps this host's events in order
		// within this replica; it does not stop another replica from claiming the same host (see ProcessorOptions.Coordinator).
		_ = claimAndBuild(ctx)
	} else {
		ran, err := p.coordinator.DoOnceIfLeader(ctx, hostClaimLockName(host), claimAndBuild)
		if err != nil {
			// ErrLockLost is distinct from failing to acquire: the section DID start and may have folded part of a batch before
			// the lock went. Nothing is acked until the batch completes, so those events stay in flight and are redelivered when
			// the claim lease expires. Moving to another host is right either way; the two just need different names in the log.
			msg := "acquire host claim lock"
			if errors.Is(err, leader.ErrLockLost) {
				msg = "lost host claim lock mid-batch; events stay in flight for redelivery"
			}
			p.logger.ErrorContext(ctx, msg, "host_id", host, "err", err)
			return 0, false
		}
		if !ran {
			return 0, false
		}
	}
	if len(events) == 0 {
		return 0, true
	}
	if buildFailed {
		// A whole withdrawal at the fold is the batch's last word too, and the matches it reports were resolved by an EARLIER
		// attempt: this one never evaluated (issue #893). Out here rather than in the locked section above, because the lock spans
		// claim, fold and flush and nothing else, and a telemetry write is not one of them.
		//
		// Unconditional, unlike the detection path's own tally, because the queue already made this decision. It hands a carried
		// tally back only for a batch it withdrew in full, and nothing otherwise, so a whole-batch comparison here would re-check
		// what the contract guarantees. Exactly-once comes from the same place: the 0 -> 3 transition happens once for a row in
		// its life, so only the caller whose statement performed it is handed the tally.
		p.recordCarriedMatches(ctx, carried)
		// Already requeued inside the lock. Stop draining so a persistently failing batch cannot hot-spin.
		return 0, true
	}

	return p.evaluateAndAck(ctx, events, eventIDsOf(events), claimStamp), true
}

// withHostLock runs fn while holding the host's claim lock, so an acknowledgement cannot interleave with another worker's claim
// for the same host (issue #863).
//
// The claim already runs under this lock and the acknowledgement did not, which left a window with a real ordering consequence.
// `Ack`'s conditional update takes row locks as it scans, so an earlier event of the batch can be locked while a later one is
// not; a claimer arriving in between finds the locked row via `FOR UPDATE SKIP LOCKED`, SKIPS it, and takes the later one. The
// in-flight floor does not bound that, because it only counts claims that are still live and this window is reached precisely
// when the claim has outlived its lease. So the later event is folded without its predecessor, which is the guarantee the floor
// exists to protect, reached by a route the floor cannot see.
//
// The lock is taken for the acknowledgement ALONE, not held across detection. That is the point: the processor deliberately
// releases it before evaluating rules so a slow rule cannot hold a host, and re-acquiring it for a window that is one statement
// long keeps that property while closing the race. Both callers take the advisory lock before any row lock, so the ordering
// between the two lock types is the same on the claim path and this one, and they cannot deadlock against each other.
//
// Blocking rather than try-lock, which is the difference from the claim's DoOnceIfLeader: a claimer that loses the race has other
// hosts to work on, while an acknowledgement has nothing else to do and abandoning it would leave a processed batch to be
// redelivered on lease expiry for no reason.
//
// Without a coordinator there is one worker per replica by construction (NewProcessor forces it), so there is no second claimer
// on this replica to race and fn runs directly. That does not make the ordering safe against ANOTHER replica, which is the same
// disclaimer the claim path carries.
func (p *Processor) withHostLock(ctx context.Context, host string, fn func(context.Context) error) error {
	if p.coordinator == nil {
		return fn(ctx)
	}
	return p.coordinator.WithLock(ctx, hostClaimLockName(host), fn)
}

// underHostLock is withHostLock for a callback that also reports a value, which the acknowledgement does: whether the claim was
// still held. Written out rather than closing over a variable at each call site, because the variable would be read after the
// lock is released and the point of the helper is that everything about the acknowledgement happens inside it.
func (p *Processor) underHostLock(ctx context.Context, host string, fn func(context.Context) (bool, error)) (bool, error) {
	var out bool
	err := p.withHostLock(ctx, host, func(lockedCtx context.Context) error {
		var innerErr error
		out, innerErr = fn(lockedCtx)
		return innerErr
	})
	return out, err
}

// eventIDsOf projects a claimed batch to the identities Ack and Nack take, so neither the locked region nor the post-lock path has to
// keep a parallel slice in step with events.
func eventIDsOf(events []visibilityapi.Event) []string {
	ids := make([]string, len(events))
	for i, e := range events {
		ids[i] = e.EventID
	}
	return ids
}

// evaluateAndAck runs detection over an already-materialized batch and acknowledges it, returning the events processed or 0 if the
// batch was nacked or the ack failed. Split from processHost so the locked region above stays readable as claim-fold-flush.
func (p *Processor) evaluateAndAck(ctx context.Context, events []visibilityapi.Event, eventIDs []string, claimStamp int64) int {
	// Run detection rules after processes are materialized.
	var tally rulesapi.MonitorTally
	if p.detection != nil {
		var err error
		tally, err = p.detection.Evaluate(ctx, events)
		if err != nil {
			p.logDetectionRetry(ctx, err)
			// This attempt DID evaluate, so it hands its matches to Nack to be kept with the events. They are discarded for this
			// attempt either way, which is right: the batch comes back and produces them again. What changes is that a LATER
			// attempt failing at the fold, which resolves nothing of its own, can still report them when it withdraws the batch
			// (issue #893). An encoding failure costs only that carry, so it is logged and the nack proceeds: withdrawing the
			// batch matters more than the counter, and this attempt still records its own tally below.
			carry, encodeErr := encodeMonitorTally(tally)
			if encodeErr != nil {
				p.logger.ErrorContext(ctx, "encode monitor tally for retry", "err", encodeErr, "entries", len(tally))
			}
			var nacked visibilityapi.NackResult
			nackErr := p.withHostLock(ctx, hostOf(events), func(lockedCtx context.Context) error {
				var innerErr error
				nacked, innerErr = p.eventLog.Nack(lockedCtx, eventIDs, claimStamp, carry)
				return innerErr
			})
			if nackErr != nil {
				p.logger.ErrorContext(ctx, "nack events after detection failure", "err", nackErr)
			}
			p.reportLostClaim(ctx, nackErr, nacked.Held, hostOf(events), len(eventIDs))
			p.reportSetAside(ctx, hostOf(events), nacked.SetAside, stageDetection)
			// A withdrawn batch has no later attempt to be counted by, so this one is the last word on what it matched. Every
			// other nack discards the tally, and must: the batch comes back and produces the same matches again.
			//
			// A withdrawal at the FOLD is covered too, since #893: the tally handed to Nack above is kept with the events and
			// returned to whoever withdraws them, so an attempt that never evaluated still reports what an earlier one matched.
			// It rides in the queue rather than in the replica because ADR-0010 rules out in-process state a peer would need,
			// and it costs no additional write, because the nack that has a tally is already updating those rows.
			//
			// Only a WHOLE batch counts, and the comparison is against the batch rather than against zero. The withdrawal
			// predicate is per row, so a partial withdrawal leaves rows that are re-claimed and re-evaluated, and this tally
			// covers all of them: recording it would count the survivors twice.
			//
			// Exactly-once across replicas comes from the queue rather than from a lock here, and specifically from set-aside
			// being TERMINAL. Nack's withdrawing statement matches rows at processed = 0, and a withdrawn row sits at 3, which
			// nothing moves it back from: Nack's own reset requires 2. So the 0 -> 3 transition happens once for a row in its
			// life, row locks serialise concurrent attempts at it, and only the caller whose statement performed it counts it.
			//
			// NOT because that statement is restricted to rows this transaction reset, which review corrected: its predicate is
			// the requested ids at processed = 0, so it can also match a row another nack had already returned to pending. That
			// makes no difference to the count, and the distinction matters for anyone changing this queue.
			//
			// Per claim as well as per row, since #840: a nack acts only on the events the claim it names still holds, so an
			// attempt that outran its lease withdraws nothing and is told so, rather than withdrawing a replacement's events and
			// being rejected here for a count short of its own batch.
			if nacked.SetAside == int64(len(eventIDs)) {
				// What the queue carried, not this attempt's own tally, whenever the encoding above succeeded. The two differ in
				// a case that is ordinary rather than exotic: Evaluate returns the matches it accumulated UP TO the failure, so
				// an attempt that fails on an earlier rule than a previous one returns FEWER matches, and possibly none. Rules
				// are also skipped per replica once a rule exceeds its evaluation budget, and the active rule set is reloaded
				// between attempts. Recording this attempt's tally would then discard what an earlier one resolved on the very
				// path #893 exists to fix, just reached through detection rather than the fold.
				//
				// The queue holds whichever is authoritative: this attempt's, since a non-empty tally was handed over above and
				// supersedes; or an earlier attempt's, when this one resolved nothing and handed over nothing.
				//
				// The fallback is for an encoding failure alone, where the queue could NOT have this attempt's tally, so the
				// value in hand is the only one that reflects this attempt.
				if encodeErr != nil {
					p.recordMonitorMatches(ctx, tally)
				} else {
					p.recordCarriedMatches(ctx, nacked.CarriedTally)
				}
			}
			return 0
		}
	}

	held, err := p.underHostLock(ctx, hostOf(events), func(lockedCtx context.Context) (bool, error) {
		return p.eventLog.Ack(lockedCtx, eventIDs, claimStamp)
	})
	if err != nil {
		// The batch processed but the queue was not durably advanced (the rows stay leased until the claim lease expires).
		// Returning 0 stops the drain loop so the worker waits for the next tick rather than treating this as a full-batch
		// drain and immediately re-claiming, which would spread a transient ack outage into a tight re-processing loop.
		p.logger.ErrorContext(ctx, "ack events", "err", err)
		return 0
	}
	if !held {
		// This evaluation outlived its claim lease and another attempt owns the rows now (issue #817). Everything up to here is
		// idempotent: the graph builder is keyed on event identity and alert persistence deduplicates on
		// (source, host, rule, subject). What follows is not, so it belongs to whichever attempt still holds the claim.
		//
		// Logged at WARN because it is also the first visibility anyone has that leases are being exceeded at all, which was
		// previously invisible by construction: both attempts acknowledged successfully and neither learned it had lost.
		p.logger.WarnContext(ctx, "lost the claim before acknowledging; another attempt owns this batch",
			"host_id", hostOf(events), "events", len(eventIDs))
		return 0
	}
	p.recordMonitorMatches(ctx, tally)
	return len(events)
}

// recordMonitorMatches persists and counts a batch's monitor-mode matches, on whichever transition ends the batch's life.
//
// Two transitions end it, and both call here. The ordinary one is the acknowledgement, and this runs AFTER it so a replayed batch
// is counted once: everything before that point can still nack, and a nacked batch re-evaluates and produces the same matches
// again. The other is the batch being withdrawn from processing for good once its retry bounds are passed (#836), where there is
// no later attempt to count it and the attempt that was withdrawn is the last word on what it matched (#843).
//
// The cost of recording after a transition rather than during evaluation is the opposite failure, a crash between the transition
// and this write, which loses those counts.
//
// That loss is the RISK-BEARING direction and is accepted rather than preferred. A count that is too low makes a rule look quiet,
// which is exactly what persuades an operator to promote it, and promoting a noisy rule is the alert flood issue #764 exists to
// prevent. It is the better trade only because the alternative is systematic: counting during evaluation inflates on every
// retry, while this loses counts only in the window between two adjacent statements.
//
// A successful Ack IS now proof that this attempt uniquely processed the batch, which it was not when this comment was first
// written. Ack was an unconditional update that ignored its affected-row count, so an evaluation outliving its five-minute lease
// ran alongside its own reclaimer and both acknowledged successfully, double-counting this additive counter (alert persistence was
// immune, deduplicating on (host, rule, subject)). Issue #817 fixed that in the queue contract, where it belonged: Ack is
// conditional on still holding the claim and reports whether it did, and the caller skips this write when it has lost.
//
// A failure here cannot fail the batch, on either path, and for the same reason on both: the batch has already reached a state it
// will not be processed again from, so there is nothing left to fail. Acknowledged events are done, and withdrawn ones are not
// coming back; re-nacking either to save a counter would replay real detection work or undo a withdrawal. It is logged and
// dropped.
func (p *Processor) recordMonitorMatches(ctx context.Context, tally rulesapi.MonitorTally) {
	if len(tally) == 0 {
		return
	}
	if p.metrics != nil {
		for _, m := range tally {
			p.metrics.MonitorMatched(ctx, m.RuleID, m.Severity, m.Count)
		}
	}
	if p.monitorMatches == nil {
		return
	}
	if err := p.monitorMatches.RecordMonitorMatches(ctx, tally); err != nil {
		p.logger.ErrorContext(ctx, "record monitor matches", "err", err, "entries", len(tally))
	}
}

// recordCarriedMatches records the tally Nack carried across a batch's attempts, for a withdrawal reached by an attempt that never
// evaluated (issue #893).
//
// A decode failure loses the counts and is logged rather than failing anything, matching what recordMonitorMatches does with a
// write failure and for the same reason: the batch has been withdrawn and is not coming back, so there is nothing left to fail.
func (p *Processor) recordCarriedMatches(ctx context.Context, carried []byte) {
	if len(carried) == 0 {
		return
	}
	tally, err := decodeMonitorTally(carried)
	if err != nil {
		p.logger.ErrorContext(ctx, "decode carried monitor tally", "err", err)
		return
	}
	p.recordMonitorMatches(ctx, tally)
}

// logDetectionRetry accounts for a detection batch failure the caller is about to nack. A not-yet-materialized subject or flow
// process (rulesapi.ErrProcessNotYetMaterialized) is an expected, transient ordering race between concurrently processed batches
// (issue #535 intra-replica workers, ADR-0011 cross-replica claimers). Under any sustained materialization-miss condition (a replica
// behind on graph materialization, an agent dropping fork/exec, a ClickHouse re-seed) the same batch re-nacks on every poll tick, so
// warn-logging it per retry floods the logs and the OTLP export (issue #631, observed ~130 WARN/min from a single host). Bound that:
// count the retry on the edr.detection.materialization_retries counter and log it at DEBUG so it stays visible under a debug log level
// without polluting normal operation. The count is taken here, at detection, not gated on the caller's subsequent Nack succeeding: a
// deferred batch is retried either way (the immediate nack, or a claim-lease-expiry re-offer if that nack fails), so the counter
// measures the miss condition itself and stays honest even during a visibility-queue outage that fails the nack. A genuine
// (non-materialization) failure, e.g. an alert persistence error, keeps its per-retry WARN line because it is rare and each
// occurrence is a real problem an operator must see.
func (p *Processor) logDetectionRetry(ctx context.Context, err error) {
	if errors.Is(err, rulesapi.ErrProcessNotYetMaterialized) {
		if p.metrics != nil {
			p.metrics.DetectionMaterializationRetry(ctx)
		}
		p.logger.DebugContext(ctx, "detection batch awaiting process materialization, will retry", "err", err)
		return
	}
	// A rule that deferred for some other reason (sensor_tamper waits out its recovery window before it can tell a tamper from an
	// upgrade cutover). Same DEBUG treatment so a recurring wait cannot flood the logs, but deliberately NOT counted on the
	// materialization metric: that counter is how an operator detects a replica behind on graph materialization, and adding
	// unrelated waits to it would make it report a problem that is not happening.
	if errors.Is(err, rulesapi.ErrRetryBatch) {
		p.logger.DebugContext(ctx, "detection batch not yet decidable, will retry", "err", err)
		return
	}
	p.logger.WarnContext(ctx, "detection failure, will retry batch", "err", err)
}

// reportSetAside surfaces events the queue withdrew from processing after repeated failure.
//
// This is the whole visibility half of issue #836. Until now a host whose batch failed the same way every time was
// indistinguishable from a quiet host: the retries were silent, the backlog gauge did not separate them, and the only symptom was
// an absence of detections nobody was watching for. So the counter carries host_id, because "which host stopped contributing" is
// the question, and the log names the host and the stage that failed, because the counter says it happened and not what to look at.
//
// Logged at ERROR rather than WARN. Whichever stage it came from, a host has permanently stopped contributing some of its
// activity, which is not a condition to notice in aggregate later. What exactly it stopped contributing depends on the stage and
// is carried on the consequence attribute rather than stated here.
//
// zero is the overwhelmingly common case: every ordinary retryable nack passes through here.
func (p *Processor) reportSetAside(ctx context.Context, hostID string, setAside int64, stage setAsideStage) {
	if setAside <= 0 {
		return
	}
	// The message is fixed and the consequence rides on an attribute, so the line stays greppable while saying something true
	// of the stage it came from. It previously claimed a process-graph gap for both, which is false for the detection stage:
	// processHost completes the builder before evaluating, so a batch withdrawn there IS in the graph, and the claim sent an
	// operator to inspect a process tree that was intact.
	p.logger.ErrorContext(ctx, "queued events set aside after repeated failure",
		"host_id", hostID, "events", setAside, "stage", stage.name, "consequence", stage.consequence)
	if p.metrics != nil {
		p.metrics.EventsSetAside(ctx, hostID, setAside)
	}
}

// reportLostClaim says when a batch was returned to the queue by an attempt that no longer owned it.
//
// The ack path has reported this since issue #817 and its own comment calls it the first visibility anyone has that leases are
// being exceeded at all. Making the nack conditional on the claim too (issue #840) created a second way to lose one, and without
// this it would be the silent way: a superseded attempt withdraws nothing, which is the same count a held batch gets when no
// event reached its bounds.
//
// WARN rather than ERROR, matching the ack path. Nothing is lost when this happens: the attempt that holds the claim carries on,
// and everything this attempt did before here is idempotent.
func (p *Processor) reportLostClaim(ctx context.Context, nackErr error, held bool, hostID string, events int) {
	// A failed nack reports held=false because it never got as far as establishing ownership, so it is not evidence that this
	// attempt lost its claim. Warning on it would put "another attempt owns this batch" beside a queue outage that has already
	// been logged, and send an operator looking for a lease overrun that did not happen (review caught it).
	if nackErr != nil || held {
		return
	}
	p.logger.WarnContext(ctx, "lost the claim before returning the batch; another attempt owns it",
		"host_id", hostID, "events", events)
}

// setAsideStage is the pipeline stage a withdrawal happened at, together with what it cost an operator.
//
// The consequence is carried ON the value rather than looked up from it, which is the second thing review corrected here. A named
// string type was the first attempt and does not do the job the call sites need: Go assigns an untyped literal to one happily, so
// a misspelling compiles and a lookup keyed on it then reports every value that is not the builder as detection. Pairing the two
// removes the lookup, so there is no mapping left to get wrong and nothing to keep in step.
type setAsideStage struct {
	// name is the stage as it appears on the record's stage attribute.
	name string
	// consequence is what the host lost, phrased as what an operator should go and check.
	consequence string
}

var (
	// stageBuilder is the process-graph materialisation.
	//
	// "MAY have a gap" rather than "has a gap", and review was right that the definite form is reachable. Attempts accumulate on
	// the queue row whichever stage nacked it, so a batch can fold successfully, fail at detection, and then be withdrawn on a
	// later attempt whose fold is the thing that failed. Those events are in the graph, put there by the earlier attempt, and
	// nothing on the row records that they got that far. Claiming a gap there would be this change's own defect, one attempt
	// further back.
	stageBuilder = setAsideStage{
		name:        "builder",
		consequence: "this host may have a gap in its process graph",
	}

	// stageDetection is detection: rule evaluation and the persistence of what it finds, running on an already-materialised batch.
	//
	// Names the OUTCOME rather than the step that failed. Exactly two things reach this withdrawal, and "a rule failed" is neither:
	// evaluateRule logs a rule's own non-retryable error and returns nil, so per-rule isolation keeps it inside the engine. What
	// does leave is an alert-persistence error, returned from inside routeFinding's loop so the batch aborts at the finding it
	// happened on and the rules after it never run; or a retryable miss that ran out of attempts, where every rule did run.
	// Naming rule evaluation would be false for the first, and would send a responder to rule execution while the failure was in
	// alert storage.
	//
	// "may be missing" rather than "are missing", because alerts written before a persistence failure stay durable. Overstating
	// the loss sends someone hunting for alerts that are already there.
	stageDetection = setAsideStage{
		name:        "detection",
		consequence: "detection did not complete for these events, so alerts they would have raised may be missing",
	}
)

// hostOf returns the host a claimed batch belongs to. The processor claims per host, so every event in the batch carries the same
// one; an empty batch never reaches a nack.
func hostOf(events []visibilityapi.Event) string {
	if len(events) == 0 {
		return ""
	}
	return events[0].HostID
}
