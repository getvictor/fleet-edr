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
type batchEvaluator interface {
	Evaluate(ctx context.Context, events []visibilityapi.Event) error
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
	logger      *slog.Logger
	interval    time.Duration
	batch       int
	concurrency int
	clamp       *concurrencyClamp
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
		if opts.ConnBudget < connsPerWorker {
			return nil, fmt.Errorf(
				"detection processor: MySQL pool of %d connection(s) cannot serve one worker; the per-host claim lock needs %d "+
					"connections per worker (one pinned by GET_LOCK, one for the claim and flush), so raise the pool to at least %d",
				opts.ConnBudget, connsPerWorker, connsPerWorker*workerPoolShareDivisor)
		}
		if affordable := max(opts.ConnBudget/(connsPerWorker*workerPoolShareDivisor), 1); concurrency > affordable {
			clamp = &concurrencyClamp{
				reason: "detection processor concurrency clamped to the connection budget",
				attrs: []any{
					"requested_concurrency", concurrency, "effective_concurrency", affordable,
					"max_open_conns", opts.ConnBudget, "conns_per_worker", connsPerWorker,
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
		buildFailed bool
	)
	claimAndBuild := func(lockedCtx context.Context) error {
		claimed, err := p.eventLog.ClaimForHost(lockedCtx, host, p.batch)
		if err != nil {
			p.logger.ErrorContext(lockedCtx, "claim events", "host_id", host, "err", err)
			return nil
		}
		if len(claimed) == 0 {
			return nil
		}
		events = claimed
		if err := p.builder.ProcessBatch(lockedCtx, claimed); err != nil {
			p.logger.WarnContext(lockedCtx, "graph builder failure, will retry batch", "err", err)
			buildFailed = true
			// Requeue inside the lock, not after it. A failed batch's rows stay in flight until the Nack lands, and releasing the
			// host first would let the next claimer take this host's LATER events and fold them ahead of these, so the retry would
			// arrive behind generations it precedes. The claim's in-flight bound makes that window harmless even if this Nack
			// fails, but closing the window is cheaper than relying on the bound to cover it.
			if nackErr := p.eventLog.Nack(lockedCtx, eventIDsOf(claimed)); nackErr != nil {
				p.logger.ErrorContext(lockedCtx, "nack events after builder failure", "err", nackErr)
			}
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
		// Already requeued inside the lock. Stop draining so a persistently failing batch cannot hot-spin.
		return 0, true
	}

	return p.evaluateAndAck(ctx, events, eventIDsOf(events)), true
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
func (p *Processor) evaluateAndAck(ctx context.Context, events []visibilityapi.Event, eventIDs []string) int {
	// Run detection rules after processes are materialized.
	if p.detection != nil {
		if err := p.detection.Evaluate(ctx, events); err != nil {
			p.logDetectionRetry(ctx, err)
			if nackErr := p.eventLog.Nack(ctx, eventIDs); nackErr != nil {
				p.logger.ErrorContext(ctx, "nack events after detection failure", "err", nackErr)
			}
			return 0
		}
	}

	if err := p.eventLog.Ack(ctx, eventIDs); err != nil {
		// The batch processed but the queue was not durably advanced (the rows stay leased until the claim lease expires).
		// Returning 0 stops the drain loop so the worker waits for the next tick rather than treating this as a full-batch
		// drain and immediately re-claiming, which would spread a transient ack outage into a tight re-processing loop.
		p.logger.ErrorContext(ctx, "ack events", "err", err)
		return 0
	}
	return len(events)
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
