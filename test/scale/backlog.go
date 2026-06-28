package scale

import (
	"context"
	"database/sql"
	"fmt"
	"slices"
	"sync"
	"time"

	_ "github.com/go-sql-driver/mysql" // MySQL driver for the optional server-backlog poll; only used when --backlog-dsn is set.
)

// defaultBacklogPollInterval is the cadence at which the optional server-backlog sampler polls the MySQL event_queue depth. Five
// seconds is frequent enough to catch a backlog that builds over a multi-minute lane without adding meaningful query load.
const defaultBacklogPollInterval = 5 * time.Second

// backlogQueryTimeout bounds a single COUNT so a stalled DB can't wedge the sampler goroutine past one poll interval.
const backlogQueryTimeout = 5 * time.Second

// backlogQuery counts not-yet-acknowledged rows in the work queue: the server-side processing backlog (waiting + in-flight). It is the
// same predicate eventlog.Store.CountPending uses to back the processor-backlog gauge, run here from the load driver's vantage so the
// long-form lane can gate on it without the server exposing a new endpoint.
const backlogQuery = "SELECT COUNT(*) FROM event_queue WHERE processed != 1"

// backlogSampler polls the server-side event_queue depth on an interval for the life of a run. It is started only when an operator
// passes --backlog-dsn (the per-PR smoke and the default baseline run never open a DB connection), matching the README's stance that
// DB-side metrics are an opt-in operator concern during a deliberate scale run.
//
// Why poll MySQL directly rather than scrape the OTel gauge: the driver is a black-box HTTP client with no metrics scrape path, and
// the backlog is not exposed over HTTP. A read-only COUNT against the operator-supplied DSN is the lightest honest signal. The poll is
// best-effort: a transient query error drops one sample rather than failing the run, the same soft-signal discipline the SigNoz
// cross-check uses.
type backlogSampler struct {
	db   *sql.DB
	done chan struct{}

	mu      sync.Mutex
	samples []int64
}

// startBacklogSampler opens the DSN, runs the backlog query once to prove it works, and launches the poll goroutine bound to ctx. It
// returns an error if the query fails so a misconfigured DSN fails the run loudly at startup rather than silently recording zero
// samples (which would bypass the PassMaxServerBacklog gate).
func startBacklogSampler(ctx context.Context, dsn string, interval time.Duration) (*backlogSampler, error) {
	if interval <= 0 {
		interval = defaultBacklogPollInterval
	}
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, err
	}
	// The sampler is a single goroutine issuing serial queries, so one connection is all it needs; cap the pool to match.
	db.SetMaxOpenConns(1)
	// Fail closed: run the backlog query once at startup rather than a bare Ping. A DSN can ping successfully yet be unusable for the
	// poll (wrong schema, no SELECT on event_queue), which would otherwise drop every poll error and leave the run with zero samples,
	// silently bypassing the PassMaxServerBacklog gate (Copilot/Gemini/CodeRabbit #536). The pre-flight query surfaces that at startup.
	var probe int64
	if err := db.QueryRowContext(ctx, backlogQuery).Scan(&probe); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("pre-flight backlog query: %w", err)
	}
	s := &backlogSampler{db: db, done: make(chan struct{})}
	go func() {
		defer close(s.done)
		t := time.NewTicker(interval)
		defer t.Stop()
		s.sampleOnce(ctx) // one immediate sample so a short lane still records a baseline depth.
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s.sampleOnce(ctx)
			}
		}
	}()
	return s, nil
}

// sampleOnce records one backlog reading. A failed query (transient DB hiccup, ctx cancellation at the run boundary) is dropped, not
// fatal: one missing sample never changes a percentile materially, whereas aborting the run on a blip would flake the lane.
func (s *backlogSampler) sampleOnce(ctx context.Context) {
	qctx, cancel := context.WithTimeout(ctx, backlogQueryTimeout)
	defer cancel()
	var n int64
	if err := s.db.QueryRowContext(qctx, backlogQuery).Scan(&n); err != nil {
		return
	}
	s.mu.Lock()
	s.samples = append(s.samples, n)
	s.mu.Unlock()
}

// stop blocks until the poll goroutine has exited (ctx cancelled at the run boundary) and closes the DB handle. Call it before reading
// snapshot() so the sample set is final.
func (s *backlogSampler) stop() {
	<-s.done
	_ = s.db.Close()
}

// snapshot returns a copy of the collected depths.
func (s *backlogSampler) snapshot() []int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]int64(nil), s.samples...)
}

// aggregateServerBacklog folds the sampled depths into the report and applies the optional max-backlog gate. It is pure over
// (samples, opts) so the gate logic is unit-testable without a DB. It only ever flips Pass to false (never resets it to true), so it
// composes after aggregate()'s ingest gates: a run can fail on ingest p99 AND backlog independently.
func aggregateServerBacklog(rep *Report, samples []int64, opts Options) {
	rep.PassMaxServerBacklog = opts.PassMaxServerBacklog
	rep.ServerBacklogSamples = len(samples)
	if len(samples) == 0 {
		return
	}
	sorted := append([]int64(nil), samples...)
	slices.Sort(sorted)
	rep.ServerBacklogP50 = depthPercentile(sorted, percentileP50)
	rep.ServerBacklogP95 = depthPercentile(sorted, percentileP95)
	rep.ServerBacklogP99 = depthPercentile(sorted, percentileP99)
	rep.ServerBacklogMax = sorted[len(sorted)-1]
	if opts.PassMaxServerBacklog > 0 && rep.ServerBacklogMax > opts.PassMaxServerBacklog {
		rep.Pass = false
		rep.FailReasons = append(rep.FailReasons,
			fmt.Sprintf("server_backlog_max %d exceeds budget %d", rep.ServerBacklogMax, opts.PassMaxServerBacklog))
	}
}
