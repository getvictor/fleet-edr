// Package uploader reads event batches from the SQLite queue and uploads them
// to the cloud ingestion server.
package uploader

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"time"

	"github.com/fleetdm/edr/agent/queue"
)

const (
	// defaultBatchSize is the per-batch dequeue cap.
	defaultBatchSize = 100

	// maxBatchesPerTick bounds the catch-up burst within a single tick. When the queue holds a backlog (e.g. after an
	// event storm), a fixed one-batch-per-tick loop drains at only BatchSize/Interval events/sec and can take many
	// minutes to catch up, pushing detection latency well past SLA because fresh events sit behind the backlog in the
	// FIFO queue. Draining back-to-back while batches come back full lets the uploader run at server-limited speed; the
	// cap keeps a deep backlog from starving shutdown or monopolising a degraded link.
	maxBatchesPerTick = 50

	// defaultMaxRetries is the per-batch retry cap before the uploader gives
	// up and falls through to the next drain tick.
	defaultMaxRetries = 5

	// defaultClientErrorQuarantineThreshold caps the number of consecutive drain ticks a row's batch may return a non-401 4xx
	// before the row is quarantined (uploaded=1, removed from the dequeue set, audit log emitted). 10 matches the spec's
	// "after the configured maximum retry budget is exhausted" clause and gives operators ~10 seconds at the default tick
	// rate to roll back a bad server change before client events start dropping.
	defaultClientErrorQuarantineThreshold = 10

	// defaultClientTimeout is the per-request HTTP timeout when the caller
	// does not pass an *http.Client.
	defaultClientTimeout = 30 * time.Second

	// shutdownDrainTimeout bounds the final drain attempt Run runs when its caller cancels the context. The parent ctx is already dead
	// at that point, so DequeueBatch + the HTTP POST need a fresh context to make progress; this constant prevents a hung server from
	// blocking Run's return indefinitely. 10s is enough for one upload round-trip on a degraded network.
	shutdownDrainTimeout = 10 * time.Second
)

// Config holds uploader settings.
type Config struct {
	// ServerURL is the base URL of the ingestion server (e.g. "https://edr.example.com").
	ServerURL string

	// TokenFn returns the current bearer token at request time. Typically backed by the
	// enrollment package's TokenProvider. Nil means "send no Authorization header" (tests).
	TokenFn func() string

	// OnAuthFail is called when the server returns HTTP 401 so the agent can trigger a
	// re-enroll. Nil is allowed (tests); in production wire it to TokenProvider.OnUnauthorized.
	OnAuthFail func(ctx context.Context)

	// BatchSize is the maximum number of events per upload.
	BatchSize int

	// Interval is the time between upload attempts.
	Interval time.Duration

	// MaxRetries is the maximum number of retries per batch on failure.
	MaxRetries int

	// ClientErrorQuarantineThreshold is the count of consecutive drain ticks a row's batch returning a non-401 4xx
	// must reach before the row is marked uploaded so it stops being dequeued. 0 disables quarantine (the legacy
	// behaviour: 4xx batches stay in the queue forever and re-fail every tick). Default applied by DefaultConfig is
	// 10, which gives the server ~10 drain-ticks (~10s with the default 1s tick) to recover from a transient
	// validation glitch before the agent gives up on the events.
	ClientErrorQuarantineThreshold int
}

// DefaultConfig returns sensible defaults.
func DefaultConfig() Config {
	return Config{
		BatchSize:                      defaultBatchSize,
		Interval:                       time.Second,
		MaxRetries:                     defaultMaxRetries,
		ClientErrorQuarantineThreshold: defaultClientErrorQuarantineThreshold,
	}
}

// MetricsRecorder is the optional OTel write hook the uploader uses for per-event-dropped-too-large accounting. Nil-safe;
// agents started without observability initialised pass nil here and the calls are no-ops.
type MetricsRecorder interface {
	// EventsDroppedTooLarge is called once per dropped event after a single-event batch was rejected with HTTP 413. The
	// caller MUST have already MarkUploaded'd the row before this fires (drop is durable before the metric is recorded so
	// a crash between metric + DB write doesn't manifest as a counter rate without a matching audit log).
	EventsDroppedTooLarge(ctx context.Context, n int64)
}

// Uploader reads from a Queue and uploads to the ingestion server.
type Uploader struct {
	queue   *queue.Queue
	client  *http.Client
	cfg     Config
	logger  *slog.Logger
	metrics MetricsRecorder
}

// SetMetrics installs the OTel hook. Safe to call after New; nil clears.
func (u *Uploader) SetMetrics(m MetricsRecorder) { u.metrics = m }

// New creates an Uploader. The http.Client should already be wrapped with otelhttp.NewTransport if the caller wants OTel propagation;
// callers that pass nil get a vanilla client with a 30s timeout and no instrumentation.
//
// ClientErrorQuarantineThreshold normalisation: production wiring (agent/cmd/fleet-edr-agent/main.go) constructs
// uploader.Config via a keyed literal that doesn't mention every field; without the normalisation below the threshold
// would default to 0 and disable the #253 quarantine path entirely. A zero value is treated as "apply the documented
// default"; a NEGATIVE value remains negative and is treated as "explicitly disabled" downstream so test code can opt
// out without colliding with the zero-value default.
func New(q *queue.Queue, cfg Config, client *http.Client, logger *slog.Logger) *Uploader {
	if client == nil {
		client = &http.Client{Timeout: defaultClientTimeout}
	}
	if logger == nil {
		logger = slog.Default()
	}
	if cfg.ClientErrorQuarantineThreshold == 0 {
		cfg.ClientErrorQuarantineThreshold = defaultClientErrorQuarantineThreshold
	}
	return &Uploader{
		queue:  q,
		client: client,
		cfg:    cfg,
		logger: logger,
	}
}

// Run polls the queue and uploads events until the context is cancelled.
func (u *Uploader) Run(ctx context.Context) error {
	ticker := time.NewTicker(u.cfg.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			// Shutdown drain: the spec's "execute one more upload attempt before returning" clause requires a usable context.
			// Reusing the cancelled `ctx` here would short-circuit DequeueBatch (SQLite QueryContext rejects cancelled contexts
			// immediately). context.WithoutCancel detaches from the parent's cancellation signal while preserving its values
			// (OTel trace IDs, slog attributes), so the shutdown-drain log lines and spans still correlate with the run that
			// triggered them. The bounded timeout caps Run's exit latency: long enough for one HTTP upload round-trip on a
			// degraded network, short enough that a hung server cannot block agent shutdown indefinitely.
			drainCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownDrainTimeout)
			_ = u.drainOnce(drainCtx)
			cancel()
			return ctx.Err()
		case <-ticker.C:
			u.drainUntilCaughtUp(ctx)
		}
	}
}

// drainUntilCaughtUp drains batches back-to-back until the queue is caught up (a dequeue returns fewer than BatchSize
// rows), an error occurs (back off to the next tick), or the per-tick cap is hit. A full batch means more events are
// almost certainly waiting, so this lets the uploader catch up at server-limited speed under backlog while still idling
// at a single short batch per tick once drained.
func (u *Uploader) drainUntilCaughtUp(ctx context.Context) {
	for range maxBatchesPerTick {
		if ctx.Err() != nil {
			return
		}
		n, err := u.drainBatch(ctx)
		// n == 0 terminates on an empty queue regardless of BatchSize. BatchSize is validated positive in
		// production, but the explicit check keeps the loop from spinning maxBatchesPerTick times if it is ever
		// constructed with a misconfigured BatchSize <= 0 (where n < BatchSize would be false for an empty dequeue).
		if err != nil || n == 0 || n < u.cfg.BatchSize {
			return
		}
	}
}

// Drain attempts one more upload cycle without waiting for the next tick. Callers that need to report shutdown status (e.g. "final
// flush failed, N events still queued") can inspect the returned error. An empty queue returns nil.
func (u *Uploader) Drain(ctx context.Context) error {
	return u.drainOnce(ctx)
}

// drainOnce uploads a single batch, returning only the error. Retained as the error-only entrypoint for Drain and the
// shutdown-drain path; drainUntilCaughtUp uses drainBatch when it needs the dequeued count.
func (u *Uploader) drainOnce(ctx context.Context) error {
	_, err := u.drainBatch(ctx)
	return err
}

// drainBatch dequeues and uploads a single batch, returning the number of events dequeued so callers can tell a full
// batch (more likely waiting) from a short one (queue caught up). An empty queue returns (0, nil).
func (u *Uploader) drainBatch(ctx context.Context) (int, error) {
	batch, err := u.queue.DequeueBatch(ctx, u.cfg.BatchSize)
	if err != nil {
		u.logger.ErrorContext(ctx, "uploader dequeue", "err", err)
		return 0, err
	}
	if len(batch) == 0 {
		return 0, nil
	}
	return len(batch), u.uploadBatch(ctx, batch)
}

// uploadBatch is the per-batch send path. Marshals the in-memory events, POSTs the body, and dispatches on the
// outcome:
//
//  1. 2xx: MarkUploaded for every id in the batch, return nil.
//  2. 401 (clientError with statusCode=401): leave queued (OnAuthFail has been signalled by doUpload), return the error.
//  3. 413 (requestEntityTooLargeError) with len(batch) > 1: bisect the batch and recurse on each half. Halves that deliver are
//     marked uploaded as part of their own recursive call; halves that still 413 recurse until single-event leaves.
//  4. 413 (requestEntityTooLargeError) with len(batch) == 1: drop the event - MarkUploaded so the queue stops surfacing it, emit
//     a WARN log with the event id, and increment the events_dropped_too_large counter. Per the spec, 413 does NOT
//     consume the quarantine budget because the recovery shape differs (size signal, not "malformed event" signal).
//  5. Other 4xx: route through recordClientErrorAndAudit (the existing #253 quarantine path).
//  6. 5xx / network / timeout (the non-clientError return from uploadWithRetry after MaxRetries): logged + returned, the
//     batch stays queued for the next drain tick.
//
// Recursion depth is bounded by ceil(log2(N)) where N is the original batch size; a 10000-event batch recurses at most
// ~14 levels before reaching single-event leaves.
func (u *Uploader) uploadBatch(ctx context.Context, batch []queue.QueuedEvent) error {
	payloads := make([]json.RawMessage, len(batch))
	ids := make([]int64, len(batch))
	for i, e := range batch {
		payloads[i] = json.RawMessage(e.EventJSON)
		ids[i] = e.ID
	}

	body, err := json.Marshal(payloads)
	if err != nil {
		u.logger.ErrorContext(ctx, "uploader marshal", "err", err)
		return err
	}

	if err := u.uploadWithRetry(ctx, body); err != nil {
		return u.handleUploadErr(ctx, batch, ids, err)
	}

	if err := u.queue.MarkUploaded(ctx, ids); err != nil {
		u.logger.ErrorContext(ctx, "uploader mark uploaded", "err", err)
		return err
	}
	return nil
}

// handleUploadErr routes a non-nil uploadWithRetry return to the appropriate recovery path: 401 leaves queued, 413
// splits or drops, other 4xx records-and-audits, 5xx/network logs-and-returns. Extracted so uploadBatch stays under the
// cognitive-complexity budget (Sonar S3776).
func (u *Uploader) handleUploadErr(ctx context.Context, batch []queue.QueuedEvent, ids []int64, err error) error {
	var tooLargeErr *requestEntityTooLargeError
	if errors.As(err, &tooLargeErr) {
		return u.handleBodyTooLarge(ctx, batch)
	}

	// 401 specifically is a recoverable state: OnAuthFail has already been signalled and the batch stays in the queue for
	// the next tick to retry with a fresh token. Log at warn, not error, so operators don't see a flood of error-level
	// lines during an expected re-enroll window.
	var clientErr *clientError
	if errors.As(err, &clientErr) && clientErr.statusCode == http.StatusUnauthorized {
		u.logger.WarnContext(ctx, "uploader upload unauthorized; re-enroll in flight",
			"batch_size", len(batch))
		return err
	}
	// Non-401 4xx is a permanent client error for this batch (malformed event, schema-rejected payload, etc.). Without
	// the quarantine path, the batch would stay queued and re-fail every drain tick forever (#253).
	if errors.As(err, &clientErr) && u.cfg.ClientErrorQuarantineThreshold > 0 {
		u.recordClientErrorAndAudit(ctx, ids, clientErr.statusCode, len(batch))
	}
	// Context cancellation / deadline is an EXPECTED outcome during graceful shutdown - the shutdown drain runs against a
	// bounded WithTimeout context, and one truncated drain attempt on a degraded server is not an operator-actionable error
	// (Gemini #276). Log at warn so dashboards keyed on uploader error rate don't false-trip on every shutdown.
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		u.logger.WarnContext(ctx, "uploader upload aborted by context cancellation",
			"err", err, "batch_size", len(batch))
		return err
	}
	u.logger.ErrorContext(ctx, "uploader upload failed", "err", err, "batch_size", len(batch))
	return err
}

// handleBodyTooLarge implements the recursive split-and-retry for HTTP 413 responses. A multi-event batch is bisected and
// each half is uploadBatch'd; a single-event batch is dropped (MarkUploaded + WARN log + metric increment). The drop path is
// durable BEFORE the metric is recorded so a crash between MarkUploaded and the counter Add doesn't leave the queue and the
// counter out of step.
//
// Shutdown-aware split (Gemini #276): between the two halves we honor `ctx.Err()` so the shutdown drain (bounded by
// shutdownDrainTimeout) doesn't burn its budget POSTing the second half after the parent context already cancelled. If the
// first half succeeded but the context cancels before the second, the second-half events stay queued (uploaded=0) for the
// next agent start to pick up.
func (u *Uploader) handleBodyTooLarge(ctx context.Context, batch []queue.QueuedEvent) error {
	if len(batch) == 1 {
		return u.dropOverSizeEvent(ctx, batch[0])
	}

	mid := len(batch) / 2
	if firstErr := u.uploadBatch(ctx, batch[:mid]); firstErr != nil {
		// Fail-fast on a first-half error rather than attempting the second half (Gemini #277). The first-half failure
		// is the dominant signal across every non-413 error mode: 401 means the token is stale and the second half
		// would use the same token; a 5xx-after-retries means the server is unhappy with our request shape and the
		// second half is the same shape; a network timeout means the connection itself is degraded. For 413, the
		// first-half failure already routed back into handleBodyTooLarge via uploadBatch's recursion, so the second
		// half's behaviour is independent of the first half's outcome and we never reach here on the 413 path.
		return firstErr
	}
	if err := ctx.Err(); err != nil {
		// Parent context cancelled between halves (the shutdown drain bounded by shutdownDrainTimeout). The first half
		// already landed; the second half stays queued for the next drain tick / agent start.
		return err
	}
	return u.uploadBatch(ctx, batch[mid:])
}

// dropOverSizeEvent is the single-event 413 drop path lifted out of handleBodyTooLarge so the parent stays linear (Sonar
// S3776 cognitive-complexity budget) and the spec-required event_id extraction has one call site. The event_id is pulled
// out of EventJSON via a minimal Unmarshal into a struct holding only the event_id field - if the JSON is malformed or the
// field is missing, the log line carries an empty event_id and the queue row id (event_db_id) still uniquely identifies the
// event for operators (Copilot #276 spec-compliance fix).
func (u *Uploader) dropOverSizeEvent(ctx context.Context, ev queue.QueuedEvent) error {
	if err := u.queue.MarkUploaded(ctx, []int64{ev.ID}); err != nil {
		u.logger.ErrorContext(ctx, "uploader mark uploaded for dropped over-size event",
			"err", err, "event_db_id", ev.ID)
		return err
	}
	var meta struct {
		EventID string `json:"event_id"`
	}
	_ = json.Unmarshal(ev.EventJSON, &meta) // best-effort; empty event_id is logged if the JSON is malformed
	u.logger.WarnContext(ctx, "uploader dropped single event that exceeds server body cap",
		"audit", "uploader.events_dropped_too_large",
		"event_id", meta.EventID,
		"event_db_id", ev.ID,
		"event_json_bytes", len(ev.EventJSON),
	)
	if u.metrics != nil {
		u.metrics.EventsDroppedTooLarge(ctx, 1)
	}
	return nil
}

// recordClientErrorAndAudit is the #253 poisoned-events bookkeeping path extracted out of drainOnce. Bumps the per-row
// client_error_count for every id in the dequeued batch; rows that cross the threshold get sealed (uploaded=1) by
// RecordClientError in the same transaction and returned for the audit-log line. The audit log fires at most once per drain
// tick (the tick that crosses the threshold for any row); subsequent ticks see uploaded=1 rows that DequeueBatch no longer
// surfaces. Extraction was driven by Sonar's S3776 budget (drainOnce was 18 vs 15 cognitive complexity).
func (u *Uploader) recordClientErrorAndAudit(ctx context.Context, ids []int64, statusCode, batchSize int) {
	quarantined, qerr := u.queue.RecordClientError(ctx, ids, u.cfg.ClientErrorQuarantineThreshold)
	if qerr != nil {
		u.logger.ErrorContext(ctx, "uploader quarantine bookkeeping failed", "err", qerr, "batch_size", batchSize)
	}
	if len(quarantined) == 0 {
		return
	}
	// One audit-class log line per drain tick that quarantines any rows. The structured fields (event_count, status_code,
	// threshold) are what a SigNoz alert dashboard groups on so operators can tell "one bad event" from "the server
	// started rejecting everything".
	u.logger.ErrorContext(ctx, "uploader quarantined events after persistent client errors",
		"audit", "uploader.events_quarantined",
		"event_count", len(quarantined),
		"status_code", statusCode,
		"threshold", u.cfg.ClientErrorQuarantineThreshold,
	)
}

func (u *Uploader) uploadWithRetry(ctx context.Context, body []byte) error {
	url := u.cfg.ServerURL + "/api/events"

	for attempt := range u.cfg.MaxRetries {
		err := u.doUpload(ctx, url, body)
		if err == nil {
			return nil
		}

		// Don't retry client errors (4xx) - only server/network errors are retryable. 413 is its own non-retryable type because
		// the caller (uploadBatch) branches into split-and-retry rather than the quarantine path; returning it from the retry
		// loop preserves the typed-error chain that errors.As inspects upstream.
		var tooLargeErr *requestEntityTooLargeError
		if errors.As(err, &tooLargeErr) {
			return tooLargeErr
		}
		var clientErr *clientError
		if errors.As(err, &clientErr) {
			return clientErr
		}

		backoff := time.Duration(math.Pow(2, float64(attempt))) * 100 * time.Millisecond
		u.logger.WarnContext(ctx, "uploader attempt failed",
			"attempt", attempt+1, "err", err, "backoff", backoff)

		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}

	return fmt.Errorf("all %d attempts failed", u.cfg.MaxRetries)
}

// clientError represents a non-retryable HTTP 4xx response other than 413.
type clientError struct {
	statusCode int
}

func (e *clientError) Error() string {
	return fmt.Sprintf("server returned %d", e.statusCode)
}

// requestEntityTooLargeError represents an HTTP 413 (Request Entity Too Large) response. The server uses this status for
// two diagnostics that share the same agent-side recovery shape - `body_too_large` (body bytes exceed the per-request
// cap) and `too_many_events` (event count exceeds MaxIngestEventsPerRequest); both route through split-and-retry. Kept
// distinct from clientError so the caller can
// route to the split-and-retry recovery path without re-inspecting statusCode, and so a future addition of another
// special-cased 4xx (e.g. 429 with Retry-After) follows the same typed-error pattern instead of growing a switch.
type requestEntityTooLargeError struct{}

func (*requestEntityTooLargeError) Error() string {
	return "server returned 413 (request entity too large)"
}

func (u *Uploader) doUpload(ctx context.Context, url string, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if u.cfg.TokenFn != nil {
		if tok := u.cfg.TokenFn(); tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
	}

	resp, err := u.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}

	if resp.StatusCode == http.StatusUnauthorized && u.cfg.OnAuthFail != nil {
		// Surface the 401 to the enrollment package so it can re-enroll. We fall through to the 4xx branch below,
		// so this fires at most once per drain tick (not per retry - clientError is non-retryable). The callback is itself
		// rate-limited, so repeated drain ticks while the token is stale are safe.
		u.cfg.OnAuthFail(ctx)
	}

	// 413 is its own typed error so uploadBatch can route to the recursive split-and-retry recovery path without re-inspecting
	// the status code. Per the spec, 413 must not consume the quarantine budget (size signal, not "malformed event" signal).
	if resp.StatusCode == http.StatusRequestEntityTooLarge {
		return &requestEntityTooLargeError{}
	}

	if resp.StatusCode >= 400 && resp.StatusCode < 500 {
		return &clientError{statusCode: resp.StatusCode}
	}

	return fmt.Errorf("server returned %d", resp.StatusCode)
}
