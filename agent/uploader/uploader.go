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
	// defaultBatchSize is the per-tick upload cap.
	defaultBatchSize = 100

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

// Uploader reads from a Queue and uploads to the ingestion server.
type Uploader struct {
	queue  *queue.Queue
	client *http.Client
	cfg    Config
	logger *slog.Logger
}

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
			_ = u.drainOnce(ctx)
		}
	}
}

// Drain attempts one more upload cycle without waiting for the next tick. Callers that need to report shutdown status (e.g. "final
// flush failed, N events still queued") can inspect the returned error. An empty queue returns nil.
func (u *Uploader) Drain(ctx context.Context) error {
	return u.drainOnce(ctx)
}

func (u *Uploader) drainOnce(ctx context.Context) error {
	batch, err := u.queue.DequeueBatch(ctx, u.cfg.BatchSize)
	if err != nil {
		u.logger.ErrorContext(ctx, "uploader dequeue", "err", err)
		return err
	}
	if len(batch) == 0 {
		return nil
	}

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
		// 401 specifically is a recoverable state: OnAuthFail has already been signalled and the batch stays in the queue for
		// the next tick to retry with a fresh token. Log at warn, not error, so operators don't see a flood of error-level
		// lines during an expected re-enroll window.
		var clientErr *clientError
		if errors.As(err, &clientErr) && clientErr.statusCode == http.StatusUnauthorized {
			u.logger.WarnContext(ctx, "uploader upload unauthorized; re-enroll in flight",
				"batch_size", len(batch))
			return err
		}
		// Non-401 4xx is a permanent client error for this batch (malformed event, schema-rejected payload, etc.). Without the
		// quarantine path, the batch would stay queued and re-fail every drain tick forever (#253). recordClientErrorAndAudit
		// extracts the bump + audit-log path so drainOnce stays under the cognitive-complexity budget Sonar enforces.
		if errors.As(err, &clientErr) && u.cfg.ClientErrorQuarantineThreshold > 0 {
			u.recordClientErrorAndAudit(ctx, ids, clientErr.statusCode, len(batch))
		}
		u.logger.ErrorContext(ctx, "uploader upload failed", "err", err, "batch_size", len(batch))
		return err
	}

	if err := u.queue.MarkUploaded(ctx, ids); err != nil {
		u.logger.ErrorContext(ctx, "uploader mark uploaded", "err", err)
		return err
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

		// Don't retry client errors (4xx) — only server/network errors are retryable.
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

// clientError represents a non-retryable HTTP 4xx response.
type clientError struct {
	statusCode int
}

func (e *clientError) Error() string {
	return fmt.Sprintf("server returned %d", e.statusCode)
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
		// so this fires at most once per drain tick (not per retry — clientError is non-retryable). The callback is itself
		// rate-limited, so repeated drain ticks while the token is stale are safe.
		u.cfg.OnAuthFail(ctx)
	}

	if resp.StatusCode >= 400 && resp.StatusCode < 500 {
		return &clientError{statusCode: resp.StatusCode}
	}

	return fmt.Errorf("server returned %d", resp.StatusCode)
}
