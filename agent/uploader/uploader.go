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

// Config holds uploader settings.
type Config struct {
	// ServerURL is the base URL of the ingestion server (e.g. "https://edr.example.com").
	ServerURL string

	// APIKey is the static API key for authentication.
	APIKey string

	// BatchSize is the maximum number of events per upload.
	BatchSize int

	// Interval is the time between upload attempts.
	Interval time.Duration

	// MaxRetries is the maximum number of retries per batch on failure.
	MaxRetries int
}

// DefaultConfig returns sensible defaults.
func DefaultConfig() Config {
	return Config{
		BatchSize:  100,
		Interval:   time.Second,
		MaxRetries: 5,
	}
}

// Uploader reads from a Queue and uploads to the ingestion server.
type Uploader struct {
	queue  *queue.Queue
	client *http.Client
	cfg    Config
	logger *slog.Logger
}

// New creates an Uploader. The http.Client should already be wrapped with otelhttp.NewTransport
// if the caller wants OTel propagation; callers that pass nil get a vanilla client with a 30s
// timeout and no instrumentation.
func New(q *queue.Queue, cfg Config, client *http.Client, logger *slog.Logger) *Uploader {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	if logger == nil {
		logger = slog.Default()
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
			u.drainOnce(ctx)
			return ctx.Err()
		case <-ticker.C:
			u.drainOnce(ctx)
		}
	}
}

// Drain attempts one more upload cycle without waiting for the next tick. Useful during shutdown.
func (u *Uploader) Drain(ctx context.Context) {
	u.drainOnce(ctx)
}

func (u *Uploader) drainOnce(ctx context.Context) {
	batch, err := u.queue.DequeueBatch(ctx, u.cfg.BatchSize)
	if err != nil {
		u.logger.ErrorContext(ctx, "uploader dequeue", "err", err)
		return
	}
	if len(batch) == 0 {
		return
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
		return
	}

	if err := u.uploadWithRetry(ctx, body); err != nil {
		u.logger.ErrorContext(ctx, "uploader upload failed", "err", err, "batch_size", len(batch))
		return
	}

	if err := u.queue.MarkUploaded(ctx, ids); err != nil {
		u.logger.ErrorContext(ctx, "uploader mark uploaded", "err", err)
	}
}

func (u *Uploader) uploadWithRetry(ctx context.Context, body []byte) error {
	url := u.cfg.ServerURL + "/api/v1/events"

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
	req.Header.Set("Authorization", "Bearer "+u.cfg.APIKey)

	resp, err := u.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}

	if resp.StatusCode >= 400 && resp.StatusCode < 500 {
		return &clientError{statusCode: resp.StatusCode}
	}

	return fmt.Errorf("server returned %d", resp.StatusCode)
}
