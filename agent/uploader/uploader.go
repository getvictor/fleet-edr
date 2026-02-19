// Package uploader reads event batches from the SQLite queue and uploads them
// to the cloud ingestion server.
package uploader

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"time"

	"github.com/fleetdm/edr/agent/queue"
)

// Config holds uploader settings.
type Config struct {
	// ServerURL is the base URL of the ingestion server (e.g. "http://localhost:8080").
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
}

// New creates an Uploader.
func New(q *queue.Queue, cfg Config) *Uploader {
	return &Uploader{
		queue:  q,
		client: &http.Client{Timeout: 30 * time.Second},
		cfg:    cfg,
	}
}

// Run polls the queue and uploads events until the context is cancelled.
func (u *Uploader) Run(ctx context.Context) error {
	ticker := time.NewTicker(u.cfg.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			// Drain remaining events on shutdown.
			u.drainOnce(ctx)
			return ctx.Err()
		case <-ticker.C:
			u.drainOnce(ctx)
		}
	}
}

// drainOnce uploads one batch from the queue.
func (u *Uploader) drainOnce(ctx context.Context) {
	batch, err := u.queue.DequeueBatch(u.cfg.BatchSize)
	if err != nil {
		log.Printf("uploader: dequeue error: %v", err)
		return
	}
	if len(batch) == 0 {
		return
	}

	// Build JSON array of raw event payloads.
	payloads := make([]json.RawMessage, len(batch))
	ids := make([]int64, len(batch))
	for i, e := range batch {
		payloads[i] = json.RawMessage(e.EventJSON)
		ids[i] = e.ID
	}

	body, err := json.Marshal(payloads)
	if err != nil {
		log.Printf("uploader: marshal error: %v", err)
		return
	}

	if err := u.uploadWithRetry(ctx, body); err != nil {
		log.Printf("uploader: upload failed after retries: %v", err)
		return
	}

	if err := u.queue.MarkUploaded(ids); err != nil {
		log.Printf("uploader: mark uploaded error: %v", err)
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
		if clientErr, ok := err.(*clientError); ok {
			return clientErr
		}

		backoff := time.Duration(math.Pow(2, float64(attempt))) * 100 * time.Millisecond
		log.Printf("uploader: attempt %d failed: %v, retrying in %v", attempt+1, err, backoff)

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
	if u.cfg.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+u.cfg.APIKey)
	}

	resp, err := u.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}

	if resp.StatusCode >= 400 && resp.StatusCode < 500 {
		return &clientError{statusCode: resp.StatusCode}
	}

	return fmt.Errorf("server returned %d", resp.StatusCode)
}
