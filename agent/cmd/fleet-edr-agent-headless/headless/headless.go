//go:build !darwin || !cgo

// Package headless is the development + test build of the agent's Go core that runs on linux (or on darwin with CGO disabled) without
// the macOS XPC system extension. It wires the same enrollment + queue + uploader pipeline as the production agent, substitutes the
// non-darwin stub receiver for the XPC bridge, and exposes a local unix-socket control plane so tests can inject events directly into
// the receiver. The fleet-edr-agent-headless binary (main.go alongside this package) is a thin entrypoint that calls Run; the L3
// integration tests at test/integration/agentserver import Run directly. See docs/testing-strategy.md for the M2 + M4 design.
package headless

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/fleetdm/edr/agent/enrollment"
	"github.com/fleetdm/edr/agent/queue"
	"github.com/fleetdm/edr/agent/receiver"
	"github.com/fleetdm/edr/agent/uploader"
)

const (
	// defaultEventBuffer sizes the stub receiver's events channel. The headless binary is designed for test scenarios feeding tens to
	// hundreds of events per second; a 1024-event buffer gives ample slack between Inject and the queue-pump goroutine.
	defaultEventBuffer = 1024

	// defaultBatchSize and defaultUploadInterval match production agent defaults for scenarios that exercise realistic batching.
	defaultBatchSize      = 100
	defaultUploadInterval = 1 * time.Second

	// uploaderMaxRetries mirrors the production agent's upload-retry cap. Tests that legitimately need a different cap can override
	// via Options.UploaderMaxRetries.
	uploaderMaxRetries = 3

	// drainTimeout caps the final upload attempt after ctx is cancelled. Long enough for a real upload to complete; short enough that a
	// hung server doesn't stall test teardown indefinitely.
	drainTimeout = 5 * time.Second
)

// Options is the headless binary's runtime configuration. main builds Options from CLI flags + env; tests construct Options directly.
type Options struct {
	// ServerURL is the base URL of the EDR ingestion server.
	ServerURL string

	// HostID is the host identifier this agent claims. On linux there is no IOPlatformUUID to derive, so callers must supply one.
	HostID string

	// QueuePath is the SQLite WAL queue database path. Test code should use t.TempDir to scope per-test.
	QueuePath string

	// SocketPath is the unix-socket path for the control plane. Empty means do not start the control plane (allowed for non-test runs
	// where events would arrive through some other channel, though in M2 there is no such channel).
	SocketPath string

	// TokenProvider yields the current bearer token for the uploader. Production wires the enrollment package's provider; tests pass
	// a fixed-token stub. Required.
	TokenProvider enrollment.TokenProvider

	// BatchSize, UploadInterval, UploaderMaxRetries override the defaults at the top of this file. Zero values fall back to defaults.
	BatchSize          int
	UploadInterval     time.Duration
	UploaderMaxRetries int

	// HTTPClient is the http.Client the uploader uses to talk to ServerURL. Nil means uploader.New constructs a default client. Tests
	// typically pass a client wrapping httptest.Server's transport so the upload lands locally without TLS setup.
	HTTPClient *http.Client

	// Logger is the slog logger. Nil means slog.Default.
	Logger *slog.Logger
}

// validate fills in defaults and rejects obviously invalid combinations. The error messages name the missing field so a test failure or
// operator misconfiguration is immediately actionable.
func (o *Options) validate() error {
	if o.ServerURL == "" {
		return errors.New("headless: Options.ServerURL is required")
	}
	if o.HostID == "" {
		return errors.New("headless: Options.HostID is required (no IOPlatformUUID outside darwin)")
	}
	if o.QueuePath == "" {
		return errors.New("headless: Options.QueuePath is required")
	}
	if o.TokenProvider == nil {
		return errors.New("headless: Options.TokenProvider is required")
	}
	if o.BatchSize == 0 {
		o.BatchSize = defaultBatchSize
	}
	if o.UploadInterval == 0 {
		o.UploadInterval = defaultUploadInterval
	}
	if o.UploaderMaxRetries == 0 {
		o.UploaderMaxRetries = uploaderMaxRetries
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	return nil
}

// counters track control-plane observable state. Embedded in the running agent so the GET /state handler can read them without holding
// any locks (atomic loads).
type counters struct {
	eventsInjected   atomic.Int64
	injectErrors     atomic.Int64
	lastInjectAtUnix atomic.Int64
}

// Run wires the headless agent and blocks until ctx is cancelled. Returns the first non-nil error from setup; once setup succeeds and
// the goroutines spin up, errors from those goroutines are logged but do not propagate (the production agent's behaviour is the same).
//
// Lifecycle on ctx cancel: stops the control plane, drains any remaining queue contents one last time (bounded by drainTimeout), closes
// the queue, returns nil.
func Run(ctx context.Context, opts Options) error {
	if err := opts.validate(); err != nil {
		return err
	}
	logger := opts.Logger.With("component", "headless-agent", "host_id", opts.HostID)
	receiver.SetLogger(logger)

	q, err := queue.Open(ctx, opts.QueuePath, queue.Options{Logger: logger})
	if err != nil {
		return fmt.Errorf("open queue at %s: %w", opts.QueuePath, err)
	}
	defer func() { _ = q.Close() }()

	up := uploader.New(q, uploader.Config{
		ServerURL:  opts.ServerURL,
		TokenFn:    opts.TokenProvider.Token,
		OnAuthFail: opts.TokenProvider.OnUnauthorized,
		BatchSize:  opts.BatchSize,
		Interval:   opts.UploadInterval,
		MaxRetries: opts.UploaderMaxRetries,
	}, opts.HTTPClient, logger)

	recv := receiver.New("headless-stub", defaultEventBuffer)
	defer recv.Disconnect()

	cnt := &counters{}

	// pumpEvents bridges the stub receiver into the queue, mirroring the production agent's pipeEvents goroutine. q.Enqueue is called
	// with the outer ctx; cancellation on shutdown propagates and Enqueue returns context.Canceled rather than blocking.
	go pumpEvents(ctx, recv, q, logger)

	// runUploader runs the uploader's main loop until ctx is done. The uploader returns nil on ctx cancellation; we log a non-nil
	// error but do not propagate (production behaviour).
	go func() {
		if err := up.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
			logger.ErrorContext(ctx, "uploader run", "err", err)
		}
	}()

	// Control plane: optional. When SocketPath is non-empty, start the server in a goroutine. Capture shutdown so we can call it
	// explicitly between ctx.Done() and drainOnShutdown (see below); also keep a deferred call as a safety net in case Run returns
	// before ctx.Done() fires. http.Server.Shutdown is idempotent so the double-call is safe.
	shutdownControlPlane := func() {}
	if opts.SocketPath != "" {
		shutdown, err := startControlPlane(ctx, opts.SocketPath, recv, q, cnt, logger)
		if err != nil {
			return fmt.Errorf("start control plane: %w", err)
		}
		shutdownControlPlane = shutdown
		defer shutdownControlPlane()
	}

	logger.InfoContext(ctx, "headless agent ready",
		"server_url", opts.ServerURL, "queue_path", opts.QueuePath, "socket_path", opts.SocketPath)

	<-ctx.Done()
	// Stop accepting new POST /event requests BEFORE the final drain. Otherwise a late injection between ctx.Done() and the
	// deferred shutdown lands in recv.events with pumpEvents already exited; the event would be silently dropped at process exit.
	shutdownControlPlane()
	drainOnShutdown(up, logger)
	return nil
}

// pumpEvents reads from the receiver's Events() channel and enqueues each event. Exits when the channel closes or ctx is done. Errors
// are logged but do not stop the pump because the queue's enforceCap path can transiently fail on a full disk; we want the agent to
// keep running and try the next event.
func pumpEvents(ctx context.Context, recv *receiver.Receiver, q *queue.Queue, logger *slog.Logger) {
	events := recv.Events()
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-events:
			if !ok {
				return
			}
			if err := q.Enqueue(ctx, ev.Data); err != nil {
				logger.WarnContext(ctx, "enqueue failed", "err", err, "event_bytes", len(ev.Data))
			}
		}
	}
}

// drainOnShutdown attempts one final upload pass after ctx has been cancelled, with a bounded timeout so a slow / dead server cannot
// hold the headless binary's exit indefinitely. The shutdown context is fresh (not the cancelled run context) so the uploader's HTTP
// call actually has time to complete.
func drainOnShutdown(up *uploader.Uploader, logger *slog.Logger) {
	shutdownCtx, cancel := context.WithTimeout(context.Background(), drainTimeout)
	defer cancel()
	if err := up.Drain(shutdownCtx); err != nil && !errors.Is(err, context.Canceled) {
		logger.WarnContext(shutdownCtx, "final drain", "err", err)
	}
}
