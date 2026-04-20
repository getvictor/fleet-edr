// Package bootstrap wires the one-time daemon prelude that every fleet-edr Go
// binary needs: load config from env, install a signal-cancel context, initialise
// OTel, initialise the structured logger, and hand back a deferred flush.
//
// Each daemon's main() drops from ~40 lines of identical setup to a handful of
// calls, which also eliminates the primary source of cross-binary duplication
// that SonarQube was flagging on the refactor PR.
package bootstrap

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/fleetdm/edr/server/config"
	"github.com/fleetdm/edr/server/logging"
	"github.com/fleetdm/edr/server/observability"
)

// Env is the bundle of ready-to-use primitives returned by Init.
type Env struct {
	// Ctx is cancelled when the process receives SIGINT/SIGTERM.
	Ctx context.Context
	// Cancel releases the signal.NotifyContext. Safe to call multiple times.
	Cancel context.CancelFunc
	// Config is the validated env configuration.
	Config *config.Config
	// Logger is installed as slog.Default() as a side effect of Init.
	Logger *slog.Logger
	// FlushOTel flushes buffered OTel telemetry. Callers defer this immediately
	// after Init so any later startup failure still gets drained to the collector.
	FlushOTel func()
}

// Options identify the daemon to observability (service.name / service.version).
type Options struct {
	ServiceName    string
	ServiceVersion string
}

// Init runs the daemon prelude. On any error the partial state is torn down
// before returning so the caller only has to check err. The caller is
// responsible for calling env.Cancel (on clean exit) and env.FlushOTel (on every
// exit path, ideally via defer immediately after Init returns).
func Init(opts Options) (*Env, error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, err
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)

	shutdownOTel, err := observability.Init(ctx, observability.Options{
		ServiceName:    opts.ServiceName,
		ServiceVersion: opts.ServiceVersion,
	})
	if err != nil {
		cancel()
		return nil, err
	}

	logger, err := logging.New(os.Stderr, logging.Options{
		Level:               cfg.LogLevel,
		Format:              cfg.LogFormat,
		InstrumentationName: opts.ServiceName,
	})
	if err != nil {
		// Best-effort OTel flush before we bail — the partial OTLP state would
		// otherwise leak a pending batch.
		flushWithTimeout(shutdownOTel)
		cancel()
		return nil, err
	}
	slog.SetDefault(logger)

	flush := func() { flushWithTimeout(shutdownOTel) }
	return &Env{
		Ctx:       ctx,
		Cancel:    cancel,
		Config:    cfg,
		Logger:    logger,
		FlushOTel: flush,
	}, nil
}

// flushWithTimeout caps OTel flush at 5s so a dead collector doesn't stall the
// shutdown path.
func flushWithTimeout(shutdown func(context.Context) error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := shutdown(ctx); err != nil {
		slog.Default().WarnContext(ctx, "otel shutdown", "err", err)
	}
}
