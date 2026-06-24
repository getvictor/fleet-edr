package tracing

import (
	"context"
	"log/slog"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
)

// settingsPollInterval is how often each replica re-reads trace_sampler_settings. 60s matches industry defaults for feature-flag-style
// runtime config: an operator's change lands across the fleet within a minute, and the per-replica single-row read is negligible.
const settingsPollInterval = 60 * time.Second

// settingsReadTimeout bounds a single settings read so a stalled DB connection cannot park the poll goroutine indefinitely (which would
// freeze runtime sampler updates until process shutdown). Well above a healthy single-row read; the next tick retries on timeout.
const settingsReadTimeout = 5 * time.Second

// pollTracer instruments the poll loop. When OTLP export is off the global provider returns a no-op tracer, so this costs nothing.
var pollTracer = otel.Tracer("github.com/fleetdm/edr/internal/observability/tracing")

// StartSettingsPoller runs the polling loop until ctx is cancelled. It does one immediate read at startup so the sampler picks up the
// row's current values without waiting a full interval, then re-reads on each tick and applies only when something changed. If a read
// fails, the sampler keeps its previously applied values (its compile-time defaults on the first read) and the next tick retries.
//
// Intended to run as `go StartSettingsPoller(ctx, sampler, reader, logger)`; it returns when ctx is cancelled.
func StartSettingsPoller(ctx context.Context, sampler *RouteTierSampler, reader SettingsReader, logger *slog.Logger) {
	if logger == nil {
		logger = slog.Default()
	}
	last := applyOnce(ctx, sampler, nil, reader, logger)

	ticker := time.NewTicker(settingsPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			last = applyOnce(ctx, sampler, last, reader, logger)
		}
	}
}

// applyOnce reads the settings once and applies them to the sampler when they differ from last. It returns the settings to compare
// against next tick: the freshly read value on success, or last unchanged on a read error or a no-op (so a transient DB blip never
// resets the sampler). Extracted from the loop so the change-detection logic is unit-testable without waiting on the ticker.
func applyOnce(ctx context.Context, sampler *RouteTierSampler, last *Settings, reader SettingsReader, logger *slog.Logger) *Settings {
	spanCtx, span := pollTracer.Start(ctx, "tracing.poll_settings",
		trace.WithNewRoot(),
		trace.WithSpanKind(trace.SpanKindInternal),
	)
	defer span.End()

	// Bound each read so one stalled DB query can't park this goroutine forever and freeze runtime sampler updates.
	readCtx, cancel := context.WithTimeout(spanCtx, settingsReadTimeout)
	defer cancel()
	got, err := reader.GetTraceSamplerSettings(readCtx)
	if err != nil {
		logger.ErrorContext(spanCtx, "trace sampler settings poll failed", "err", err)
		return last
	}
	if last != nil &&
		got.HighVolumeRatio == last.HighVolumeRatio &&
		got.StandardRatio == last.StandardRatio &&
		got.ForceFull == last.ForceFull {
		return last
	}
	sampler.Apply(got.HighVolumeRatio, got.StandardRatio, got.ForceFull)
	logger.InfoContext(spanCtx, "trace sampler settings applied",
		"high_volume_ratio", got.HighVolumeRatio,
		"standard_ratio", got.StandardRatio,
		"force_full", got.ForceFull,
	)
	return got
}
