package tracing

import (
	"context"
	"time"
)

// Settings is the runtime-tunable head-sampling configuration. It lives in the trace_sampler_settings singleton row and is polled by
// each replica so an operator can adjust sampling without a restart. The db tags let the identity store scan a row straight into it.
type Settings struct {
	HighVolumeRatio float64   `json:"high_volume_ratio" db:"high_volume_ratio"`
	StandardRatio   float64   `json:"standard_ratio" db:"standard_ratio"`
	ForceFull       bool      `json:"force_full" db:"force_full"`
	UpdatedAt       time.Time `json:"updated_at,omitzero" db:"updated_at"`
}

// SettingsReader is the minimal store surface StartSettingsPoller needs. It is implemented by the identity context's
// trace-sampler-settings store and injected at wiring time, so this package carries no persistence or bounded-context dependency
// (the poller depends on the interface; cmd/main injects the implementation).
type SettingsReader interface {
	GetTraceSamplerSettings(ctx context.Context) (*Settings, error)
}
