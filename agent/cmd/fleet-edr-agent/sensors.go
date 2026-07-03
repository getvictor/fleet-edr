package main

import (
	"context"
	"log/slog"

	"github.com/fleetdm/edr/agent/config"
	"github.com/fleetdm/edr/agent/health"
	"github.com/fleetdm/edr/agent/proctable"
	"github.com/fleetdm/edr/agent/receiver"
)

// telemetryDeps bundles what a platform's telemetry sensor(s) need to start. It is shared by the platform-specific
// startTelemetrySensors implementations (sensors_notwindows.go / sensors_windows.go).
type telemetryDeps struct {
	logger        *slog.Logger
	cfg           *config.Config
	enqueue       func(context.Context, []byte) error
	pidTable      *proctable.Table
	health        *health.Registry
	esfDispatcher *receiver.Dispatcher
	hostID        string
}
