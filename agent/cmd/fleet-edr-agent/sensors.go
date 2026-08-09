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
	// hostID is the value at sensor-start time. Fine for the Windows ETW sensor, which stamps it once into a connector.
	hostID string
	// hostIDFn reads the CURRENT host id. Anything that stamps an id onto an event must use this rather than hostID: a
	// re-enrollment (which OnUnauthorized can trigger at any time) replaces the agent's identity, and an event carrying
	// the superseded value is attributed to a host that may no longer exist. agent/reconcile takes the same provider
	// function for the same reason.
	hostIDFn func() string
}
