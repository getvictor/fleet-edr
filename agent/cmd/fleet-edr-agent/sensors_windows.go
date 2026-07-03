//go:build windows

package main

import (
	"context"

	"github.com/fleetdm/edr/agent/health"
	"github.com/fleetdm/edr/agent/receiver"
	"github.com/fleetdm/edr/agent/wintel"
)

// startTelemetrySensors starts the Windows telemetry sensor: one ETW Kernel-Process consumer driven through the shared receiver.Loop
// (reconnect/backoff/heartbeat + health). The loop's connectorFactory builds a fresh wintel.Sensor per connect, mirroring how the macOS
// loops build a fresh XPC receiver. The health component is registered before the loop starts so the first status check-in already
// reports the sensor state (issue #359).
func startTelemetrySensors(ctx context.Context, d telemetryDeps) {
	d.health.Register(health.ComponentWindowsETWSensor, "Windows ETW sensor")
	go startReceiverLoop(ctx, receiverLoopParams{
		logger: d.logger,
		// serviceLabel is only a log/heartbeat label on Windows (no Mach service); wintel.SensorLabel is the single source of truth so
		// the loop's "service" matches the sensor's drop-warning "service".
		serviceLabel: wintel.SensorLabel,
		enqueue:      d.enqueue,
		pt:           d.pidTable,
		updateTable:  true,
		health:       d.health,
		component:    health.ComponentWindowsETWSensor,
		connectorFactory: func() receiver.Connector {
			return wintel.New(d.hostID, receiverEventBuffer, d.logger)
		},
	})
}
