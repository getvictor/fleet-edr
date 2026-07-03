//go:build !windows

package main

import (
	"context"

	"github.com/fleetdm/edr/agent/health"
	"github.com/fleetdm/edr/agent/receiver"
)

// startTelemetrySensors starts the macOS telemetry sensors: the Endpoint Security extension loop and, when enabled, the network
// extension loop. Both run through the shared receiver.Loop machinery and report their connectivity into the health registry (issue
// #359). Components are registered before the loops start so the first status check-in already reports a not-yet-activated extension,
// which is exactly the fresh-install gap that feature surfaces. On Linux (the compile-only / headless build) the XPC receiver is the
// non-darwin stub, so these loops connect to nothing; that is unchanged from before the Windows split.
func startTelemetrySensors(ctx context.Context, d telemetryDeps) {
	d.health.Register(health.ComponentEndpointSecurityExtension, "Security extension")
	if d.cfg.NetXPCService != "" {
		d.health.Register(health.ComponentNetworkExtension, "Network extension")
	}

	go startReceiverLoop(ctx, receiverLoopParams{
		logger:       d.logger,
		serviceLabel: d.cfg.XPCService,
		enqueue:      d.enqueue,
		pt:           d.pidTable,
		updateTable:  true,
		dispatcher:   d.esfDispatcher,
		health:       d.health,
		component:    health.ComponentEndpointSecurityExtension,
	})
	if d.cfg.NetXPCService != "" {
		go startReceiverLoop(ctx, receiverLoopParams{
			logger:       d.logger,
			serviceLabel: d.cfg.NetXPCService,
			enqueue:      d.enqueue,
			pt:           d.pidTable,
			upgradeProbe: func() bool { return receiver.NEUpgradePending(ctx) },
			health:       d.health,
			component:    health.ComponentNetworkExtension,
		})
	}
}
