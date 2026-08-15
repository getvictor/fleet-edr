//go:build !windows

package main

import (
	"context"
	"time"

	"github.com/fleetdm/edr/agent/health"
	"github.com/fleetdm/edr/agent/receiver"
	"github.com/fleetdm/edr/agent/selfheal"
	"github.com/fleetdm/edr/agent/sensorevent"
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
		// One emitter shared by both durable sensor records: the provider transitions and the repair-gave-up event go
		// through the same queue on the same host.
		emitter := sensorevent.NewEnqueueEmitter(d.hostIDFn, d.enqueue, func() int64 { return time.Now().UnixNano() })
		go startReceiverLoop(ctx, receiverLoopParams{
			logger:       d.logger,
			serviceLabel: d.cfg.NetXPCService,
			enqueue:      d.enqueue,
			pt:           d.pidTable,
			upgradeProbe: func() bool { return receiver.NEUpgradePending(ctx) },
			health:       d.health,
			component:    health.ComponentNetworkExtension,
			// Only this loop: the network extension's XPC listener starts before its providers, so health here must key on
			// which providers report themselves running (issue #649).
			providerLiveness: true,
			// A provider that stops takes its telemetry stream with it and, before this, stayed stopped until a human ran
			// the host app's activate by hand (issue #632). The controller re-enables it from the same report health grades,
			// so a pkg upgrade or a settings toggle recovers on its own.
			// Health forgets a stop as soon as the self-heal repairs it, so the transition is written down separately as
			// durable tamper evidence (issue #684).
			transitions: sensorevent.New(emitter, d.logger),
			selfHeal: selfheal.New(selfheal.Options{
				Remediator: selfheal.NewRemediator(""),
				Health:     d.health,
				Component:  health.ComponentNetworkExtension,
				Logger:     d.logger,
				// The repair giving up is recorded durably as well as in health (issue #691). Health says what is true
				// now, so once an operator fixes the host by hand it reads healthy again and nothing records that the
				// host went uncaptured for however long it took them to notice. The alert is the durable account, the
				// same argument that justified recording the stop itself.
				OnEscalation: func(e selfheal.Escalation) {
					if err := sensorevent.EmitRecoveryFailed(ctx, emitter, e.Provider, e.Outcome, e.Attempts); err != nil {
						// Best effort by design: the health state is already published and the agent must keep
						// running. Logged at WARN so a queue that is rejecting writes is visible.
						d.logger.WarnContext(ctx, "could not record that automatic capture recovery gave up",
							"provider", e.Provider, "outcome", e.Outcome, "err", err)
					}
				},
			}),
		})
	}
}
