// Package tracing implements a route-aware head sampler for the EDR server's OTel trace export. Every inbound HTTP span is
// classified by a Registry into one of four tiers and sampled per tier: agent data-plane traffic (TierHighVolume) is downsampled
// aggressively, operator/UI read traffic (TierStandard) moderately, everything else (TierFull, the zero value) at 100%, and
// liveness/health probes (TierDrop) are dropped unconditionally. The goal is to keep the noisy agent firehose from drowning out the
// rare load-bearing flows (enroll, command delivery, detection) without losing them.
//
// Mechanism vs policy: this package owns the mechanism (the sampler, the tier enum, the registry). The route-to-tier policy lives in
// the server layer (server/tracingpolicy) so this shared package stays free of any EDR-route or bounded-context coupling, and the
// agent can depend on internal/observability without dragging server routes in.
//
// Runtime control: the two ratios and a force-full incident toggle live in a durable settings record. Each replica runs
// StartSettingsPoller, which re-reads the record on a fixed interval and atomically swaps the sampler's state, so an operator can
// adjust sampling across a multi-replica deployment without a restart. The applied state is a per-replica cache that is safe to lose
// (ADR-0010): on a read failure the sampler keeps its built-in defaults.
package tracing
