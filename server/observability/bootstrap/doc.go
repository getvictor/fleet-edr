// Package bootstrap wires the observability bounded context: the deployment's runtime telemetry-control surface (issue #374).
//
// Today it owns one capability, the OTel trace head-sampling settings (the per-tier ratios + force-full toggle): a singleton MySQL
// table, a super-admin admin API (GET/PATCH /api/settings/tracing), and the read accessor the per-replica sampler poller consumes.
// It is a sixth bounded context (an amendment to ADR-0004's original five) because the surface owns its own schema and serves an
// authorization-gated, audited HTTP route while consuming identity.api for authz + audit, which is the bounded-context shape in this
// codebase and not something a context-free platform package may do.
//
// The sampler mechanism itself (the Sampler, Registry, poller, and Settings type) lives in internal/observability/tracing so it stays
// agent-safe and free of any server or persistence dependency; this context only persists and serves those settings.
package bootstrap
