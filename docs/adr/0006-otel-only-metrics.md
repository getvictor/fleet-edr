# 0006. OpenTelemetry is the only metrics pipeline; no Prometheus /metrics

- Status: Accepted
- Date: 2026-05-15
- Deciders: getvictor

## Context

The EDR server and the EDR agent both need to be operable: someone has to be able to ask "is ingest healthy", "is detection keeping up", "is the retention runner deleting rows", "is the agent's local queue spilling", "is the DB slow on the hot read path", and "how many hosts are offline right now". The Go ecosystem offers two dominant conventions for that, and a project this small can really only afford to support one well:

1. **Prometheus pull model.** The process exposes `/metrics` over HTTP in Prometheus's text format; a Prometheus server (or any tool that speaks the text format) scrapes the endpoint on a schedule. The surface is `prometheus/client_golang`, `promhttp`, a registry per process, and label conventions specific to the Prometheus ecosystem.
2. **OpenTelemetry push model via OTLP.** The process registers counters, histograms, and observable gauges against an OTel meter; an SDK reader collects + exports them over OTLP (gRPC or HTTP) to either a vendor backend directly or to an OTel Collector that fans out. The same SDK powers traces and logs, so a single transport, a single auth/TLS posture, and a single set of resource attributes carry every signal off the host.

Reality on the ground in this codebase, before this ADR is written:

- `internal/observability/observability.go` is a single `Init` call that wires up the tracer provider, meter provider, and logger provider against the same OTLP/gRPC endpoint. The provider trio is installed atomically: any exporter failure leaves the SDK defaults in place and returns an error, so callers never observe a half-initialised stack. All three EDR binaries (`fleet-edr-server`, `fleet-edr-ingest`, `fleet-edr-agent`) call this same `Init`.
- `server/metrics/metrics.go` and `agent/metrics/metrics.go` expose typed `Recorder` methods (`EventsIngested`, `AlertCreated`, `RetentionRowsDeleted`, `ProcessesTTLReconciled`, `QueueDropped`, `ObserveDBQuery`, plus observable gauges for enrolled and offline host counts). Every instrument is registered against the global OTel meter; there is no second registry. Recorders are nil-safe so call sites do not need defensive checks.
- [`operations.md`](../operations.md) documents the metric names operators monitor (`edr.events.ingested`, `edr.alerts.created`, `edr.enrolled.hosts`, `edr.offline.hosts`, `edr.retention.rows_deleted`, `edr.processes.ttl_reconciled`, `edr.db.query.duration`, `edr.agent.queue.dropped`). All eight names follow OTel semconv spelling, not Prometheus snake_case conventions.
- The development loop targets a local SigNoz at `localhost:4317` via OTLP/gRPC. Production deployments point `OTEL_EXPORTER_OTLP_*` at whatever OTLP-speaking collector the operator runs (SigNoz, Grafana Alloy, Datadog Agent, AWS Distro for OpenTelemetry, the upstream OpenTelemetry Collector, etc.).
- There are zero imports of `github.com/prometheus/client_golang` in the module. There has never been a `/metrics` HTTP route registered.

The decision to record is whether to keep going OTel-only or to add a Prometheus `/metrics` endpoint alongside the existing push pipeline. This question keeps coming back in code reviews and was historically answered "no, OTel-only" in conversation; writing it down stops the question being relitigated every quarter.

The forces:

- A second pipeline is an ongoing tax, not a one-time cost. Two metric naming conventions to keep in sync, two registration surfaces, a `/metrics` HTTP handler with its own auth + TLS considerations, two sets of cardinality controls, and two sets of client-library CVEs to track.
- The OTel pipeline is already paying for itself. Traces and logs ride the same transport, the same resource attributes, and the same auth. Adding metrics on top of it costs the import of the metric SDK packages, not a separate stack.
- Operators who insist on Prometheus aren't actually locked out: the upstream OpenTelemetry Collector ships a `prometheus` exporter that re-emits OTel metrics as a Prometheus scrape target. Anyone who runs an OTel Collector in front of their backend can land scrapes against the collector, not against the EDR processes.
- The product is small. Carrying a duplicated observability stack on a small team starves the work that customers actually pay for (detection content, agent reliability, response actions).

## Decision

The EDR has exactly one metrics pipeline: OpenTelemetry metrics exported over OTLP, configured by the standard `OTEL_*` env vars and initialised by `internal/observability.Init`. There is no Prometheus `/metrics` HTTP endpoint, no `prometheus/client_golang` dependency, no secondary metric registry, and no plan to add any of those.

Operators who need Prometheus-shaped scrape data run an OTel Collector in front of their preferred backend and use the collector's `prometheus` exporter (or `prometheusremotewrite` exporter). The collector becomes the integration seam, not the EDR processes.

Instrumentation rule for new metrics: register the counter, histogram, or observable gauge against the global OTel meter (`otel.Meter("github.com/fleetdm/edr/server/metrics")` for server, the equivalent agent path for agent), expose it through a typed method on the `Recorder` so call sites pass concrete attribute values rather than free-form labels, and document the name + cardinality story in [`operations.md`](../operations.md).

## Consequences

**Good:**

- One pipeline to operate. One auth / TLS posture, one set of resource attributes, one cardinality story. Traces, logs, and metrics share the same off-host path.
- Backend portability. Any OTLP-speaking collector or vendor accepts the data. The team is not locked into Prometheus, SigNoz, or any single backend; `OTEL_EXPORTER_OTLP_ENDPOINT` is the only setting an operator changes.
- Smaller dependency surface. No `prometheus/client_golang` (which drags in its own register / collector / exposition logic), no `promhttp.Handler` registered on the public HTTP mux, no scrape authentication to design.
- OTel semconv compliance by default. Names follow the published conventions and inherit any future OTel-side standardisation work for free.
- Per-binary metric subset is auditable via `go list -deps ./<binary>/cmd/...`: the agent does not link the server's metric registrations, and vice versa, because the `metrics` packages are per-binary by design (see `server/metrics/` and `agent/metrics/`).

**Bad:**

- Customers running Prometheus as their primary observability backend must run an OTel Collector to bridge the two. Bridging is well-trod ground but is an extra hop their runbooks have to cover.
- Pull-model debugging (curl `/metrics` from a developer laptop to read the current counter snapshot) is not available out of the box. `internal/observability/observability.go` instantiates `otlpmetricgrpc` directly rather than going through the OTel SDK's autoconfigure path, so swapping in the `stdoutmetric` exporter for local debugging is a small code edit to `Init`, not a configuration toggle. If a built-in stdout path is wanted later, the fix is to route exporter selection through an env var inside `Init`; the ADR doesn't preclude that.
- The team has to track OTel SDK releases as a load-bearing dependency. The OTel Go SDK has shipped breaking API changes in pre-`v1.0` modules (the logs API was experimental for a long time) and pinning + bumps cost some maintenance cycles. That cost is a cost the project would pay anyway for trace/log emission; the decision here just acknowledges that metrics share the bill.

## Alternatives considered

**Prometheus `/metrics` endpoint only, no OTel metrics.** Stacks both sides on a single ecosystem and uses pull collection that's familiar to most operators. Rejected because the project already needs the OTel SDK for traces and logs, so going Prometheus-only for metrics would mean carrying two SDKs and two pipelines, and it would force traces and logs onto a Prometheus-shaped backend that is not what most OTLP-native backends (SigNoz, Grafana Cloud, Datadog) want.

**Dual stack: Prometheus `/metrics` AND OTel metrics.** Every instrument registered twice; cardinality and naming have to be kept in sync; the `/metrics` endpoint requires its own scrape authentication design separate from the rest of the API; and operators have to decide which pipeline is authoritative. The "for safety" appeal of dual-stack vanishes once you consider that the operational information is in one place anyway (whatever the operator's primary backend is), and the duplicate surface is real engineering tax. Looked at concretely: every metric in this codebase would be registered twice in the metrics package, every doc update would have to cover two names, and a label-set drift between the two would produce two contradictory dashboards over the same event.

**Push gateway with Prometheus client.** A push gateway lets short-lived processes write to Prometheus despite the pull model. Rejected because the EDR server and agent are not short-lived (they're long-running processes), the push gateway's own ergonomics are widely considered an anti-pattern in the Prometheus community, and the proposed escape hatch is exactly what OTLP already does natively.

**Hand-rolled `/metrics` text-format endpoint without a Prometheus client library.** Avoids the `prometheus/client_golang` dependency but reinvents the registration, the exposition format, the cardinality management, and the test coverage that an established library handles. Costs more than the dual-stack option for the same outcome.

**StatsD push.** Pre-OTel-era choice. Rejected as a clear step backwards: no histograms with explicit buckets (StatsD timers are approximations), no resource attributes, no traces or logs on the same pipe, and the ecosystem has largely converged to OTLP for new work.

## References

- `internal/observability/observability.go` (the single `Init` that wires tracer + meter + logger to OTLP/gRPC).
- `server/metrics/metrics.go` (typed `Recorder` over the global OTel meter; counters, histograms, observable gauges).
- `agent/metrics/metrics.go` (same pattern in the agent).
- [`operations.md`](../operations.md) "Metrics and monitoring" section (operator-facing list of metric names + interpretation).
- `Taskfile.yml` `dev:server` env block (`OTEL_EXPORTER_OTLP_*` knobs).
- [OpenTelemetry Collector contrib repo](https://github.com/open-telemetry/opentelemetry-collector-contrib) ships the `prometheus` and `prometheusremotewrite` exporters operators run if they need Prometheus-shaped scrapes off the OTel pipeline.
- ADR-0003 "EDR is a standalone product, Fleet is a deployment channel" (this ADR's "operators run their own collector" model rhymes with 0003's "MDMs are deployment channels, not the data plane").
