# Observability Instrumentation Specification

## Purpose

The observability surface is the contract between the EDR server and any backend that ingests its traces, metrics, and logs
(SigNoz in development; Splunk, Datadog, Tempo, or any OTLP-aware collector in production). Operators write dashboards,
alerts, and SLO burn-rate queries against the metric and span attribute names declared here, so renaming a counter or dropping a
span attribute is an externally-visible breaking change even when no Go API changes.

This specification defines what the server emits, the names downstream dashboards depend on, the propagation guarantees that
make distributed traces coherent, and the no-op behaviour required so unit tests, offline development, and CI runs without an
OTLP collector remain functional.

## Requirements

### Requirement: OTLP export is opt-in via `OTEL_EXPORTER_OTLP_ENDPOINT`

The system SHALL export traces, metrics, and logs over OTLP when the `OTEL_EXPORTER_OTLP_ENDPOINT` environment variable
is non-empty, and SHALL treat all instrumentation as a no-op when that variable is empty or unset. The system reads
`OTEL_EXPORTER_OTLP_ENDPOINT` directly (the OpenTelemetry SDK convention) rather than introducing an EDR-specific name,
so any standard OTel-aware collector configuration documented for other services applies here. With the variable
unset, every counter add, histogram record, and observable-gauge callback MUST succeed silently and the process MUST
start, run, and shut down without contacting any collector.

#### Scenario: `OTEL_EXPORTER_OTLP_ENDPOINT` is unset

- **GIVEN** the server starts with `OTEL_EXPORTER_OTLP_ENDPOINT` empty or unset
- **WHEN** instrumentation code increments counters, records histograms, and writes structured logs
- **THEN** the server runs normally and no telemetry is exported
- **AND** the server's shutdown hook completes without errors related to telemetry export

#### Scenario: `OTEL_EXPORTER_OTLP_ENDPOINT` points at a collector

- **GIVEN** the server starts with `OTEL_EXPORTER_OTLP_ENDPOINT` pointing at a reachable collector
- **WHEN** instrumentation code emits telemetry
- **THEN** traces, metrics, and logs are exported to the configured collector via OTLP using the protocol selected by the
  standard OpenTelemetry SDK environment variables

### Requirement: Stable counter names

The system SHALL expose the following counters with stable names so dashboards and alerts can be authored against them:
`edr.events.ingested` (events accepted by the ingest endpoint), `edr.alerts.created` (newly created alerts, deduplicated alerts
not counted), `edr.agent.queue.dropped` (events the agent queue dropped), and `edr.processes.ttl_reconciled` (processes whose
exit time was synthesized by the freshness-TTL reconciler). Renaming any of these is a breaking change and MUST NOT happen
silently.

#### Scenario: Ingested events are counted by host

- **GIVEN** the ingest endpoint accepts a batch of events for a host
- **WHEN** the batch is committed
- **THEN** `edr.events.ingested` is incremented by the size of the batch with a `host_id` attribute

#### Scenario: Alerts are counted only on creation

- **GIVEN** the detection engine evaluates a rule
- **WHEN** evaluation produces a newly-created alert
- **THEN** `edr.alerts.created` is incremented with `rule_id` and `severity` attributes

#### Scenario: Already-delivered queue trim is distinguishable from data loss

- **GIVEN** the agent queue drops events
- **WHEN** the dropped events were already delivered (lossless trim) or had not yet been delivered (lossy drop)
- **THEN** `edr.agent.queue.dropped` is incremented with a `lossy` boolean attribute reflecting which case applied

### Requirement: DB query latency histogram

The system SHALL expose a histogram named `edr.db.query.duration` that records the latency of each instrumented store operation.
Every recorded sample MUST carry an `op` attribute drawn from a bounded, stable set of short names (for example
`insert_event`, `update_host_last_seen`) so that dashboards can compute per-operation p50/p95/p99 without dynamic-cardinality
explosions.

#### Scenario: A store operation records its latency

- **GIVEN** an instrumented store operation
- **WHEN** the operation completes
- **THEN** a sample is recorded against `edr.db.query.duration` with the operation's stable name as the `op` attribute

#### Scenario: Operation names are bounded

- **GIVEN** the set of `op` values across a representative workload
- **WHEN** the operator queries the histogram in the backend
- **THEN** the distinct `op` values match the documented stable set and do not include host ids, table-row values, or other
  high-cardinality data

### Requirement: Observable host-fleet gauges

The system SHALL expose two observable gauges, `edr.enrolled.hosts` and `edr.offline.hosts`, evaluated on each collection cycle
by the OTel reader. The enrolled gauge MUST report the number of non-revoked enrollments. The offline gauge MUST report the
number of hosts whose last-seen timestamp exceeds the configured offline threshold. A failed callback MUST NOT take down the
collection cycle for other gauges.

#### Scenario: Gauges evaluate on the reader cadence

- **GIVEN** OTLP export is enabled
- **WHEN** the OTel reader requests a metric collection
- **THEN** the gauges' callbacks run, query the data store, and observe the current values

#### Scenario: A failing gauge callback is contained

- **GIVEN** the data store is temporarily unavailable
- **WHEN** the gauge callback fails
- **THEN** no value is observed for that gauge in this collection cycle but the rest of the metric collection succeeds

### Requirement: Trace propagation through the request pipeline

The system SHALL accept inbound W3C `traceparent` and `baggage` headers and propagate the resulting span context through the
ingest, processor, and detection pipelines so that downstream backends can stitch the request into one trace. The system MUST
attach span attributes that name the entity each span operates on — in particular `host_id` on ingest spans, and `rule_id`
plus an alert count on detection spans — so analysts can navigate from an alert back to the upstream telemetry.

#### Scenario: Inbound traceparent is honoured

- **GIVEN** an HTTP request carrying a valid `traceparent` header
- **WHEN** the server handles the request
- **THEN** the resulting server span is a child of the inbound trace and the same trace propagates to downstream processing
  spans

#### Scenario: Detection spans carry rule context

- **GIVEN** the detection engine evaluates a rule
- **WHEN** evaluation produces an alert
- **THEN** the corresponding span carries at least `rule_id` and an alert count attribute that downstream dashboards can group by

### Requirement: Structured logs carry trace correlation

The system SHALL emit structured logs that include the active span's trace id and span id as record fields so that backend
indexers (SigNoz, Splunk, Datadog) can pivot from an alert log line to the originating trace and span. Logs MUST flow through
the same OTLP pipeline that traces and metrics use when OTLP export is enabled, and MUST be filtered to the configured log
level so a `WARN` configuration does not export `DEBUG` records to the collector.

#### Scenario: Log line under an active span

- **GIVEN** a request whose handler holds an active span
- **WHEN** the handler emits a structured log record
- **THEN** the record includes `trace_id` and `span_id` matching the active span

#### Scenario: Log level is honoured for export

- **GIVEN** the configured log level is `WARN`
- **WHEN** the handler emits a `DEBUG` or `INFO` record
- **THEN** the record is not exported to the OTLP backend

### Requirement: Instrumentation is safe on a nil receiver

Every recorder method on the metrics surface SHALL be safe to call on a nil receiver. Call sites MUST NOT need defensive
`if recorder != nil` guards around instrumentation calls; an absent recorder is equivalent to a no-op for the purposes of
counter, histogram, and gauge updates.

#### Scenario: Call sites do not guard the recorder

- **GIVEN** a code path that records metrics through a recorder reference that is nil
- **WHEN** instrumentation methods are invoked on that nil receiver
- **THEN** the call returns without panicking and without recording any value
