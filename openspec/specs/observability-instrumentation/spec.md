# Observability Instrumentation Specification

## Purpose

The observability surface is the contract between the EDR server and any backend that ingests its traces, metrics, and logs (SigNoz in development; Splunk, Datadog, Tempo, or any OTLP-aware collector in production). Operators write dashboards, alerts, and SLO burn-rate queries against the metric and span attribute names declared here, so renaming a counter or dropping a span attribute is an externally-visible breaking change even when no Go API changes.

This specification defines what the server emits, the names downstream dashboards depend on, the propagation guarantees that make distributed traces coherent, and the no-op behaviour required so unit tests, offline development, and CI runs without an OTLP collector remain functional.

## Requirements

### Requirement: OTLP export is opt-in via `OTEL_EXPORTER_OTLP_ENDPOINT`

The system SHALL export traces, metrics, and logs over OTLP when the `OTEL_EXPORTER_OTLP_ENDPOINT` environment variable is non-empty, and SHALL treat all instrumentation as a no-op when that variable is empty or unset. The system reads `OTEL_EXPORTER_OTLP_ENDPOINT` directly (the OpenTelemetry SDK convention) rather than introducing an EDR-specific name, so any standard OTel-aware collector configuration documented for other services applies here. With the variable unset, every counter add, histogram record, and observable-gauge callback MUST succeed silently and the process MUST start, run, and shut down without contacting any collector.

#### Scenario: `OTEL_EXPORTER_OTLP_ENDPOINT` is unset

- **GIVEN** the server starts with `OTEL_EXPORTER_OTLP_ENDPOINT` empty or unset
- **WHEN** instrumentation code increments counters, records histograms, and writes structured logs
- **THEN** the server runs normally and no telemetry is exported
- **AND** the server's shutdown hook completes without errors related to telemetry export

#### Scenario: `OTEL_EXPORTER_OTLP_ENDPOINT` points at a collector

- **GIVEN** the server starts with `OTEL_EXPORTER_OTLP_ENDPOINT` pointing at a reachable collector
- **WHEN** instrumentation code emits telemetry
- **THEN** traces, metrics, and logs are exported to the configured collector via OTLP using the protocol selected by the standard OpenTelemetry SDK environment variables

### Requirement: Stable counter names

The system SHALL expose the following counters with stable names so dashboards and alerts can be authored against them: `edr.events.ingested` (events accepted by the ingest endpoint), `edr.alerts.created` (newly created alerts, deduplicated alerts not counted), `edr.detection.monitor_matches` (rule matches suppressed because the resolved mode was monitor), `edr.agent.queue.dropped` (events the agent queue dropped), `edr.processes.ttl_reconciled` (processes whose exit time was synthesized by the freshness-TTL reconciler), `edr.detection.materialization_retries` (detection batches re-queued because an event's subject or flow process was not materialized yet), and `edr.events.set_aside` (queued events withdrawn from processing because their batch could not be processed). Renaming any of these is a breaking change and MUST NOT happen silently.

`edr.detection.monitor_matches` SHALL carry the same `rule_id` and `severity` attributes as `edr.alerts.created`, and SHALL label a match with the severity the alert would have carried, so that the two series describe one rule identically and can be compared. Comparing them is how an operator judges what promoting a rule to alerting would produce.

`edr.detection.monitor_matches` SHALL be recorded once the batch that produced the matches will not be processed again, not while the batch is evaluated, and this SHALL be documented where the counter is defined. A batch that fails is nacked and replayed whole, so a counter incremented during evaluation counts a retried batch once per attempt; recorded on the transition that ends the batch's life, which is usually its acknowledgement and is also its withdrawal from the queue after repeated failure, a replayed batch is counted once.

The counter SHALL be documented as counting MATCHES rather than would-be alerts. `edr.alerts.created` counts newly created alerts, which deduplicate on (host, rule, subject) permanently, so a rule that keeps matching one subject increments the monitor series every time and would raise exactly one alert. That biases the monitor series upward against what promoting the rule produces, while the counter's documented losses bias it downward, so it SHALL be described as an approximation rather than as a bound in either direction. Documenting that is what keeps the recommended comparison from being read as a forecast.

`edr.events.set_aside` SHALL carry a `host_id` attribute. The question it answers is which host has stopped contributing some of its activity, and a fleet-wide total cannot answer it. WHAT it stopped contributing depends on the stage the batch was withdrawn at and is not derivable from the counter, so the counter SHALL NOT be documented as identifying a gap in that host's process graph; the accompanying log record carries the stage and its consequence.

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

#### Scenario: A suppressed match is counted rather than only logged

- **GIVEN** a rule whose resolved mode is monitor
- **WHEN** it matches an event
- **THEN** `edr.detection.monitor_matches` is incremented with `rule_id` and `severity` attributes
- **AND** no alert is created for that match

#### Scenario: A suppressed match is labelled with the severity the alert would have carried

- **GIVEN** a rule whose resolved mode is monitor and whose setting carries a severity override
- **WHEN** it matches an event
- **THEN** the counter's `severity` attribute is the overridden severity, not the rule's declared one

#### Scenario: Materialization-miss batch retries are counted

- **GIVEN** a detection batch that will be re-queued because a rule saw an event whose subject or flow process was not materialized yet
- **WHEN** the retry is recorded
- **THEN** `edr.detection.materialization_retries` is incremented

#### Scenario: Events withdrawn from processing are counted per host

- **GIVEN** a batch whose events are set aside because it could not be processed
- **WHEN** they are set aside
- **THEN** `edr.events.set_aside` is incremented by the number of events with a `host_id` attribute

### Requirement: DB client metrics via standard driver instrumentation

The system SHALL emit database-client latency and connection-pool metrics through the standard OpenTelemetry SQL driver instrumentation (otelsql), not a bespoke per-call-site metric. The pool is opened through otelsql so every query is timed by the driver as a `db.sql.latency` histogram (with `db.sql.connection.*` pool gauges) without any instrumentation code at the call sites. This avoids a hand-maintained operation-name allowlist and gives complete coverage of every query rather than only the few that were manually instrumented. Per-query timing with full request context remains available on the otelsql spans.

#### Scenario: The pool is instrumented by the driver, not the call sites

- **GIVEN** the connection pool is opened through the otelsql driver wrapper
- **WHEN** the OTel reader collects metrics
- **THEN** the driver-level connection-pool metrics (`db.sql.connection.*`) are reported without any per-call-site instrumentation code

### Requirement: HTTP server request duration

The system SHALL expose a histogram named `http.server.request.duration` (the OpenTelemetry HTTP semantic-convention name, in seconds) that records the latency of every inbound HTTP request. Each sample MUST carry `http.request.method`, `http.route`, and `http.response.status_code` attributes, where `http.route` is the matched route TEMPLATE (for example `/api/hosts/{host_id}/tree`) and never the raw path, so high-frequency endpoints do not explode metric cardinality; an unrecognized method MUST collapse to `_OTHER` and a request that matched no route MUST use the route value `unmatched`. Because this metric carries the per-request rate and latency signal, the access log MUST NOT emit an info-level line per successful request: healthy 2xx/3xx requests log at debug, 4xx at info, 5xx or slow requests at warn.

#### Scenario: Inbound requests are timed by route, method, and status

- **GIVEN** the server handles inbound HTTP requests
- **WHEN** a request completes
- **THEN** a sample is recorded on `http.server.request.duration` labeled with the request's method, matched route template, and response status code
- **AND** requests sharing a method, route template, and status code collapse into one time series

### Requirement: Observable host-fleet gauges

The system SHALL expose two observable gauges, `edr.enrolled.hosts` and `edr.offline.hosts`, evaluated on each collection cycle by the OTel reader. The enrolled gauge MUST report the number of non-revoked enrollments. The offline gauge MUST report the number of hosts whose last-seen timestamp exceeds the configured offline threshold. A failed callback MUST NOT take down the collection cycle for other gauges.

#### Scenario: Gauges evaluate on the reader cadence

- **GIVEN** OTLP export is enabled
- **WHEN** the OTel reader requests a metric collection
- **THEN** the gauges' callbacks run, query the data store, and observe the current values

#### Scenario: A failing gauge callback is contained

- **GIVEN** the data store is temporarily unavailable
- **WHEN** the gauge callback fails
- **THEN** no value is observed for that gauge in this collection cycle but the rest of the metric collection succeeds

### Requirement: Trace propagation through the request pipeline

The system SHALL accept inbound W3C `traceparent` and `baggage` headers and propagate the resulting span context through the ingest, processor, and detection pipelines so that downstream backends can stitch the request into one trace. The system MUST attach span attributes that name the entity each span operates on (in particular `host_id` on ingest spans, and `rule_id` plus an alert count on detection spans) so analysts can navigate from an alert back to the upstream telemetry.

#### Scenario: Inbound traceparent is honoured

- **GIVEN** an HTTP request carrying a valid `traceparent` header
- **WHEN** the server handles the request
- **THEN** the resulting server span is a child of the inbound trace and the same trace propagates to downstream processing spans

#### Scenario: Detection spans carry rule context

- **GIVEN** the detection engine evaluates a rule
- **WHEN** evaluation produces an alert
- **THEN** the corresponding span carries at least `rule_id` and an alert count attribute that downstream dashboards can group by

### Requirement: Structured logs carry trace correlation

The system SHALL emit structured logs that include the active span's trace id and span id as record fields so that backend indexers (SigNoz, Splunk, Datadog) can pivot from an alert log line to the originating trace and span. Logs MUST flow through the same OTLP pipeline that traces and metrics use when OTLP export is enabled, and MUST be filtered to the configured log level so a `WARN` configuration does not export `DEBUG` records to the collector.

#### Scenario: Log line under an active span

- **GIVEN** a request whose handler holds an active span
- **WHEN** the handler emits a structured log record
- **THEN** the record includes `trace_id` and `span_id` matching the active span

#### Scenario: Log level is honoured for export

- **GIVEN** the configured log level is `WARN`
- **WHEN** the handler emits a `DEBUG` or `INFO` record
- **THEN** the record is not exported to the OTLP backend

### Requirement: Instrumentation is safe on a nil receiver

Every recorder method on the metrics surface SHALL be safe to call on a nil receiver. Call sites MUST NOT need defensive `if recorder != nil` guards around instrumentation calls; an absent recorder is equivalent to a no-op for the purposes of counter, histogram, and gauge updates.

#### Scenario: Call sites do not guard the recorder

- **GIVEN** a code path that records metrics through a recorder reference that is nil
- **WHEN** instrumentation methods are invoked on that nil receiver
- **THEN** the call returns without panicking and without recording any value

### Requirement: Telemetry carries a deployment environment resource attribute

The system SHALL set the `deployment.environment.name` resource attribute on every emitted span, metric, and log, and SHALL also set the deprecated `deployment.environment` attribute to the same value for backends that still key on the older name. Both SHALL default to `default` and SHALL be emitted unconditionally so the attribute key exists in every backend a binary reports to, which lets a dashboard offer a dynamic environment selector that populates on any instance. The default SHALL be overridable via `OTEL_RESOURCE_ATTRIBUTES`: an operator-supplied `deployment.environment` (or `deployment.environment.name`) value MUST win over the built-in `default` so a deployment exporting to a shared backend can scope its telemetry per environment.

#### Scenario: Default deployment environment

- **GIVEN** no `OTEL_RESOURCE_ATTRIBUTES` override for the deployment environment
- **WHEN** the telemetry resource is built
- **THEN** the resource carries `deployment.environment.name` equal to `default`
- **AND** the resource carries the deprecated `deployment.environment` equal to `default`

#### Scenario: Operator overrides the deployment environment

- **GIVEN** `OTEL_RESOURCE_ATTRIBUTES` sets `deployment.environment` (and/or `deployment.environment.name`) to an operator-chosen value
- **WHEN** the telemetry resource is built
- **THEN** the resource carries the operator-supplied value rather than `default`

### Requirement: Route-tier head sampling of exported traces

When OTLP export is enabled, the system SHALL apply head sampling to traces, classifying each inbound HTTP request span into a sampling tier and sampling each ratio-bearing tier at its configured ratio: a high-volume tier for high-frequency agent data-plane traffic, a standard tier for operator and UI read traffic, and a full tier for everything else. The full tier SHALL be sampled at 100% and SHALL be the default for any span not explicitly classified, so a newly added route is captured at full fidelity until it is deliberately downsampled. Sampling SHALL be parent-based: a span whose parent was sampled MUST itself be sampled, so a distributed trace is never partially captured. The high-frequency agent routes `POST /api/events`, the agent command poll `GET /api/commands`, and `POST /api/token/refresh` SHALL be classified high-volume; low-frequency load-bearing agent routes such as `POST /api/enroll` SHALL remain in the full tier so they are captured at full fidelity.

#### Scenario: Agent ingest traffic is downsampled

- **GIVEN** OTLP export is enabled and the high-volume ratio is below 1.0
- **WHEN** agents send many `POST /api/events` requests
- **THEN** only the configured high-volume fraction of those request traces is exported

#### Scenario: Unclassified routes are sampled at full fidelity

- **GIVEN** a request to a route that is not registered in any sampling tier
- **WHEN** the server handles the request
- **THEN** the request trace is sampled at 100%

#### Scenario: A sampled parent forces its children sampled

- **GIVEN** an inbound request whose `traceparent` marks the parent span as sampled
- **WHEN** the server creates child spans for downstream processing
- **THEN** those child spans are sampled regardless of the tier ratio that would otherwise apply

### Requirement: Sampler ratios are runtime-adjustable without redeploy

The system SHALL persist the high-volume ratio, the standard ratio, and a force-full flag in a single durable settings record bounded so each ratio is between 0 and 1 inclusive. Each server replica SHALL read this record on startup and re-read it periodically, applying any change to its live sampler without a restart, so an operator can adjust sampling across a multi-replica deployment without redeploying. The system SHALL NOT require any environment variable to configure sampling; the durable record SHALL be seeded with built-in defaults, and a replica that cannot read the record SHALL fall back to those same built-in defaults rather than failing to start.

#### Scenario: A ratio change propagates to running replicas

- **GIVEN** a running server replica with a live sampler
- **WHEN** the persisted high-volume ratio is changed
- **THEN** the replica applies the new ratio to subsequent sampling decisions within one poll interval, without a restart

#### Scenario: Settings record is unreadable at startup

- **GIVEN** the settings record cannot be read when a replica starts
- **WHEN** the replica initializes its sampler
- **THEN** the replica uses the built-in default ratios and continues running

#### Scenario: Out-of-range ratio is rejected by the store

- **GIVEN** an attempt to persist a ratio outside the range 0 to 1
- **WHEN** the write is submitted
- **THEN** the store rejects it and the persisted ratios are unchanged

### Requirement: Force-full override restores complete tracing

The system SHALL provide a force-full override that, when enabled, causes every non-drop tier to be sampled at 100% regardless of its configured ratio, so an operator can capture complete traces during an incident debug window and disable it afterward, in both cases without a redeploy. The drop tier is exempt: probe spans stay dropped even under force-full (see the probe requirement below).

#### Scenario: Force-full lifts all tiers to full sampling

- **GIVEN** the high-volume and standard ratios are below 1.0 and force-full is enabled
- **WHEN** agents and operators send requests across all tiers
- **THEN** every request trace is exported while force-full remains enabled

### Requirement: Liveness and health probe traces are never exported

The system SHALL classify liveness, readiness, health, and version-probe request spans into a drop tier whose spans are never recorded or exported. This classification SHALL take precedence over the force-full override, so enabling force-full during an incident does not flood the backend with probe traffic.

#### Scenario: Probe spans are dropped

- **GIVEN** OTLP export is enabled
- **WHEN** a load balancer or orchestrator polls the health or version endpoint
- **THEN** no trace for that request is exported

#### Scenario: Probes stay dropped under force-full

- **GIVEN** force-full is enabled
- **WHEN** the health or version endpoint is polled
- **THEN** the probe request trace is still not exported

### Requirement: Operators adjust sampler settings through an authenticated admin endpoint

The system SHALL expose an authenticated endpoint to read and update the sampler settings, restricted to operators holding the tracing-management grant (the admin or super_admin role) and authenticated by the operator session cookie and CSRF token. The endpoint SHALL reject requests from an operator without that grant. An update SHALL validate that each ratio is between 0 and 1 inclusive before persisting and SHALL return the resulting settings.

#### Scenario: An administrator updates the ratios

- **GIVEN** an operator holding the tracing-management grant with a valid session cookie and CSRF token
- **WHEN** they submit an update setting the high-volume and standard ratios within range
- **THEN** the settings are persisted and the response returns the updated values

#### Scenario: An operator without the grant is denied

- **GIVEN** an authenticated operator who does not hold the tracing-management grant
- **WHEN** they attempt to read or update the sampler settings
- **THEN** the request is denied and the settings are unchanged

#### Scenario: Update with an out-of-range ratio is rejected

- **GIVEN** an authorized operator submitting an update with a ratio above 1.0
- **WHEN** the update is processed
- **THEN** the endpoint rejects the request and no setting is changed

### Requirement: Aggregate latency and alerting derive from metrics, not sampled spans

Because traces are head-sampled, aggregate request-rate, latency-percentile, and error-rate signals SHALL be derived from the metric instruments, which are never sampled, rather than from exported spans. The per-request latency histogram and the stable counters SHALL continue to record every request and event regardless of the trace sample ratio in effect, so a low sample ratio MUST NOT bias these aggregates.

#### Scenario: Latency percentiles are unaffected by the sample ratio

- **GIVEN** the high-volume ratio is set to a small fraction
- **WHEN** many agent requests are handled
- **THEN** the `http.server.request.duration` histogram records every request and its percentiles reflect the full request population, not the sampled subset

#### Scenario: Event counts are unaffected by the sample ratio

- **GIVEN** trace sampling is in effect at any ratio
- **WHEN** the ingest endpoint accepts a batch of events
- **THEN** `edr.events.ingested` is incremented by the full batch size independent of whether the request's trace was sampled

### Requirement: Detection materialization-miss retries are bounded in log volume

The detection processor re-queues (nacks) a batch whenever rule evaluation reports the retryable not-yet-materialized error class for an event's subject or flow process. Because that condition can persist for a sustained interval under normal operational and failure modes (a replica behind on graph materialization, an agent that stopped sending fork/exec while its processes keep connecting, a datastore restore or replica re-seed, or a batch of orphaned flows for a long-lived process), the same batch re-nacks on every poll tick within its grace window. The system therefore SHALL NOT emit a warn-level log line per materialization-miss retry; it SHALL instead increment the `edr.detection.materialization_retries` counter and log the retry at debug level, so a sustained materialization-miss condition produces bounded log volume while remaining observable through the counter. A genuine (non-materialization) detection batch failure, such as an alert persistence error, SHALL continue to log at warn level so a real fault stays loud.

#### Scenario: A materialization-miss retry is debug-logged and counted

- **GIVEN** the processor evaluates a claimed batch and rule evaluation returns the retryable not-yet-materialized error class
- **WHEN** the processor re-queues the batch
- **THEN** the retry is logged at debug level, not warn level
- **AND** the `edr.detection.materialization_retries` counter is incremented

#### Scenario: A genuine detection failure still warn-logs

- **GIVEN** the processor evaluates a claimed batch and rule evaluation returns a failure that is not the not-yet-materialized error class
- **WHEN** the processor re-queues the batch
- **THEN** the failure is logged at warn level
- **AND** the `edr.detection.materialization_retries` counter is not incremented

### Requirement: Per-rule evaluation cost is recorded durably

The system SHALL record, durably and per rule, how many times each rule evaluated, how long those evaluations took, and how many ended in a retryable outcome rather than a decision.

This requirement covers the DURABLE RECORD only. Presenting these figures to an operator is a separate requirement that ships with the surface that presents them; a record no interface reads satisfies nothing on its own, and claiming the operator-facing outcome here would let this requirement pass while the thing an operator needs is still missing.

The record exists because a rule's match count cannot answer this question: a rule can be perfectly quiet and still be the one holding up the drain loop. The figures that could answer it are not durable today. Per-rule latency lives only on the evaluation span, and the retry counter is fleet-wide and so cannot name the rule responsible.

Recording SHALL count evaluation ATTEMPTS, and SHALL happen whether or not the batch is acknowledged.

That is deliberately the opposite of the rule the "Monitor-mode matches are recorded durably per rule" requirement sets for match counts, and both are correct because they count different things. A monitor match is a fact about the world, that this rule matched this host on that day, so a replayed batch must not record it twice. An evaluation is a fact about work the system performed, and a replayed batch genuinely did evaluate again. Counting attempts also keeps the derived figure honest, because the attempt count and the total time grow together, so the mean stays a mean per attempt rather than being inflated the way a per-batch figure would be. It is not invariant under replay, since an attempt that ran faster or slower than the others moves it. Recording only on the transition that ends a batch's life would additionally put the retryable-outcome count nearly out of reach, because a batch that ends in a retryable outcome is nacked rather than acknowledged, and reaches such a transition only in the rare case where it is eventually withdrawn from the queue. A count that reported almost none of the retries would be worse than no count, and naming the rule behind the retry churn is the reason it exists.

An evaluation SHALL be counted only when the rule was actually given events to evaluate. A rule the platform scope left with nothing to see did not run, and counting it would report work that never happened and drag that rule's measured cost toward zero.

A failure to record SHALL NOT fail the batch, and SHALL NOT nack a batch that has already been acknowledged.

Recorded statistics SHALL be bounded by the number of rules and the deployment's data-retention window rather than by event volume, and pruning them SHALL NOT require a leader-elected task, for the same reason the match counts' prune does not.

#### Scenario: Statistics outlive the process that produced them

- **GIVEN** a rule that has evaluated, with its statistics recorded
- **WHEN** the process restarts, or another replica serves the read
- **THEN** the recorded statistics are still reported rather than starting from zero

#### Scenario: A replayed batch counts each attempt, and records the retryable outcome

- **GIVEN** a batch whose evaluation ends in a retryable outcome, so the batch is nacked and replayed
- **WHEN** each attempt evaluates the same rule
- **THEN** every attempt is counted, with its own duration
- **AND** the retryable outcome is recorded even though the batch was never acknowledged

#### Scenario: A rule with nothing in scope is not counted as having evaluated

- **GIVEN** a batch carrying only events outside a rule's target platform
- **WHEN** the batch is evaluated
- **THEN** that rule has no recorded evaluation, rather than one of zero duration

#### Scenario: A recording failure does not fail the batch

- **GIVEN** a batch whose evaluation statistics cannot be persisted
- **WHEN** the recording fails
- **THEN** the failure is logged
- **AND** the batch's own outcome is unchanged and its events are not replayed on account of it

#### Scenario: Statistics older than the retention window are pruned

- **GIVEN** recorded statistics older than the configured retention window
- **WHEN** the prune runs
- **THEN** those statistics are deleted
- **AND** statistics inside the window are kept

### Requirement: Monitor-mode matches are recorded durably per rule

The system SHALL record, durably and per rule, how many times each rule matched in monitor mode, so that an operator deciding whether to promote a rule has the rule's observed behaviour in the product rather than only in a metrics backend.

A monitor match SHALL be attributed to the host it matched on and to the day it was recorded, so the record answers both questions a promotion turns on: how often the rule fires, and across how much of the fleet. Those are different decisions. A rule matching many times on one host is a candidate for an exclusion, while the same volume spread across every host means the rule itself is too broad, and a fleet-wide total alone cannot distinguish them.

Counts SHALL be recorded on the transition that ends the batch's life, not while the batch is evaluated. A batch that fails is nacked and replayed whole, so a count written during evaluation is written again by every retry.

Usually that transition is the acknowledgement. The other is the batch being withdrawn from processing for good once its retry bounds are passed, and there the MOST RECENT matches resolved for that batch by any of its attempts SHALL be recorded rather than discarded, because there is no later attempt to record them. Discarding them under-reports for precisely the hosts that had processing trouble, and the figure is what an operator reads when deciding whether to promote a monitor-mode rule, so the bias is toward believing a rule is quiet.

Across attempts, and not merely on the withdrawing one. Processing has stages and the retry bounds do not distinguish them: they accrue on the queue entry and count every attempt, whichever stage failed, so a batch can be evaluated on one attempt and withdrawn on an attempt that failed at the fold and evaluated nothing. Without carrying, the batch's last word says nothing about what it matched.

An attempt that resolved NO matches SHALL NOT displace what an earlier attempt resolved, and this is the case that decides what "most recent" means. Evaluation reports what it accumulated UP TO its failure, so an attempt that fails on an earlier rule than its predecessor reports fewer matches and one that fails on the first reports none. An empty result from a failing attempt is therefore an absence of information and MUST NOT be read as an assertion that the batch matched nothing; reading it that way would discard a predecessor's real matches on the commonest failure there is, which is the under-reporting this requirement exists to prevent.

The residual is stated rather than implied away: where a rule is taken out of monitor mode between two attempts, the carried matches are the demoted rule's and the figure is high by one batch for it. That is accepted because the alternative is systematic. The two cases are indistinguishable at this layer, since evaluation reports an empty result for both, and the recorded figure is already documented as approximate. Telling them apart needs evidence the result does not carry, which is tracked separately.

The matches SHALL survive the attempt that resolved them by riding with the queued events rather than in the replica that evaluated them. Per-replica state would be lost on exactly the restarts that produce these failures, and the app tier is multi-replica by design. The queue SHALL keep them without interpreting them, since a work queue that understood a monitor match would be a detection concern living in it, and keeping them SHALL NOT cost a write the return of a failed batch does not already make.

Only a batch withdrawn IN FULL SHALL be counted this way. The withdrawal decision is made per queued event, so a partly withdrawn batch leaves events that are claimed and evaluated again while the recorded figure covers all of them, and recording it would count the remainder twice. Exactly-once SHALL rest on the queue reporting a withdrawal to one caller rather than on coordination between workers, and withdrawal SHALL be a state an event does not leave. An event that has been withdrawn is not returned to the queue, so no later attempt can withdraw it again and no later attempt is told that it did.

A partial withdrawal therefore loses whatever the withdrawn events alone had matched, and this SHALL be documented rather than implied away. The surviving events are evaluated again and their matches are counted then, but a match that only the withdrawn events produced has no later attempt to produce it. Recording the survivors' share instead would need the figure to carry which event each match came from, which it does not: it is aggregated per rule and host for the batch. Discarding the whole attempt is the choice that cannot over-count, and over-counting is the direction that makes a noisy rule look worse than it is rather than safer than it is.

Two residual inaccuracies remain besides those two, and SHALL be documented rather than implied away. A crash between the transition and the record loses those counts, and so does a recording failure, which is dropped rather than allowed to fail a batch already finished with the queue (below). Which of the two sinks is left ahead depends on where in that window the failure lands: the observability counter is advanced before the durable write, so a crash before that point loses both, and only a crash after it, or a failure of the write itself, leaves the counter ahead of the durable record. That is the direction that carries risk, not the one that avoids it: a rule whose recorded volume is too low looks quiet, which is what persuades an operator to promote it, and promoting a noisy rule is the alert flood monitor mode exists to prevent. It is accepted because the alternative, counting during evaluation, is systematically wrong on every retry rather than rarely wrong in the window between two adjacent statements. A third once stood here, an evaluation outliving its claim lease and being counted by both itself and its replacement, and no longer applies: acknowledgement is conditional on still holding the claim and the loser records nothing. The recorded figure is therefore approximate, and MUST NOT be presented as an exact count of what promoting a rule would produce.

A failure to record SHALL NOT fail the batch. By the time the record is attempted the batch has reached a state it will not be processed again from, whether acknowledged or withdrawn, so there is nothing left to fail; replaying real detection work, or undoing a withdrawal, to save a counter would trade the more valuable thing for the less valuable one.

Recorded counts SHALL be subject to the deployment's data-retention window, and pruning them SHALL NOT require a leader-elected task. The delete is idempotent and needs no coordination, whereas every leader-gated loop holds a database connection for the lifetime of the process and the event processor sizes itself against what those loops leave behind.

#### Scenario: A monitor match is counted once for a batch that is retried

- **GIVEN** a rule in monitor mode that matches events in a batch
- **WHEN** the batch fails and is nacked, and the replayed batch then succeeds and is acknowledged
- **THEN** the rule's recorded match count reflects the batch once, not once per attempt

#### Scenario: Counts are attributed to the rule and the host

- **GIVEN** a rule in monitor mode that matches on two different hosts
- **WHEN** the batches are evaluated and acknowledged
- **THEN** the record distinguishes the two hosts for that rule
- **AND** the per-rule total is the sum across them

#### Scenario: A recording failure does not fail the batch

- **GIVEN** an acknowledged batch whose monitor matches cannot be persisted
- **WHEN** the recording fails
- **THEN** the failure is logged
- **AND** the batch is not nacked and its events are not replayed

#### Scenario: Counts older than the retention window are pruned

- **GIVEN** recorded counts older than the configured retention window
- **WHEN** the prune runs
- **THEN** those counts are deleted
- **AND** counts inside the window are kept

#### Scenario: A withdrawn batch is counted once, not lost

- **GIVEN** a rule in monitor mode that matched events in a batch that then failed
- **WHEN** the batch exhausts its retry bounds and every one of its events is withdrawn from processing
- **THEN** the matches that attempt resolved are recorded
- **AND** they are recorded once, because no later attempt will evaluate those events

#### Scenario: A partly withdrawn batch is not counted yet

- **GIVEN** a failing batch in which only some events have passed their retry bounds
- **WHEN** those events are withdrawn and the rest return to the queue
- **THEN** nothing is recorded for that attempt
- **AND** the events that returned are counted by the attempt that finishes them

#### Scenario: An empty result does not displace earlier matches

- **GIVEN** a batch whose first attempt resolved matches and failed, and a later attempt that reached evaluation but failed before resolving any
- **WHEN** that later attempt withdraws every one of its events
- **THEN** the first attempt's matches are recorded
- **AND** the later attempt's empty result is not read as the batch having matched nothing

#### Scenario: An earlier attempt's matches reach the withdrawal

- **GIVEN** a batch that evaluated and failed on one attempt, and on a later attempt failed before evaluation was reached
- **WHEN** that later attempt withdraws every one of its events
- **THEN** the earlier attempt's matches are recorded, because no attempt will evaluate those events again
- **AND** they are recorded once, by the attempt that withdrew the batch

### Requirement: A per-rule span reports the alerts it raised

The per-rule evaluation span SHALL report the number of findings that were raised as NEW alerts, not the number the rule produced. A finding the resolved mode suppresses SHALL NOT be counted as an alert, and a finding whose alert deduplicated against one that already existed SHALL NOT be counted as an alert either.

Those two SHALL be reported as separate counts alongside the alert count, so the span still says how much the rule found and an operator can tell which of the two happened. They are not the same event: a suppressed finding was held back by a configuration the operator chose, and a deduplicated one is the deduplication working as intended on a rule that is alerting normally. Reporting them as one count made a rule in alert mode with a standing condition show a climbing suppressed count with nothing suppressing it, which is a question the operator cannot answer by reading their own settings.

The alert count and the produced-finding count were the same number while every rule alerted. They are not once rules ship in a mode that suppresses, and a span that counted produced findings would report alerts that were never raised to every dashboard grouping by rule.

#### Scenario: A rule whose findings are all suppressed reports no alerts

- **GIVEN** a rule whose resolved mode is one that raises no alert, whether monitor or disabled, and which produces findings for a batch
- **WHEN** the batch is evaluated
- **THEN** the rule's span reports an alert count of zero
- **AND** reports the number of suppressed findings
- **AND** reports a deduplicated count of zero, since nothing reached persistence to deduplicate against

### Requirement: Recorded monitor-match counts are readable per rule

The system SHALL expose the recorded monitor-mode match counts through the operator API, aggregated per rule over a caller-specified window, so the evidence for promoting a rule is available where the promotion is made rather than only in a metrics backend.

Each rule's entry SHALL report the total matches in the window, the number of distinct hosts that contributed, and when the rule most recently matched. The three answer different halves of one decision: equal totals mean opposite things depending on whether they came from one host, which calls for an exclusion, or from many, which means the rule itself is too broad, and a rule that matched heavily but not recently is a third case again.

A rule that matched nothing in the window SHALL be absent from the response rather than present with a zero, and the response SHALL be an empty list rather than null when no rule matched.

The window SHALL default when unspecified and SHALL be capped, and the response SHALL state the window it covers, because the cap means a caller can receive a narrower window than it asked for and would otherwise describe the number to an operator as covering a period it does not. The cap SHALL be the deployment's own counter retention, not a fixed constant: the counters are pruned with the configured retention, so a fixed cap would report a window over rows that retention has already deleted. The default SHALL be capped by the same bound, since a deployment retaining less than the default would otherwise answer an unspecified window with a period it cannot cover. A window that is not a positive whole number SHALL be rejected rather than defaulted, since answering a different question than the one asked is worse than answering none, and a supplied-but-empty value is a malformed value rather than an omission.

A failure to read SHALL be reported as an error rather than as an empty result, and SHALL be distinguished from a rule having matched nothing wherever the counts are presented. An empty result reads as a quiet rule, which is the reading that gets a noisy rule promoted, so rendering a failed read as absence turns an outage into fleet-wide evidence that every rule is quiet.

The reported figure SHALL be presented as an approximation of what promoting the rule would produce, never as a count of it. It counts matches, while alerts deduplicate on (host, rule, subject) permanently, so it is biased upward by repeated subjects and downward by the recorder's documented losses.

#### Scenario: Counts are readable per rule over a window

- **GIVEN** recorded monitor matches for two rules, one concentrated on a single host and one spread across several
- **WHEN** the counts are read for a window covering them
- **THEN** each rule reports its total matches, its distinct host count, and its most recent match
- **AND** a rule whose matches all fall outside the window is absent rather than reported as zero
- **AND** each rule's most recent match is reported, so a rule that matched heavily and has since gone quiet is distinguishable from one still matching

#### Scenario: A failed read is not presented as an absence of matches

- **GIVEN** a reader whose attempt to load the counts fails
- **WHEN** the counts are presented
- **THEN** they are shown as unavailable rather than as no matches recorded
- **AND** the promotion control remains usable

#### Scenario: The window is stated and bounded

- **GIVEN** a caller requesting a window
- **WHEN** the request exceeds the cap
- **THEN** the response covers the capped window and states which window it covers
- **AND** a window that is not a positive whole number is rejected

#### Scenario: The cap follows the deployment's retention

- **GIVEN** a deployment retaining fewer days of counters than the default window
- **WHEN** the counts are read without a window, and again with one longer than retention
- **THEN** both are served at the retention, and both report that as the window covered
- **AND** a deployment that has disabled pruning is still bounded by the fixed maximum

### Requirement: Evaluation statistics are readable per rule

The system SHALL expose the recorded per-rule evaluation statistics through the operator API and present them beside the rule they describe, aggregated over a caller-specified window, so a slow or churning rule is identifiable where its tuning is done rather than only in a metrics backend.

This is the consumer half the durable-recording requirement deliberately left to whatever surface presents the figures. A record no interface reads answers nothing: at a thousand rules, the rule holding up the drain loop cannot be found by reading logs, and it is invisible to the match counts, because a rule can be perfectly quiet and still be the expensive one.

Each rule's entry SHALL report its evaluation attempts, how many of those ended without a decision, the mean time per attempt, and the worst single attempt. The mean and the maximum are both required because either alone misleads: a mean hides the rule that is usually fast and occasionally terrible, and a maximum alone promotes the rule that had one bad batch over the one that is expensive every time.

The mean SHALL be computed from the recorded totals rather than stored, so it stays correct as the window widens and as retention prunes days out of it.

Attempts SHALL be reported as attempts, not as logical batches, matching how they are recorded. A replayed batch really did evaluate again, and contributes its own duration. The mean therefore remains a mean per ATTEMPT, which is what keeps it from being inflated by replay the way a per-batch figure would be; it is not invariant under replay, since an attempt that ran faster or slower than the others moves it. A reader comparing attempt counts between rules is comparing work performed rather than events seen, and the surface SHALL say so rather than let the count read as a fire count.

A rule that did not evaluate in the window SHALL be absent from the response rather than present with zeros, and the response SHALL be an empty list rather than null when no rule evaluated.

The window SHALL default when unspecified and SHALL be capped at the deployment's own retention, and the response SHALL state the window it covers, for the same reasons the match-count read does: the cap can make the served window narrower than the one requested, and a figure labelled with a period it does not cover is a misreport rather than an approximation. A window that is not a positive whole number SHALL be rejected rather than defaulted.

A failure to read SHALL be reported as an error rather than as an empty result, and SHALL be distinguished from a rule having no recorded evaluations wherever the statistics are presented. An empty result reads as a cheap rule, so rendering a failed read as absence tells an operator hunting the slow rule that there isn't one. A surface that has no statistics to present SHALL NOT go on ordering or ranking by ones it read before, and SHALL NOT offer an ordering it is not producing. That covers a failed read and an empty successful one alike: they are different states to report, and neither is something to sort by. A ranking an operator can act on is not distinguishable from a current one by looking at it.

What the figures mean, and any caveat on reading them, SHALL be available without a pointer. A native tooltip on an element that cannot take focus reaches neither a keyboard nor a touch user, so the sentence that stops a number being misread is the one they would not get.

A control offered in a column header SHALL still read as that column's header. Making the ordering reachable by keyboard means the header is a real control rather than text, and a control carries a user-agent presentation of its own that overrides what the surrounding header sets; a header that stops matching the row it sits in reads as a stray button and stops naming its column. This is a presentation obligation the layers below the browser cannot check, since neither a component test nor a type checker applies a user-agent stylesheet.

This read and the match-count read SHALL fail independently. They describe different populations over different questions, and a rule that never matches still evaluates, so one failing SHALL NOT suppress the other.

#### Scenario: Statistics are readable per rule over a window

- **GIVEN** recorded evaluations for two rules, one cheap and frequent and one expensive
- **WHEN** the statistics are read for a window covering them
- **THEN** each rule reports its attempts, its undecided attempts, its mean time and its worst attempt
- **AND** a rule whose evaluations all fall outside the window is absent rather than reported as zero

#### Scenario: A failed read is not presented as no cost

- **GIVEN** a reader whose attempt to load the statistics fails
- **WHEN** the statistics are presented
- **THEN** they are shown as unavailable rather than as no evaluations recorded
- **AND** the rule's tuning controls remain usable

#### Scenario: One read failing does not suppress the other

- **GIVEN** a surface presenting both the evaluation statistics and the monitor-match counts
- **WHEN** one of the two reads fails and the other succeeds
- **THEN** the failed one is shown as unavailable
- **AND** the one that succeeded is still presented

#### Scenario: The window is stated and bounded

- **GIVEN** a caller requesting a window longer than the deployment retains
- **WHEN** the statistics are read
- **THEN** the response covers the retained window and states which window it covers
- **AND** a window that is not a positive whole number is rejected

#### Scenario: The ordering control still reads as a column header

- **GIVEN** a column whose header carries a control for ordering by that column
- **WHEN** the table is rendered in a browser
- **THEN** the header is presented the same way as the table's other column headers
