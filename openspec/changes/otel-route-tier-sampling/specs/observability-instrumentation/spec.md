## ADDED Requirements

### Requirement: Route-tier head sampling of exported traces

When OTLP export is enabled, the system SHALL apply head sampling to traces, classifying each inbound HTTP request span into a sampling tier and sampling each ratio-bearing tier at its configured ratio: a high-volume tier for agent data-plane traffic, a standard tier for operator and UI read traffic, and a full tier for everything else. The full tier SHALL be sampled at 100% and SHALL be the default for any span not explicitly classified, so a newly added route is captured at full fidelity until it is deliberately downsampled. Sampling SHALL be parent-based: a span whose parent was sampled MUST itself be sampled, so a distributed trace is never partially captured. The agent data-plane routes `POST /api/events`, the agent command poll `GET /api/commands`, `POST /api/token/refresh`, and `POST /api/enroll` SHALL be classified high-volume.

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

The system SHALL provide a force-full override that, when enabled, causes every tier to be sampled at 100% regardless of its configured ratio, so an operator can capture complete traces during an incident debug window and disable it afterward, in both cases without a redeploy.

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
