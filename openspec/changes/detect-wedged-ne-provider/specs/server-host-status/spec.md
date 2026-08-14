# server-host-status delta

## ADDED Requirements

### Requirement: The server derives health conditions its endpoints cannot report

The server SHALL derive per-host health conditions by contradicting the health a host reported against the telemetry that reached the server, so that a capture provider which has stopped delivering while continuing to report itself healthy is surfaced as degraded rather than healthy.

A derived condition SHALL be raised for a telemetry stream when all of the following hold, and SHALL NOT be raised otherwise:

- the host's reported overall health is `healthy`, so there is a positive claim to contradict;
- the host produced process telemetry inside the silence window, so the host is known to be doing work rather than idle;
- the stream produced nothing inside the silence window;
- the stream produced something inside the longer reference window, so the stream is one this host actually uses.

A derived condition SHALL name the provider an operator must remediate, SHALL carry status `degraded` rather than `unhealthy` (it is inferred from absence, not observed by the endpoint), and SHALL be reported separately from the conditions the agent itself reported, so an operator can tell the server's inference from the endpoint's claim.

The host's effective overall status SHALL fold derived conditions in, and SHALL be the same on the host list and the host detail, so the two surfaces cannot disagree about one host. Folding SHALL NOT downgrade a worse reported status.

Derived conditions SHALL carry no last-transition timestamp, because a count over a window cannot recover the instant a stream fell silent.

A failure to read the telemetry SHALL degrade to serving the reported health alone rather than failing the request, so that losing the event archive does not take the operator's host views down with it.

#### Scenario: A wedged provider is surfaced as degraded

- **GIVEN** a host whose reported health claims every component is healthy
- **AND** the host produced process telemetry within the silence window
- **AND** the host produced no `dns_query` events within the silence window but did within the reference window
- **WHEN** an operator reads that host's health detail
- **THEN** the response carries a derived condition naming the DNS proxy with status `degraded`
- **AND** the host's effective overall status is `degraded`
- **AND** the conditions the agent reported are still carried unchanged alongside it

#### Scenario: An idle host is not accused

- **GIVEN** a host whose reported health claims every component is healthy
- **AND** the host produced no process telemetry within the silence window
- **WHEN** an operator reads that host's health detail
- **THEN** no derived condition is raised
- **AND** the host's effective overall status is `healthy`

#### Scenario: A provider that never produced is not accused

- **GIVEN** a host whose reported health claims every component is healthy
- **AND** the host produced process telemetry within the silence window
- **AND** the host produced no events of a stream within either the silence window or the reference window
- **WHEN** an operator reads that host's health detail
- **THEN** no derived condition is raised for that stream

#### Scenario: A host already reporting a fault gains no second condition

- **GIVEN** a host whose reported overall health is `unhealthy` or `degraded`
- **WHEN** an operator reads that host's health detail
- **THEN** no derived condition is raised

#### Scenario: The host list badge agrees with the host detail

- **GIVEN** a host for which a derived condition is raised
- **WHEN** an operator reads the host list
- **THEN** that host's row carries the same effective overall status the host detail reports

#### Scenario: The signal clears when telemetry resumes

- **GIVEN** a host previously surfaced as degraded by a derived condition
- **WHEN** the stream produces events again within the silence window
- **AND** an operator reads that host's health detail
- **THEN** no derived condition is raised
- **AND** the host's effective overall status is its reported status

#### Scenario: An unreadable archive degrades rather than failing the request

- **GIVEN** a host with a stored health snapshot
- **AND** the telemetry read fails
- **WHEN** an operator reads that host's health detail or the host list
- **THEN** the request succeeds carrying the reported health alone
- **AND** no derived condition is raised
